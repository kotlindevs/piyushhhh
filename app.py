from bson.objectid import ObjectId
from quart import Quart, Response, request, session, jsonify, g
from quart_cors import cors
import motor.motor_asyncio as motor
import urllib.parse as parser
import bcrypt
import secrets
import datetime
import jwt
from functools import wraps
import json

app = Quart(__name__)
app = cors(
    app,
    allow_credentials=True,
    allow_headers=["Content-Type", "Authorization",
                   "Access-Control-Allow-Origin"],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_origin="https://pycontacts.onrender.com/"
)

app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(32)
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(hours=24)

uname = parser.quote_plus("Rajat")
passwd = parser.quote_plus("2844")
cluster = "cluster0.gpq2duh"
url = f"mongodb+srv://{uname}:{passwd}@{cluster}.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true"
client = motor.AsyncIOMotorClient(url)
db = client["Contacts"]
helplines = db["Helplines"]
accounts = db["Accounts"]
user_contacts_collection = db["User_contacts"]
labels_collection = db["Labels"]
trash_collection = db["Trash"]


def jwt_required(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]

        if not token:
            return jsonify({'error': 'Token is missing!'}), 401

        try:
            payload = jwt.decode(
                token,
                app.config['JWT_SECRET_KEY'],
                algorithms=["HS256"]
            )
            g.username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return await f(*args, **kwargs)
    return decorated_function


async def check_user_async(username: str) -> bool:
    try:
        chk_user = await accounts.find_one({"Username": username})
        return chk_user is not None
    except Exception as e:
        print(f"Error while checking username: {e}")
        return False


async def create_user_async(image:str, name: str, username: str, password: str, mobile: str):
    try:
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        user = {
            "Photo" : image,
            "Name": name,
            "Username": username,
            "Password": hashed_password,
            "Contact": mobile
        }
        await accounts.insert_one(user)
        return True, "User created successfully."
    except Exception as e:
        print(f"Error while creating user: {e}")
        return False, "An error occurred while creating the user."


async def validate_user_async(username: str, password: str) -> bool:
    try:
        user = await accounts.find_one({"Username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['Password']):
            return True
        return False
    except Exception as e:
        print(f"Error while validating user: {e}")
        return False


async def update_user_async(username: str, image:str, name: str, mobile: str):
    try:
        update_fields = {"Name": name}
        if mobile:
            update_fields["Contact"] = mobile

        if image:
            update_fields["Photo"] = image

        result = await accounts.update_one(
            {"Username": username},
            {"$set": update_fields}
        )
        if result.modified_count == 1:
            return True, "Profile updated successfully."
        else:
            return False, "User not found or no changes made."
    except Exception as e:
        print(f"Error updating user profile: {e}")
        return False, "An unexpected error occurred while updating the profile."


async def get_contacts_async(username: str):
    try:
        user_contacts = await user_contacts_collection.find_one({"Username": username})
        if user_contacts:
            return user_contacts.get("Contacts", [])
        return []
    except Exception as e:
        print(f"Error getting contacts: {e}")
        return []


async def get_contact_by_id_async(username: str, contact_id: str):
    try:
        obj_id = ObjectId(contact_id)
        user_contacts = await user_contacts_collection.find_one({"Username": username})
        if user_contacts:
            for contact in user_contacts.get("Contacts", []):
                if contact.get("_id") == obj_id:
                    return contact
        return None
    except Exception as e:
        print(f"Error getting contact: {e}")
        return None


async def add_contact_async(username,image, name, mobile, email, job_title, company, labels, datetime):
    try:
        new_contact = {
            "_id": ObjectId(),
            "Photo": image,
            "Name": name,
            "Contact": mobile,
            "Email": email,
            "Job": job_title,
            "Company": company,
            "Labels": labels,
            "DateTime": datetime
        }
        await user_contacts_collection.update_one(
            {"Username": username},
            {"$push": {"Contacts": new_contact}},
            upsert=True
        )
        return True, "Contact added successfully.", new_contact
    except Exception as e:
        print(f"Error adding contact: {e}")
        return False, "An error occurred while adding the contact.", None


async def update_contact_async(username, contact_id, new_name, mobile, email, job_title, company, labels):
    try:
        obj_id = ObjectId(contact_id)

        update_fields = {
            "Contacts.$.Name": new_name,
            "Contacts.$.Contact": mobile,
            "Contacts.$.Email": email,
            "Contacts.$.Job": job_title,
            "Contacts.$.Company": company,
            "Contacts.$.Labels": labels
        }

        result = await user_contacts_collection.update_one(
            {"Username": username, "Contacts._id": obj_id},
            {"$set": update_fields}
        )

        if result.modified_count == 1:
            return True, "Contact updated successfully."
        else:
            return False, "Contact not found or no changes made."
    except Exception as e:
        print(f"Error updating contact: {e}")
        return False, "An error occurred while updating the contact."


async def create_label_async(username: str, label_name: str):
    try:
        new_label = {
            "Username": username,
            "LabelName": label_name
        }
        await labels_collection.insert_one(new_label)
        return True, "Label created successfully."
    except Exception as e:
        print(f"Error creating label: {e}")
        return False, "An error occurred while creating the label."


async def get_labels_async(username: str):
    try:
        user_labels = await labels_collection.find({"Username": username}).to_list(length=None)
        return [label["LabelName"] for label in user_labels]
    except Exception as e:
        print(f"Error getting labels: {e}")
        return []


async def delete_label_async(username: str, label_name: str):
    try:
        result = await labels_collection.delete_one({"Username": username, "LabelName": label_name})
        if result.deleted_count == 1:
            return True, "Label deleted successfully."
        else:
            return False, "Label not found."
    except Exception as e:
        print(f"Error deleting label: {e}")
        return False, "An error occurred while deleting the label."


async def edit_the_label_async(username: str, old_label_name: str, new_label_name: str):
    try:
        result = await labels_collection.update_one(
            {"Username": username, "LabelName": old_label_name},
            {"$set": {"LabelName": new_label_name}}
        )
        if result.modified_count == 1:
            return True, "Label updated successfully."
        else:
            return False, "Label not found or no changes made."
    except Exception as e:
        print(f"Error updating label: {e}")
        return False, "An error occurred while updating the label."


async def check_the_label_exists_async(username: str, label_name: str):
    try:
        label = await labels_collection.find_one({"Username": username, "LabelName": label_name})
        return label is not None
    except Exception as e:
        print(f"Error checking label existence: {e}")
        return False


async def move_to_trash_async(username: str, contact_id: str):
    try:
        obj_id = ObjectId(contact_id)
    except Exception:
        return False, "Invalid contact ID format."

    try:
        user_doc = await user_contacts_collection.find_one({"Username": username})
        if not user_doc:
            return False, "User not found."

        contact_to_move = None
        for contact in user_doc.get("Contacts", []):
            if contact.get("_id") == obj_id:
                contact_to_move = contact
                break

        if not contact_to_move:
            return False, "Contact not found in main list."

        trash_item = {
            "contact_id": obj_id,
            "Username": username,
            "ContactDetails": contact_to_move,
            "deleted_at": datetime.datetime.utcnow()
        }
        await trash_collection.insert_one(trash_item)

        await user_contacts_collection.update_one(
            {"Username": username},
            {"$pull": {"Contacts": {"_id": obj_id}}}
        )
        return True, "Contact moved to trash successfully."

    except Exception as e:
        print(f"Error moving contact to trash: {e}")
        return False, "An error occurred while moving the contact to trash."


async def delete_contacts_by_ids_async(username: str, contact_ids: list):
    try:
        await user_contacts_collection.update_one(
            {"Username": username},
            {"$pull": {"Contacts": {"_id": {"$in": contact_ids}}}}
        )
        return True, "Contacts deleted successfully.", None
    except Exception as e:
        print(f"Error deleting contacts: {e}")
        return False, "An error occurred while deleting contacts.", None


async def merge_contacts_async(username: str, contact_ids: list):
    if not isinstance(contact_ids, list) or len(contact_ids) < 2:
        # All return statements now consistently return 3 values
        return False, "A list of at least two contact IDs is required to merge.", None

    merged_name = None
    merged_mobile = None
    merged_email = None
    merged_job = None
    merged_company = None
    merged_labels = set()
    
    contacts_to_delete_ids = []
    
    for cid in contact_ids:
        # Check if the item is a dictionary (from client-side objects) or a string (from simple IDs)
        if isinstance(cid, dict):
            contact_id_str = str(cid.get('_id'))
        elif isinstance(cid, str):
            contact_id_str = cid
        else:
            # All return statements now consistently return 3 values
            return False, f"Invalid contact ID format: '{cid}'", None

        try:
            contact = await get_contact_by_id_async(username, contact_id_str)
            
            if not contact:
                # All return statements now consistently return 3 values
                return False, f"Contact with ID '{contact_id_str}' not found.", None
            
            contacts_to_delete_ids.append(contact.get("_id"))
            
            # Merge fields, prioritizing the first non-empty value
            if not merged_name:
                merged_name = contact.get("Name")
            if not merged_mobile:
                merged_mobile = contact.get("Contact")
            if not merged_email:
                merged_email = contact.get("Email")
            if not merged_job:
                merged_job = contact.get("Job")
            if not merged_company:
                merged_company = contact.get("Company")
            
            # Combine all labels
            for label in contact.get("Labels", []):
                merged_labels.add(label)
                
        except Exception:
            # All return statements now consistently return 3 values
            return False, f"Invalid contact ID format: '{contact_id_str}'", None
            
    # Add the new merged contact
    success, message, new_contact = await add_contact_async(
        username,
        merged_name,
        merged_mobile,
        merged_email,
        merged_job,
        merged_company,
        list(merged_labels),
        datetime=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    
    if success:
        # Delete the original contacts
        await delete_contacts_by_ids_async(username, contacts_to_delete_ids)
        if new_contact and '_id' in new_contact:
            new_contact['_id'] = str(new_contact['_id'])
        return True, "Contacts merged successfully.", new_contact
    else:
        return False, message, None

async def get_trashed_contacts_async(username: str):
    try:
        trashed_docs = []
        async for doc in trash_collection.find({"Username": username}).sort("deleted_at", -1):
            if '_id' in doc and doc['_id']:
                doc['_id'] = str(doc['_id'])
            if 'contact_id' in doc and doc['contact_id']:
                doc['contact_id'] = str(doc['contact_id'])

            if 'ContactDetails' in doc and 'ContactDetails' in doc:
                contact_details = doc['ContactDetails']
                if '_id' in contact_details and contact_details['_id']:
                    contact_details['_id'] = str(contact_details['_id'])
            trashed_docs.append(doc)
        return trashed_docs
    except Exception as e:
        print(f"Error getting trashed contacts: {e}")
        return []


async def restore_contact_async(username, contact_id):
    try:
        obj_id = ObjectId(contact_id)
    except Exception:
        return False, "Invalid contact ID format."

    try:
        trashed_item = await trash_collection.find_one({"Username": username, "contact_id": obj_id})
        if not trashed_item:
            return False, "Contact not found in trash."

        contact_to_restore = trashed_item['ContactDetails']

        await user_contacts_collection.update_one(
            {"Username": username},
            {"$push": {"Contacts": contact_to_restore}}
        )

        await trash_collection.delete_one({"_id": trashed_item["_id"]})

        return True, "Contact restored successfully."
    except Exception as e:
        print(f"Error restoring contact: {e}")
        return False, "An error occurred while restoring the contact."


async def delete_permanently_async(username: str, contact_id: str):
    try:
        obj_id = ObjectId(contact_id)
    except Exception:
        return False, "Invalid contact ID format."

    try:
        result = await trash_collection.delete_one({"contact_id": obj_id, "Username": username})
        if result.deleted_count == 0:
            return False, "Contact not found in trash."
        return True, "Contact permanently deleted."
    except Exception as e:
        print(f"Error deleting contact permanently: {e}")
        return False, "An error occurred while deleting the contact."


async def empty_trash_async(username: str):
    try:
        await trash_collection.delete_many({"Username": username})
        return True, "Trash emptied successfully."
    except Exception as e:
        print(f"Error emptying trash: {e}")
        return False, "An error occurred while emptying the trash."


async def search_contacts_async(username: str, query: str):
    try:
        contacts_list = await get_contacts_async(username)
        search_results = [
            contact for contact in contacts_list
            if query.lower() in contact.get("Name", "").lower()
            or query.lower() in contact.get("Contact", "").lower()
            or query.lower() in contact.get("Email", "").lower()
            or any(query.lower() in label.lower() for label in contact.get("Labels", []))
        ]
        return search_results
    except Exception as e:
        print(f"Error searching contacts: {e}")
        return []


async def export_contacts_async(username: str):
    try:
        contacts = await get_contacts_async(username)
        for contact in contacts:
            if '_id' in contact:
                contact['_id'] = str(contact['_id'])
        return True, contacts, None
    except Exception as e:
        print(f"Error exporting contacts: {e}")
        return False, None, "An error occurred while exporting contacts."


@app.route('/')
async def index():
    return jsonify({"message": "Welcome to the Contacts API!"})


@app.route('/api/v1/signup', methods=['POST'])
async def api_register():
    try:
        data = await request.get_json()
        image = data.get('image')
        name = data.get('name')
        username = data.get('username')
        password = data.get('password')
        mobile = data.get('mobile')

        if not all([name, username, password]):
            return jsonify({"error": "Missing required fields"}), 400

        if await check_user_async(username):
            return jsonify({"error": "Username already exists. Please choose a different one."}), 409

        success, message = await create_user_async(image, name, username, password, mobile)

        if success:
            return jsonify({"success": True, "message": "User registered successfully."}), 201
        else:
            return jsonify({"success": False, "error": message}), 500

    except Exception as e:
        print(f"Error in registration API: {e}")
        return jsonify({"success": False, "error": "An internal server error occurred."}), 500


@app.route('/api/v1/signin', methods=['POST'])
async def api_login():
    try:
        data = await request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not all([username, password]):
            return jsonify({"error": "Missing required fields"}), 400

        if await validate_user_async(username, password):
            payload = {
                'username': username,
                'exp': datetime.datetime.now(datetime.timezone.utc) + app.config['JWT_EXPIRATION_DELTA']
            }
            token = jwt.encode(
                payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
            print(f"User '{username}' logged in successfully, JWT issued.")
            return jsonify({"success": True, "message": "Login successful", "token": token}), 200
        else:
            print(f"Failed login attempt for user '{username}'.")
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

    except Exception as e:
        print(f"Error in login API: {e}")
        return jsonify({"success": False, "error": "An internal server error occurred."}), 500


@app.route('/api/v1/user', methods=['GET'])
@jwt_required
async def api_get_user_profile():
    try:
        user = await accounts.find_one({"Username": g.username})
        if user:
            user_info = {
                "photo": user.get("Photo"),
                "name": user.get("Name"),
                "username": user.get("Username"),
                "mobile": user.get("Contact")
            }
            return jsonify({"success": True, "user": user_info}), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"Error fetching user profile: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/user/update', methods=['PUT'])
@jwt_required
async def api_update_user_profile():
    try:
        data = await request.get_json()
        image = data.get('image')
        name = data.get('name')
        mobile = data.get('mobile')

        if not name:
            return jsonify({"error": "Name is a required field."}), 400

        success, message = await update_user_async(
            username=g.username, image=image, name=name, mobile=mobile
        )
        if success:
            updated_user = await accounts.find_one({"Username": g.username})
            user_info = {
                "name": updated_user.get("Name"),
                "username": updated_user.get("Username"),
                "mobile": updated_user.get("Contact"),
                "photo" : updated_user.get("Photo")
            }
            return jsonify({"success": True, "message": message, "user": user_info}), 200
        else:
            return jsonify({"error": message}), 404
    except Exception as e:
        print(f"Error in update user profile API: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/contacts', methods=['GET'])
@jwt_required
async def api_contacts():
    try:
        contacts_list = await get_contacts_async(g.username)
        # Convert ObjectId to string for JSON serialization
        for contact in contacts_list:
            if '_id' in contact and contact['_id']:
                contact['_id'] = str(contact['_id'])

        if not contacts_list:
            print(f"No contacts found for user '{g.username}'.")
        else:
            print(f"{len(contacts_list)} contacts found for user '{g.username}'.")

        return jsonify({"success": True, "contacts": contacts_list}), 200

    except Exception as e:
        print(f"Error fetching contacts in API: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/create_contact', methods=['POST'])
@jwt_required
async def api_create_contact():
    try:
        data = await request.get_json()
        if not data:
            print("Invalid JSON body received.")
            return jsonify({"error": "Invalid request body, expected JSON"}), 400
        
        image = data.get('image')
        name = data.get('name')
        mobile = data.get('mobile')
        email = data.get('email')
        job_title = data.get('job_title')
        company = data.get('company')
        labels = data.get('labels', [])
        dt = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if not name or not isinstance(name, str) or len(name.strip()) == 0:
            return jsonify({"error": "A valid 'name' (string) is required"}), 400

        if not mobile or not isinstance(mobile, str) or not mobile.isdigit():
            return jsonify({"error": "A valid 'mobile' number (digits only) is required"}), 400

        await add_contact_async(
            g.username,
            image,
            name,
            mobile,
            email,
            job_title,
            company,
            labels,
            dt
        )
        print(
            f"Contact '{name}' created successfully for user '{g.username}'.")
        return jsonify({"success": True, "message": "Contact created successfully"}), 201

    except TypeError as e:
        print(f"Data type error in request: {e}")
        return jsonify({"error": "Invalid data format provided."}), 400

    except Exception as e:
        print(f"An unexpected error occurred while creating contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/edit_contact/<contact_id>', methods=['GET', 'PUT'])
@jwt_required
async def api_edit_contact(contact_id):
    if request.method == 'GET':
        try:
            contact = await get_contact_by_id_async(g.username, contact_id)
            if contact:
                if '_id' in contact and contact['_id']:
                    contact['_id'] = str(contact['_id'])
                return jsonify({"success": True, "contact": contact}), 200
            else:
                return jsonify({"error": "Contact not found"}), 404
        except Exception as e:
            print(f"An unexpected error occurred while fetching contact: {e}")
            return jsonify({"error": "An internal server error occurred."}), 500

    elif request.method == 'PUT':
        try:
            data = await request.get_json()
            if not data:
                return jsonify({"error": "Invalid request body, expected JSON"}), 400

            fname = data.get('fname')
            lname = data.get('lname')
            mobile = data.get('mobile')
            email = data.get('email')
            job_title = data.get('job_title')
            company = data.get('company')
            labels = data.get('labels')

            if not fname or not mobile:
                return jsonify({"error": "First name and Mobile are required fields."}), 400

            if not isinstance(mobile, str) or not mobile.isdigit():
                return jsonify({"error": "Mobile number must be a string of digits."}), 400

            new_name = f"{fname} {lname}" if lname else fname

            success, message = await update_contact_async(
                g.username,
                contact_id,
                new_name,
                mobile,
                email,
                job_title,
                company,
                labels
            )
            if success:
                print(
                    f"Contact with ID '{contact_id}' updated to '{new_name}' successfully.")
                return jsonify({"success": True, "message": message}), 200
            else:
                return jsonify({"error": message}), 404

        except Exception as e:
            print(f"An unexpected error occurred while editing contact: {e}")
            return jsonify({"error": "An internal server error occurred."}), 500

@app.route('/api/v1/contact/<contact_id>', methods=['GET'])
@jwt_required
async def api_get_contact(contact_id):
    """
    Retrieves a single contact by its unique _id.
    """
    try:
        contact = await get_contact_by_id_async(g.username, contact_id)
        if not contact:
            return jsonify({"error": "Contact not found"}), 404

        # Convert ObjectId to string for JSON serialization
        contact['_id'] = str(contact['_id'])
        return jsonify({"success": True, "contact": contact}), 200

    except Exception as e:
        print(f"An unexpected error occurred while fetching contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500

@app.route('/api/v1/merge_contacts', methods=['POST'])
@jwt_required
async def api_merge_contacts():
    try:
        data = await request.get_json()
        contact_ids = data.get('contact_ids')

        success, message, merged_contact = await merge_contacts_async(g.username, contact_ids)
        if success:
            print(f"Contacts '{contact_ids}' merged successfully for user '{g.username}'.")
            return jsonify({
                "success": True,
                "message": message,
                "contact": merged_contact
            }), 201
        else:
            return jsonify({"success": False, "error": message}), 400
    except Exception as e:
        print(f"An unexpected error occurred while merging contacts: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500

@app.route('/api/v1/remove_contact/<contact_id>', methods=['DELETE'])
@jwt_required
async def api_remove_contact(contact_id):
    try:
        success, message = await move_to_trash_async(g.username, contact_id)
        if success:
            print(
                f"Contact with _id '{contact_id}' removed to trash successfully for user '{g.username}'.")
            return jsonify({"success": True, "message": message}), 200
        else:
            return jsonify({"error": message}), 404
    except Exception as e:
        print(f"An unexpected error occurred while removing contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/trash', methods=['GET'])
@jwt_required
async def api_get_trashed_contacts():
    try:
        trashed_docs = await get_trashed_contacts_async(g.username)
        return jsonify({"success": True, "trashed_contacts": trashed_docs}), 200
    except Exception as e:
        print(
            f"An unexpected error occurred while fetching trashed contacts: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/restore_contact/<contact_id>', methods=['POST'])
@jwt_required
async def api_restore_contact(contact_id):
    try:
        success, message = await restore_contact_async(g.username, contact_id)
        if success:
            print(
                f"Contact with _id '{contact_id}' restored successfully for user '{g.username}'.")
            return jsonify({"success": True, "message": message}), 200
        else:
            return jsonify({"error": message}), 404
    except Exception as e:
        print(f"An unexpected error occurred while restoring contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/delete_permanently/<contact_id>', methods=['DELETE'])
@jwt_required
async def api_delete_permanently(contact_id):
    try:
        success, message = await delete_permanently_async(g.username, contact_id)
        if success:
            print(
                f"Contact with _id '{contact_id}' permanently deleted successfully for user '{g.username}'.")
            return jsonify({"success": True, "message": message}), 200
        else:
            return jsonify({"error": message}), 404
    except Exception as e:
        print(
            f"An unexpected error occurred while permanently deleting contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/empty_trash', methods=['DELETE'])
@jwt_required
async def api_empty_trash():
    try:
        success, message = await empty_trash_async(g.username)
        if success:
            print(f"Trash emptied successfully for user '{g.username}'.")
            return jsonify({"success": True, "message": message}), 200
        else:
            return jsonify({"error": message}), 404
    except Exception as e:
        print(f"An unexpected error occurred while emptying trash: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/create_label', methods=['POST'])
@jwt_required
async def api_create_label():
    try:
        data = await request.get_json()
        label_name = data.get('label_name')
        if not label_name:
            return jsonify({"error": "Missing 'label_name' field"}), 400

        if await check_the_label_exists_async(g.username, label_name):
            return jsonify({"error": "Label already exists"}), 409
        else:
            success, message = await create_label_async(g.username, label_name)
            if success:
                print(
                    f"Label '{label_name}' created successfully for user '{g.username}'.")
                return jsonify({"success": True, "message": message}), 201
            else:
                return jsonify({"error": message}), 400

    except Exception as e:
        print(f"An unexpected error occurred while creating label: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/get_labels', methods=['GET'])
@jwt_required
async def api_get_labels():
    try:
        labels = await get_labels_async(g.username)
        if labels:
            print(f"Labels retrieved successfully for user '{g.username}'.")
            return jsonify({"success": True, "labels": labels}), 200
        else:
            print(f"No labels found for user '{g.username}'.")
            return jsonify({"success": True, "labels": []}), 200
    except Exception as e:
        print(f"An unexpected error occurred while fetching labels: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/contacts/import_csv', methods=['POST'])
@jwt_required
async def import_contacts_from_json():
    try:
        data = await request.get_json()
        if not data or 'contacts' not in data or not isinstance(data['contacts'], list):
            return jsonify({"success": False, "error": "Invalid request body format. Expected JSON with a 'contacts' array."}), 400

        contacts_to_add = data['contacts']
        success_count = 0
        failed_contacts = []

        for contact in contacts_to_add:
            name = contact.get('name')
            mobile = contact.get('mobile')
            email = contact.get('email')
            job_title = contact.get('job_title')
            company = contact.get('company')

            if not name or not isinstance(name, str) or len(name.strip()) == 0:
                failed_contacts.append(
                    {'contact': contact, 'reason': "Missing or invalid 'name'"})
                continue

            if not mobile or not isinstance(mobile, str) or not mobile.isdigit():
                failed_contacts.append(
                    {'contact': contact, 'reason': "Missing or invalid 'mobile'"})
                continue

            success, message = await add_contact_async(
                g.username,
                name,
                mobile,
                email,
                job_title,
                company,
                labels=[],
                datetime=datetime.datetime.now(
                    datetime.timezone.utc).isoformat()
            )
            if success:
                success_count += 1
            else:
                failed_contacts.append({'contact': contact, 'reason': message})

        if failed_contacts:
            return jsonify({
                "success": False,
                "message": f"Successfully imported {success_count} contacts, but some failed.",
                "total_contacts_attempted": len(contacts_to_add),
                "failed_contacts": failed_contacts
            }), 400

        return jsonify({
            "success": True,
            "message": f"Successfully imported {success_count} contacts."
        }), 201

    except Exception as e:
        print(f"Error processing contacts import: {e}")
        return jsonify({"success": False, "error": "An internal server error occurred."}), 500


@app.route('/api/v1/delete_label', methods=['DELETE'])
@jwt_required
async def api_delete_label():
    try:
        data = await request.get_json()
        label_name = data.get('label_name')
        if not label_name:
            return jsonify({"error": "Missing 'label_name' field"}), 400

        success, message = await delete_label_async(g.username, label_name)
        if success:
            print(
                f"Label '{label_name}' deleted successfully for user '{g.username}'.")
            return jsonify({"success": True, "message": message}), 200
        else:
            return jsonify({"error": message}), 404
    except Exception as e:
        print(f"An unexpected error occurred while deleting label: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/edit_label', methods=['PUT'])
@jwt_required
async def api_edit_label():
    try:
        data = await request.get_json()
        old_label_name = data.get('old_label_name')
        new_label_name = data.get('new_label_name')
        if not old_label_name or not new_label_name:
            return jsonify({"error": "Missing 'old_label_name' or 'new_label_name' field"}), 400

        exists = await check_the_label_exists_async(g.username, old_label_name)
        if not exists:
            return jsonify({"error": "Label not found"}), 404

        success, message = await edit_the_label_async(g.username, old_label_name, new_label_name)
        if success:
            print(
                f"Label '{old_label_name}' edited successfully for user '{g.username}'.")
            return jsonify({"success": True, "message": message}), 200
        else:
            return jsonify({"error": message}), 400
    except Exception as e:
        print(f"An unexpected error occurred while editing label: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/contacts/search', methods=['GET'])
@jwt_required
async def api_search_contacts():
    try:
        query = request.args.get('query', '')
        if not query:
            return jsonify({"error": "Missing search query parameter 'query'"}), 400

        search_results = await search_contacts_async(g.username, query)
        
        # Convert ObjectId to string for JSON serialization
        for contact in search_results:
            if '_id' in contact:
                contact['_id'] = str(contact['_id'])
                
        return jsonify({"success": True, "contacts": search_results}), 200
        
    except Exception as e:
        print(f"Error in contacts search API: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/contacts/export', methods=['GET'])
@jwt_required
async def api_export_contacts():
    try:
        success, data, error_message = await export_contacts_async(g.username)
        if not success:
            return jsonify({"success": False, "error": error_message}), 500

        # Create a JSON file content
        json_content = json.dumps(data, indent=2)

        # Create a response with a JSON file
        response = Response(
            json_content,
            mimetype='application/json',
            headers={
                'Content-Disposition': 'attachment;filename=contacts.json'
            }
        )
        return response

    except Exception as e:
        print(f"Error in contacts export API: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.before_serving
async def initialize_db():
    try:
        count = await helplines.count_documents({})
        if count == 0:
            print("Database is empty. Seeding with initial contacts...")
            await helplines.insert_many([
                {"_id": "0000100", "Name": "Police", "Contact": "100"},
                {"_id": "0000108", "Name": "Ambulance", "Contact": "108"},
                {"_id": "0000101", "Name": "Fire Department", "Contact": "101"},
                {"_id": "00001098", "Name": "Child Helpline", "Contact": "1098"},
                {"_id": "00001077", "Name": "Disaster Management", "Contact": "1077"}
            ])
            print("Seeding complete.")
        else:
            print("Database already contains helpline data.")
    except Exception as e:
        print(f"Error during database initialization: {e}")


@app.route('/api/v1/check_username', methods=['POST'])
async def api_check_username():
    try:
        data = await request.get_json()
        username = data.get('username')
        if not username:
            return jsonify({"error": "Missing 'username' field"}), 400

        exists = await check_user_async(username)
        if exists:
            return jsonify({"exists": True, "message": "Username already taken"}), 200
        else:
            return jsonify({"exists": False, "message": "Username is available"}), 200
    except Exception as e:
        print(f"Error in check_username API: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/logout', methods=['POST'])
@jwt_required
async def api_logout():
    print(
        f"User '{g.username}' logged out successfully by client-side token removal.")
    return jsonify({"success": True, "message": "Logged out successfully"}), 200
