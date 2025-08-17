from quart import Quart, Response, request, session, jsonify, g
from quart_cors import cors
import motor.motor_asyncio as motor
import urllib.parse as parser
import bcrypt
import secrets
import datetime
import jwt
from functools import wraps

app = Quart(__name__)
app = cors(
    app, 
    allow_credentials=True, 
    allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_origin="https://pycontacts.onrender.com/"
)

app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(32)
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(hours=1)

uname = parser.quote_plus("Rajat")
passwd = parser.quote_plus("2844")
cluster = "cluster0.gpq2duh"
url = f"mongodb+srv://{uname}:{passwd}@{cluster}.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true"
client = motor.AsyncIOMotorClient(url)
db = client["Contacts"]
helplines = db["Helplines"]
accounts = db["Accounts"]
user_contacts_collection = db["User_contacts"]
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


async def create_user_async(name, username, password, mobile):
    try:
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        user = {
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


async def validate_user_async(username, password):
    try:
        user = await accounts.find_one({"Username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['Password']):
            return True
        return False
    except Exception as e:
        print(f"Error while validating user: {e}")
        return False


async def get_contacts_async(username: str):
    try:
        user_contacts = await user_contacts_collection.find_one({"Username": username})
        if user_contacts:
            return user_contacts.get("Contacts", [])
        return []
    except Exception as e:
        print(f"Error getting contacts: {e}")
        return []


async def get_contact_by_name_async(username: str, contact_name: str):
    try:
        user_contacts = await user_contacts_collection.find_one({"Username": username})
        if user_contacts:
            for contact in user_contacts.get("Contacts", []):
                if contact.get("Name") == contact_name:
                    return contact
        return None
    except Exception as e:
        print(f"Error getting contact: {e}")
        return None


async def add_contact_async(username, name, mobile, email, job_title, company):
    try:
        new_contact = {
            "Name": name,
            "Contact": mobile,
            "Email": email,
            "Job": job_title,
            "Company": company
        }
        await user_contacts_collection.update_one(
            {"Username": username},
            {"$push": {"Contacts": new_contact}},
            upsert=True
        )
        return True, "Contact added successfully."
    except Exception as e:
        print(f"Error adding contact: {e}")
        return False, "An error occurred while adding the contact."


async def update_contact_async(username, old_name, new_name, mobile, email, job_title, company):
    try:
        user_doc = await user_contacts_collection.find_one({"Username": username})
        if user_doc:
            contacts = user_doc.get("Contacts", [])
            for contact in contacts:
                if contact.get("Name") == old_name:
                    contact['Name'] = new_name
                    contact['Contact'] = mobile
                    contact['Email'] = email
                    contact['Job'] = job_title
                    contact['Company'] = company
                    break

            await user_contacts_collection.update_one(
                {"Username": username},
                {"$set": {"Contacts": contacts}}
            )
            return True, "Contact updated successfully."
        return False, "Contact not found."
    except Exception as e:
        print(f"Error updating contact: {e}")
        return False, "An error occurred while updating the contact."


async def move_to_trash_async(username: str, contact_name: str):
    try:
        user_doc = await user_contacts_collection.find_one({"Username": username})
        if not user_doc:
            return False, "User not found."

        contact_to_move = None
        for contact in user_doc.get("Contacts", []):
            if contact.get("Name") == contact_name:
                contact_to_move = contact
                break

        if not contact_to_move:
            return False, "Contact not found."

        trash_item = {
            "Username": username,
            "Contact": contact_to_move,
            "deleted_at": datetime.datetime.utcnow()
        }
        await trash_collection.insert_one(trash_item)

        await user_contacts_collection.update_one(
            {"Username": username},
            {"$pull": {"Contacts": {"Name": contact_name}}}
        )
        return True, "Contact moved to trash successfully."
    except Exception as e:
        print(f"Error moving contact to trash: {e}")
        return False, "An error occurred while moving the contact to trash."


async def get_trashed_contacts_async(username: str):
    try:
        cursor = trash_collection.find({"Username": username})
        return await cursor.sort("deleted_at", -1).to_list(length=None)
    except Exception as e:
        print(f"Error getting trashed contacts: {e}")
        return []


async def restore_contact_async(username: str, contact_name: str):
    try:
        trashed_item = await trash_collection.find_one({"Username": username, "Contact.Name": contact_name})
        if not trashed_item:
            return False, "Contact not found in trash."

        contact_to_restore = trashed_item['Contact']

        await user_contacts_collection.update_one(
            {"Username": username},
            {"$push": {"Contacts": contact_to_restore}},
            upsert=True
        )

        await trash_collection.delete_one({"_id": trashed_item["_id"]})
        return True, "Contact restored successfully."
    except Exception as e:
        print(f"Error restoring contact: {e}")
        return False, "An error occurred while restoring the contact."


async def delete_permanently_async(username: str, contact_name: str):
    try:
        result = await trash_collection.delete_one({"Username": username, "Contact.Name": contact_name})
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


@app.route('/')
async def index():
    return jsonify({"message": "Welcome to the Contacts API!"})


@app.route('/api/v1/signup', methods=['POST'])
async def api_register():
    try:
        data = await request.get_json()
        name = data.get('name')
        username = data.get('username')
        password = data.get('password')
        mobile = data.get('mobile')

        if not all([name, username, password]):
            return jsonify({"error": "Missing required fields"}), 400

        if await check_user_async(username):
            return jsonify({"error": "Username already exists. Please choose a different one."}), 409

        success, message = await create_user_async(name, username, password, mobile)

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

            token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
            
            print(f"User '{username}' logged in successfully, JWT issued.")
            return jsonify({"success": True, "message": "Login successful", "token": token}), 200
        else:
            print(f"Failed login attempt for user '{username}'.")
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

    except Exception as e:
        print(f"Error in login API: {e}")
        return jsonify({"success": False, "error": "An internal server error occurred."}), 500


@app.route('/api/v1/contacts', methods=['GET'])
@jwt_required
async def api_contacts():
    try:
        contacts_list = await get_contacts_async(g.username)

        if not contacts_list:
            print(f"No contacts found for user '{g.username}'.")
        else:
            print(f"{len(contacts_list)} contacts found for user '{g.username}'.")

        return jsonify({"success": True, "contacts": contacts_list}), 200

    except Exception as e:
        print(f"Error fetching contacts in API: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/user', methods=['GET'])
@jwt_required
async def api_get_user_profile():
    try:
        user = await accounts.find_one({"Username": g.username})
        if user:
            user_info = {
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


@app.route('/api/v1/create_contact', methods=['POST'])
@jwt_required
async def api_create_contact():
    try:
        data = await request.get_json()
        if not data:
            print("Invalid JSON body received.")
            return jsonify({"error": "Invalid request body, expected JSON"}), 400

        name = data.get('name')
        mobile = data.get('mobile')
        email = data.get('email')
        job_title = data.get('job_title')
        company = data.get('company')

        if not name or not isinstance(name, str) or len(name.strip()) == 0:
            return jsonify({"error": "A valid 'name' (string) is required"}), 400

        if not mobile or not isinstance(mobile, str) or not mobile.isdigit():
            return jsonify({"error": "A valid 'mobile' number (digits only) is required"}), 400

        await add_contact_async(
            g.username,
            name,
            mobile,
            email,
            job_title,
            company
        )

        print(f"Contact '{name}' created successfully for user '{g.username}'.")
        return jsonify({"success": True, "message": "Contact created successfully"}), 201

    except TypeError as e:
        print(f"Data type error in request: {e}")
        return jsonify({"error": "Invalid data format provided."}), 400

    except Exception as e:
        print(f"An unexpected error occurred while creating contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/edit_contact/<contact_name>', methods=['GET', 'PUT'])
@jwt_required
async def api_edit_contact(contact_name):
    if request.method == 'GET':
        try:
            contact = await get_contact_by_name_async(g.username, contact_name)
            if contact:
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

            if not fname or not mobile:
                return jsonify({"error": "First name and Mobile are required fields."}), 400

            if not isinstance(mobile, str) or not mobile.isdigit():
                return jsonify({"error": "Mobile number must be a string of digits."}), 400

            new_name = f"{fname} {lname}" if lname else fname

            await update_contact_async(
                g.username,
                contact_name,
                new_name,
                mobile,
                email,
                job_title,
                company
            )

            print(f"Contact '{contact_name}' updated to '{new_name}' successfully.")
            return jsonify({"success": True, "message": "Contact updated successfully"}), 200

        except Exception as e:
            print(f"An unexpected error occurred while editing contact: {e}")
            return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/remove_contact/<contact_name>', methods=['DELETE'])
@jwt_required
async def api_remove_contact(contact_name):
    try:
        await move_to_trash_async(g.username, contact_name)

        print(f"Contact '{contact_name}' removed successfully for user '{g.username}'.")
        return jsonify({"success": True, "message": "Contact removed successfully"}), 200

    except Exception as e:
        print(f"An unexpected error occurred while removing contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/trash', methods=['GET'])
@jwt_required
async def api_get_trashed_contacts():
    try:
        trashed_docs = await get_trashed_contacts_async(g.username)

        for doc in trashed_docs:
            if '_id' in doc and doc['_id']:
                doc['_id'] = str(doc['_id'])

        return jsonify({"success": True, "trashed_contacts": trashed_docs}), 200

    except Exception as e:
        print(f"An unexpected error occurred while fetching trashed contacts: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/restore_contact/<contact_name>', methods=['POST'])
@jwt_required
async def api_restore_contact(contact_name):
    try:
        await restore_contact_async(g.username, contact_name)

        print(f"Contact '{contact_name}' restored successfully for user '{g.username}'.")
        return jsonify({"success": True, "message": "Contact restored successfully"}), 200

    except Exception as e:
        print(f"An unexpected error occurred while restoring contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/delete_permanently/<contact_name>', methods=['DELETE'])
@jwt_required
async def api_delete_permanently(contact_name):
    try:
        await delete_permanently_async(g.username, contact_name)

        print(f"Contact '{contact_name}' permanently deleted successfully for user '{g.username}'.")
        return jsonify({"success": True, "message": "Contact permanently deleted successfully"}), 200

    except Exception as e:
        print(f"An unexpected error occurred while permanently deleting contact: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/api/v1/empty_trash', methods=['DELETE'])
@jwt_required
async def api_empty_trash():
    try:
        await empty_trash_async(g.username)

        print(f"Trash emptied successfully for user '{g.username}'.")
        return jsonify({"success": True, "message": "Trash emptied successfully"}), 200

    except Exception as e:
        print(f"An unexpected error occurred while emptying trash: {e}")
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
    print(f"User '{g.username}' logged out successfully by client-side token removal.")
    return jsonify({"success": True, "message": "Logged out successfully"}), 200
