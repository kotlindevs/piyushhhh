# ==============================================================================
# Contact Management Web Application (Flask/WSGI)
#
# This application is a synchronous version of the original Quart application.
# It uses Flask for the web framework and pymongo for synchronous database
# interaction.
# ==============================================================================
from flask import Flask, render_template, request, redirect, url_for, session
import pymongo as mongo
from pymongo.collection import Collection
import urllib.parse as parser
import bcrypt
import re
import os
import datetime

# --- Flask App Initialization ---
app = Flask(__name__)
# The secret key is used for secure session management.
app.secret_key = os.urandom(24)

# --- MongoDB Configuration ---
# NOTE: In a production environment, database credentials should be stored in
# environment variables for security.
uname = parser.quote_plus("Rajat")
passwd = parser.quote_plus("2844")
cluster = "cluster0.gpq2duh"
url = f"mongodb+srv://{uname}:{passwd}@{cluster}.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true"

# Synchronous MongoDB client and database connection
client = mongo.MongoClient(url)
db = client["Contacts"]
helplines: Collection = db["Helplines"]
accounts: Collection = db["Accounts"]
trash_collection: Collection = db["Trash"] # Collection for deleted contacts


# --- Database Helper Functions (Synchronous) ---
def check_user(username: str) -> bool:
    """Checks if a username already exists in the database."""
    try:
        chk_user = accounts.find_one({"Username": username})
        return chk_user is not None
    except Exception as e:
        print(f"Error while checking username: {e}")
        return False


def create_user(name, username, password, mobile):
    """Creates a new user account."""
    try:
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        user = {
            "Name": name,
            "Username": username,
            "Password": hashed_password,
            "Contact": int(mobile) if re.match(r'^\d{10}$', mobile) else None,
            # The 'Data' array will store the user's contacts.
            "Data": []
        }
        accounts.insert_one(user)
        return True
    except Exception as e:
        print(f"Error while creating account: {e}")
        return False


def verify_password(username, password):
    """Verifies a user's password against the hashed password in the database."""
    try:
        userdata = accounts.find_one({"Username": username})
        if userdata:
            return bcrypt.checkpw(password.encode('utf-8'), userdata["Password"])
        return False
    except Exception as e:
        print(f"Error while verifying password: {e}")
        return False


def get_user_contacts(username):
    """Retrieves all contacts for a given user."""
    user_doc = accounts.find_one({"Username": username})
    if user_doc and user_doc.get("Data"):
        return user_doc["Data"]
    return []


def get_contact_by_name(username: str, contact_name: str):
    """Retrieves a single contact by name from the user's list."""
    user_doc = accounts.find_one({"Username": username})
    if user_doc and user_doc.get("Data"):
        for contact in user_doc["Data"]:
            if contact["Name"] == contact_name:
                return contact
    return None


def create_contact_in_db(username: str, fname, lname, mobile, email):
    """Adds a new contact to the user's contact list."""
    try:
        contact_data = {
            "Name": f"{fname} {lname}".strip(),
            "Contact": mobile,
            "Email": email,
            "Job": "", # Added to match original Quart app schema
            "Company": "" # Added to match original Quart app schema
        }
        accounts.update_one(
            {"Username": username},
            {"$push": {"Data": contact_data}}
        )
        return True, "Contact created successfully."
    except Exception as e:
        print(f"Error creating contact: {e}")
        return False, f"Error creating contact: {e}"


def update_contact_in_db(username: str, old_contact_name: str, new_name: str, mobile: str, email: str, job_title: str, company: str):
    """Updates an existing contact's details."""
    try:
        accounts.update_one(
            {"Username": username, "Data.Name": old_contact_name},
            {"$set": {
                "Data.$.Name": new_name,
                "Data.$.Contact": mobile,
                "Data.$.Email": email,
                "Data.$.Job": job_title,
                "Data.$.Company": company
            }}
        )
        return True, "Contact updated successfully."
    except Exception as e:
        print(f"Error updating contact: {e}")
        return False, f"Error updating contact: {e}"


def move_to_trash(username: str, contact_name: str):
    """Moves a contact from the user's list to the trash collection."""
    try:
        user_doc = accounts.find_one({"Username": username})
        if not user_doc:
            return False, "User not found."

        contact_to_move = None
        for contact in user_doc.get("Data", []):
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
        trash_collection.insert_one(trash_item)

        accounts.update_one(
            {"Username": username},
            {"$pull": {"Data": {"Name": contact_name}}}
        )
        return True, "Contact moved to trash successfully."
    except Exception as e:
        print(f"Error moving contact to trash: {e}")
        return False, "An error occurred while moving the contact to trash."


def get_trashed_contacts(username: str):
    """Retrieves all contacts in the trash for a given user, sorted by deletion date."""
    try:
        cursor = trash_collection.find({"Username": username})
        return list(cursor.sort("deleted_at", -1))
    except Exception as e:
        print(f"Error getting trashed contacts: {e}")
        return []


def restore_contact(username: str, contact_name: str):
    """Restores a contact from the trash back to the user's contact list."""
    try:
        trashed_item = trash_collection.find_one({"Username": username, "Contact.Name": contact_name})
        if not trashed_item:
            return False, "Contact not found in trash."

        contact_to_restore = trashed_item['Contact']

        accounts.update_one(
            {"Username": username},
            {"$push": {"Data": contact_to_restore}}
        )

        trash_collection.delete_one({"_id": trashed_item["_id"]})
        return True, "Contact restored successfully."
    except Exception as e:
        print(f"Error restoring contact: {e}")
        return False, "An error occurred while restoring the contact."


def delete_permanently(username: str, contact_name: str):
    """Permanently deletes a contact from the trash."""
    try:
        result = trash_collection.delete_one({"Username": username, "Contact.Name": contact_name})
        if result.deleted_count == 0:
            return False, "Contact not found in trash."
        return True, "Contact permanently deleted."
    except Exception as e:
        print(f"Error deleting contact permanently: {e}")
        return False, "An error occurred while deleting the contact."


def empty_trash(username: str):
    """Permanently deletes all contacts from the trash for a given user."""
    try:
        trash_collection.delete_many({"Username": username})
        return True, "Trash emptied successfully."
    except Exception as e:
        print(f"Error emptying trash: {e}")
        return False, "An error occurred while emptying the trash."


# --- Flask Routes ---
@app.route('/')
def index():
    """Renders the login/index page, redirects to contacts if logged in."""
    if 'username' in session:
        return redirect(url_for('contacts'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if 'username' in session:
        return redirect(url_for('contacts'))

    error = None
    success = request.args.get('success')

    if request.method == 'POST':
        form = request.form
        username = form.get('username')
        password = form.get('password')

        if verify_password(username, password):
            session['username'] = username
            return redirect(url_for('contacts'))

        error = 'Invalid username or password.'

    return render_template('index.html', error=error, success=success)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    error = None
    if request.method == 'POST':
        form = request.form
        name = form.get('name')
        username = form.get('username')
        password = form.get('password')
        mobile = form.get('mobile')

        if check_user(username):
            error = 'Username already exists.'
            return render_template('register.html', error=error)

        if create_user(name, username, password, mobile):
            return redirect(url_for('login', success='Account created successfully!'))
        else:
            error = 'An error occurred during registration.'
            return render_template('register.html', error=error)

    return render_template('register.html')


@app.route('/contacts')
def contacts():
    """Displays the main contacts page for the logged-in user."""
    if 'username' not in session:
        return redirect(url_for('login'))

    user_contacts = get_user_contacts(session['username'])
    return render_template('contacts.html', contacts=user_contacts)


@app.route('/create_contact', methods=['GET', 'POST'])
def create_contact():
    """
    Handles creating a new contact.
    GET: Displays the create contact form.
    POST: Processes the form submission.
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        form = request.form
        fname = form.get('name')
        mobile = form.get('mobile')
        email = form.get('email')
        job_title = form.get('job_title')
        company = form.get('company')

        # Note: The original Flask snippet was slightly different in fields,
        # this is aligned with the Quart version for consistency.
        if fname and mobile:
            success, message = create_contact_in_db(
                session['username'], fname, '', mobile, email)

        return redirect(url_for('contacts'))

    return render_template('create_contact.html')


@app.route('/edit_contact/<contact_name>', methods=['GET', 'POST'])
def edit_contact(contact_name):
    """Handles editing an existing contact."""
    if 'username' not in session:
        return redirect(url_for('login'))

    contact = get_contact_by_name(session['username'], contact_name)
    if not contact:
        return redirect(url_for('contacts'))

    if request.method == 'POST':
        form = request.form
        old_contact_name = form.get('old_contact_name')
        new_name = form.get('new_name')
        mobile = form.get('mobile')
        email = form.get('email')
        job_title = form.get('job_title')
        company = form.get('company')

        if new_name and mobile:
            update_contact_in_db(
                session['username'],
                old_contact_name,
                new_name,
                mobile,
                email,
                job_title,
                company
            )

        return redirect(url_for('contacts'))
    
    # Split the name for the form fields
    name_parts = contact['Name'].split(' ', 1)
    contact['fname'] = name_parts[0]
    contact['lname'] = name_parts[1] if len(name_parts) > 1 else ''
    
    return render_template('edit_contact.html', contact=contact)


@app.route('/remove_contact/<contact_name>')
def remove_contact(contact_name):
    """Moves a contact to the trash bin."""
    if 'username' not in session:
        return redirect(url_for('login'))

    move_to_trash(session['username'], contact_name)

    return redirect(url_for('contacts'))


@app.route('/trash')
def trash_page():
    """Displays the trash bin page with deleted contacts."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    trashed_docs = get_trashed_contacts(session['username'])
    
    # Format the 'deleted_at' timestamp for display
    for doc in trashed_docs:
        deleted_time = doc['deleted_at']
        now = datetime.datetime.utcnow()
        if deleted_time.date() == now.date():
            doc['deleted_at_formatted'] = f"Today, {deleted_time.strftime('%I:%M %p')}"
        else:
            doc['deleted_at_formatted'] = deleted_time.strftime('%b %d, %Y')

    return render_template('trash.html', trashed_docs=trashed_docs)


@app.route('/restore_contact/<contact_name>')
def restore_contact_route(contact_name):
    """Restores a contact from the trash."""
    if 'username' not in session:
        return redirect(url_for('login'))

    restore_contact(session['username'], contact_name)
    return redirect(url_for('trash_page'))


@app.route('/delete_permanently/<contact_name>')
def delete_permanently_route(contact_name):
    """Permanently deletes a contact from the trash."""
    if 'username' not in session:
        return redirect(url_for('login'))

    delete_permanently(session['username'], contact_name)
    return redirect(url_for('trash_page'))


@app.route('/empty_trash')
def empty_trash_route():
    """Permanently deletes all contacts from the trash."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    empty_trash(session['username'])
    return redirect(url_for('trash_page'))


@app.route('/logout')
def logout():
    """Logs the user out and clears the session."""
    session.pop('username', None)
    return redirect(url_for('index'))


def initialize_db():
    """Initializes the database with emergency helpline data if it's empty."""
    try:
        count = helplines.count_documents({})
        if count == 0:
            print("Database is empty. Seeding with initial contacts...")
            helplines.insert_many([
                {"_id": "0000100", "Name": "Police", "Contact": "100"},
                {"_id": "0000108", "Name": "Ambulance", "Contact": "108"},
                {"_id": "0000101", "Name": "Fire Department", "Contact": "101"},
                {"_id": "00001098", "Name": "Child Helpline", "Contact": "1098"},
                {"_id": "00001091", "Name": "Women's Helpline", "Contact": "1091"},
                {"_id": "0000112", "Name": "All-in-One Emergency", "Contact": "112"},
            ])
            print("Seeding complete.")
        else:
            print("Database already contains helpline data.")
    except Exception as e:
        print(f"Error during database initialization: {e}")


if __name__ == '__main__':
    initialize_db()

