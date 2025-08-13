import os
import re
import bcrypt
import datetime
import urllib.parse as parser
import pymongo
from flask import Flask, render_template, request, redirect, url_for, session

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB connection details
uname = parser.quote_plus("Rajat")
passwd = parser.quote_plus("2844")
cluster = "cluster0.gpq2duh"
url = f"mongodb+srv://{uname}:{passwd}@{cluster}.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true"

# Establish a synchronous connection to MongoDB using pymongo
client = pymongo.MongoClient(url)
db = client["Contacts"]
helplines = db["Helplines"]
accounts = db["Accounts"]
user_contacts_collection = db["User_contacts"]
trash_collection = db["Trash"] # Collection for deleted contacts

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
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        accounts.insert_one({
            "Name": name,
            "Username": username,
            "Password": hashed_password,
            "Mobile": mobile
        })
        return True
    except Exception as e:
        print(f"Error while creating user: {e}")
        return False

def check_login(username, password):
    """Checks user credentials for login."""
    try:
        user = accounts.find_one({"Username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user["Password"]):
            return user
        return None
    except Exception as e:
        print(f"Error during login check: {e}")
        return None

def add_contact_to_db(username, contact_name, mobile, email, job, company):
    """Adds a new contact to the user's contact list."""
    try:
        # Check if a contact with the same name already exists for the user
        existing_contact = user_contacts_collection.find_one({"Username": username, "Name": contact_name})
        if existing_contact:
            return False # Contact with this name already exists

        user_contacts_collection.insert_one({
            "Username": username,
            "Name": contact_name,
            "Mobile": mobile,
            "Email": email,
            "Job": job,
            "Company": company,
            "created_at": datetime.datetime.utcnow()
        })
        return True
    except Exception as e:
        print(f"Error while adding contact: {e}")
        return False

def get_user_contacts(username):
    """Retrieves all contacts for a given user."""
    try:
        contacts = user_contacts_collection.find({"Username": username})
        return list(contacts)
    except Exception as e:
        print(f"Error while fetching contacts: {e}")
        return []

def get_user_profile(username):
    """Retrieves the user's profile information."""
    try:
        user = accounts.find_one({"Username": username})
        return user
    except Exception as e:
        print(f"Error while fetching user profile: {e}")
        return None

def get_contact_by_name(username, contact_name):
    """Retrieves a specific contact by name for a user."""
    try:
        contact = user_contacts_collection.find_one({"Username": username, "Name": contact_name})
        return contact
    except Exception as e:
        print(f"Error while fetching contact by name: {e}")
        return None

def update_contact_in_db(username, old_contact_name, new_fname, new_lname, new_mobile, new_email, new_job, new_company):
    """Updates an existing contact's information."""
    try:
        full_name = f"{new_fname} {new_lname}".strip()
        update_doc = {
            "Name": full_name,
            "Mobile": new_mobile,
            "Email": new_email,
            "Job": new_job,
            "Company": new_company,
            "updated_at": datetime.datetime.utcnow()
        }
        user_contacts_collection.update_one({"Username": username, "Name": old_contact_name}, {"$set": update_doc})
        return True
    except Exception as e:
        print(f"Error while updating contact: {e}")
        return False

def move_to_trash(username, contact_name):
    """Moves a contact from the main list to the trash."""
    try:
        contact = user_contacts_collection.find_one_and_delete({"Username": username, "Name": contact_name})
        if contact:
            contact["deleted_at"] = datetime.datetime.utcnow()
            trash_collection.insert_one(contact)
        return True
    except Exception as e:
        print(f"Error while moving contact to trash: {e}")
        return False

def get_trash_contacts(username):
    """Retrieves contacts from the user's trash."""
    try:
        contacts = trash_collection.find({"Username": username})
        return list(contacts)
    except Exception as e:
        print(f"Error while fetching trash contacts: {e}")
        return []

def restore_contact_from_trash(username, contact_name):
    """Restores a contact from the trash to the main list."""
    try:
        contact = trash_collection.find_one_and_delete({"Username": username, "Name": contact_name})
        if contact:
            user_contacts_collection.insert_one(contact)
        return True
    except Exception as e:
        print(f"Error while restoring contact: {e}")
        return False

def delete_permanently(username, contact_name):
    """Permanently deletes a contact from the trash."""
    try:
        trash_collection.delete_one({"Username": username, "Name": contact_name})
        return True
    except Exception as e:
        print(f"Error while permanently deleting contact: {e}")
        return False

def empty_trash_sync(username):
    """Empties the trash for a user."""
    try:
        trash_collection.delete_many({"Username": username})
        return True
    except Exception as e:
        print(f"Error while emptying trash: {e}")
        return False


#
# Routes
#

@app.route('/')
def index():
    """Renders the login page."""
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = check_login(username, password)
        if user:
            session['username'] = username
            return redirect(url_for('contacts'))
        return render_template('index.html', error="Invalid username or password")
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        mobile = request.form.get('mobile')
        
        # Simple validation
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            return render_template('register.html', error="Username can only contain alphanumeric characters and underscores.")
        if len(password) < 8:
            return render_template('register.html', error="Password must be at least 8 characters long.")
        if check_user(username):
            return render_template('register.html', error="Username already exists")
        
        if create_user(name, username, password, mobile):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="Registration failed. Please try again.")

    return render_template('register.html')


@app.route('/profile')
def profile():
    """Displays the user's profile."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = get_user_profile(session['username'])
    if not user:
        return redirect(url_for('login'))
        
    return render_template('profile.html', user=user)


@app.route('/contacts')
def contacts():
    """Displays the user's contact list."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_contacts = get_user_contacts(session['username'])
    helpline_contacts = list(helplines.find({}))
    
    return render_template('contacts.html', contacts=user_contacts, helplines=helpline_contacts)


@app.route('/add_contact', methods=['POST'])
def add_contact():
    """Handles adding a new contact."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    fname = request.form.get('fname')
    lname = request.form.get('lname')
    mobile = request.form.get('mobile')
    email = request.form.get('email')
    job = request.form.get('job-title')
    company = request.form.get('company')

    full_name = f"{fname} {lname}".strip()

    if add_contact_to_db(session['username'], full_name, mobile, email, job, company):
        return redirect(url_for('contacts'))
    else:
        # Handle the case where the contact already exists
        return redirect(url_for('contacts'))


@app.route('/edit_contact/<string:contact_name>', methods=['POST'])
def edit_contact(contact_name):
    """Handles editing an existing contact."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    old_contact_name = request.form.get('edit-old-contact-name')
    new_fname = request.form.get('edit-fname')
    new_lname = request.form.get('edit-lname')
    new_mobile = request.form.get('edit-mobile')
    new_email = request.form.get('edit-email')
    new_job = request.form.get('edit-job-title')
    new_company = request.form.get('edit-company')
    
    # Use the original contact_name to find and update the contact in the database
    update_contact_in_db(session['username'], old_contact_name, new_fname, new_lname, new_mobile, new_email, new_job, new_company)
    
    return redirect(url_for('contacts'))


@app.route('/delete_contact/<string:contact_name>')
def delete_contact(contact_name):
    """Moves a contact to the trash."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    move_to_trash(session['username'], contact_name)
    return redirect(url_for('contacts'))


@app.route('/trash')
def trash_page():
    """Displays the trash page with deleted contacts."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    trash_contacts = get_trash_contacts(session['username'])
    return render_template('trash.html', trash_contacts=trash_contacts)


@app.route('/restore_contact/<string:contact_name>')
def restore_contact(contact_name):
    """Restores a contact from the trash."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    restore_contact_from_trash(session['username'], contact_name)
    return redirect(url_for('trash_page'))


@app.route('/delete_permanently/<string:contact_name>')
def delete_permanently_route(contact_name):
    """Permanently deletes a contact from the trash."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    delete_permanently(session['username'], contact_name)
    return redirect(url_for('trash_page'))


@app.route('/empty_trash')
def empty_trash():
    """Empties the trash for the logged-in user."""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    empty_trash_sync(session['username'])
    return redirect(url_for('trash_page'))


@app.route('/logout')
def logout():
    """Logs out the user."""
    session.pop('username', None)
    return redirect(url_for('index'))

def initialize_db():
    """Seeds the helpline contacts into the database on the first request."""
    try:
        count = helplines.count_documents({})
        if count == 0:
            print("Database is empty. Seeding with initial contacts...")
            helplines.insert_many([
                {"_id": "0000100", "Name": "Police", "Contact": "100"},
                {"_id": "0000108", "Name": "Ambulance", "Contact": "108"},
                {"_id": "0000101", "Name": "Fire Department", "Contact": "101"},
                {"_id": "00001098", "Name": "Child Helpline", "Contact": "1098"}
            ])
            print("Helpline contacts seeded successfully.")
    except Exception as e:
        print(f"Error during database initialization: {e}")


if __name__ == '__main__':
    initialize_db()

