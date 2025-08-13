import asyncio
from flask import Flask, render_template, request, redirect, url_for, session
import pymongo as mongo
import urllib.parse as parser
import bcrypt
import re
import os
import datetime
import json
from bson.objectid import ObjectId

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB connection details
# NOTE: The provided user and password in the original code are for demonstration.
# In a real-world application, you should use environment variables for sensitive information.
uname = parser.quote_plus("Rajat")
passwd = parser.quote_plus("2844")
cluster = "cluster0.gpq2duh"
url = f"mongodb+srv://{uname}:{passwd}@{cluster}.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true"

# Synchronous MongoDB client
client = mongo.MongoClient(url)
db = client["Contacts"]
helplines = db["Helplines"]
accounts = db["Accounts"]
user_contacts_collection = db["User_contacts"]
trash_collection = db["Trash"]  # Collection for deleted contacts

def check_user_sync(username: str) -> bool:
    """Checks if a username already exists in the database."""
    try:
        chk_user = accounts.find_one({"Username": username})
        return chk_user is not None
    except Exception as e:
        print(f"Error while checking username: {e}")
        return False

def create_user_sync(name, username, password, mobile):
    """Creates a new user account."""
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        accounts.insert_one({
            "Name": name,
            "Username": username,
            "Password": hashed_password.decode('utf-8'),
            "Email": "N/A",  # Default email
            "Mobile": mobile,
            "Job": "N/A",
            "Company": "N/A",
            "Profile_pic": "N/A"
        })
        return True
    except Exception as e:
        print(f"Error while creating user: {e}")
        return False

def get_user_contacts_sync(username):
    """Retrieves all contacts for a given user."""
    user_contacts = user_contacts_collection.find_one({"Username": username})
    if user_contacts and "Contacts" in user_contacts:
        return user_contacts["Contacts"]
    return []

def add_user_contact_sync(username, contact):
    """Adds a new contact for a user."""
    # Check if the user's document exists
    if not user_contacts_collection.find_one({"Username": username}):
        user_contacts_collection.insert_one({
            "Username": username,
            "Contacts": []
        })

    # Add the new contact to the user's document
    user_contacts_collection.update_one(
        {"Username": username},
        {"$push": {"Contacts": contact}}
    )
    return True

def get_user_profile_sync(username):
    """Retrieves the user's profile information."""
    return accounts.find_one({"Username": username})

def update_user_profile_sync(username, new_data):
    """Updates the user's profile information."""
    accounts.update_one({"Username": username}, {"$set": new_data})
    return True

def move_to_trash_sync(username, contact_name):
    """Moves a contact to the trash collection."""
    user_contacts_doc = user_contacts_collection.find_one({"Username": username})
    if not user_contacts_doc:
        return False

    contact_to_move = next((c for c in user_contacts_doc["Contacts"] if c["Name"] == contact_name), None)
    if not contact_to_move:
        return False

    # Remove contact from user's contacts
    user_contacts_collection.update_one(
        {"Username": username},
        {"$pull": {"Contacts": {"Name": contact_name}}}
    )

    # Check if the user's trash document exists
    if not trash_collection.find_one({"Username": username}):
        trash_collection.insert_one({"Username": username, "Contacts": []})

    # Add contact to trash
    trash_collection.update_one(
        {"Username": username},
        {"$push": {"Contacts": contact_to_move}}
    )
    return True

def get_trash_contacts_sync(username):
    """Retrieves contacts from the trash for a given user."""
    trash_contacts = trash_collection.find_one({"Username": username})
    if trash_contacts and "Contacts" in trash_contacts:
        return trash_contacts["Contacts"]
    return []

def restore_contact_sync(username, contact_name):
    """Restores a contact from the trash."""
    trash_doc = trash_collection.find_one({"Username": username})
    if not trash_doc:
        return False

    contact_to_restore = next((c for c in trash_doc["Contacts"] if c["Name"] == contact_name), None)
    if not contact_to_restore:
        return False

    # Remove from trash
    trash_collection.update_one(
        {"Username": username},
        {"$pull": {"Contacts": {"Name": contact_name}}}
    )

    # Restore to user's contacts
    if not user_contacts_collection.find_one({"Username": username}):
        user_contacts_collection.insert_one({"Username": username, "Contacts": []})
    
    user_contacts_collection.update_one(
        {"Username": username},
        {"$push": {"Contacts": contact_to_restore}}
    )
    return True

def delete_permanently_sync(username, contact_name):
    """Deletes a contact permanently from the trash."""
    trash_collection.update_one(
        {"Username": username},
        {"$pull": {"Contacts": {"Name": contact_name}}}
    )
    return True

def empty_trash_sync(username):
    """Empties the trash for a user."""
    trash_collection.update_one(
        {"Username": username},
        {"$set": {"Contacts": []}}
    )
    return True

def edit_contact_sync(username, old_contact_name, new_contact_data):
    """Edits an existing contact."""
    user_contacts_collection.update_one(
        {"Username": username, "Contacts.Name": old_contact_name},
        {"$set": {
            "Contacts.$.Mobile": new_contact_data.get("Mobile", ""),
            "Contacts.$.Email": new_contact_data.get("Email", ""),
            "Contacts.$.Job": new_contact_data.get("Job", ""),
            "Contacts.$.Company": new_contact_data.get("Company", ""),
            "Contacts.$.Name": new_contact_data.get("Name", old_contact_name),
        }}
    )
    return True


# This function will run before the first request to seed the database
@app.before_first_request
def initialize_db():
    try:
        if helplines.count_documents({}) == 0:
            print("Database is empty. Seeding with initial contacts...")
            helplines.insert_many([
                {"_id": "0000100", "Name": "Police", "Contact": "100"},
                {"_id": "0000108", "Name": "Ambulance", "Contact": "108"},
                {"_id": "0000101", "Name": "Fire Department", "Contact": "101"},
                {"_id": "00001098", "Name": "Child Helpline", "Contact": "1098"}
            ])
            print("Seeding complete.")
    except Exception as e:
        print(f"Error during database initialization: {e}")


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('contacts'))
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = accounts.find_one({"Username": username})
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['Password'].encode('utf-8')):
        session['username'] = username
        return redirect(url_for('contacts'))
    else:
        return render_template('index.html', error="Invalid username or password")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form['password']
        mobile = request.form.get('mobile')
        
        if check_user_sync(username):
            return render_template('register.html', error="Username already exists!")
        
        create_user_sync(name, username, password, mobile)
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/contacts')
def contacts():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = get_user_profile_sync(session['username'])
    user_contacts = get_user_contacts_sync(session['username'])
    
    helplines_list = list(helplines.find({}))
    
    return render_template('contacts.html', user=user, contacts=user_contacts, helplines=helplines_list)

@app.route('/add_contact', methods=['POST'])
def add_contact():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    name = f"{request.form.get('fname')} {request.form.get('lname')}"
    new_contact = {
        "Name": name.strip(),
        "Mobile": request.form.get('mobile'),
        "Email": request.form.get('email'),
        "Job": request.form.get('job-title'),
        "Company": request.form.get('company')
    }
    
    add_user_contact_sync(session['username'], new_contact)
    return redirect(url_for('contacts'))

@app.route('/delete_contact/<contact_name>')
def delete_contact(contact_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    move_to_trash_sync(session['username'], contact_name)
    return redirect(url_for('contacts'))

@app.route('/edit_contact/<old_contact_name>', methods=['POST'])
def edit_contact(old_contact_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    new_contact_name = f"{request.form.get('fname')} {request.form.get('lname')}".strip()
    
    new_contact_data = {
        "Name": new_contact_name,
        "Mobile": request.form.get('mobile'),
        "Email": request.form.get('email'),
        "Job": request.form.get('job-title'),
        "Company": request.form.get('company')
    }

    edit_contact_sync(session['username'], old_contact_name, new_contact_data)
    return redirect(url_for('contacts'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = get_user_profile_sync(session['username'])
    return render_template('profile.html', user=user)


@app.route('/trash')
def trash_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user_trash_contacts = get_trash_contacts_sync(session['username'])
    return render_template('trash.html', trash_contacts=user_trash_contacts)

@app.route('/restore_contact/<contact_name>')
def restore_contact(contact_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    restore_contact_sync(session['username'], contact_name)
    return redirect(url_for('trash_page'))

@app.route('/delete_permanently/<contact_name>')
def delete_permanently(contact_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    delete_permanently_sync(session['username'], contact_name)
    return redirect(url_for('trash_page'))


@app.route('/empty_trash')
def empty_trash():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    empty_trash_sync(session['username'])
    return redirect(url_for('trash_page'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
