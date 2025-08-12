from flask import Flask, render_template, request, redirect, url_for, session
import pymongo as mongo
import urllib.parse as parser
import bcrypt
import re
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

uname = parser.quote_plus("Rajat")
passwd = parser.quote_plus("2844")
cluster = "cluster0.gpq2duh"
url = f"mongodb+srv://{uname}:{passwd}@{cluster}.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true"
client = mongo.MongoClient(url)
db = client["Contacts"]
helplines = db["Helplines"]
accounts = db["Accounts"]


def check_user(username: str) -> bool:
    try:
        chk_user = accounts.find_one({"Username": username})
        return chk_user is not None
    except Exception as e:
        print(f"Error while checking username: {e}")
        return False


def create_user(name, username, password, mobile):
    try:
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt())
        user = {
            "Name": name,
            "Username": username,
            "Password": hashed_password,
            "Contact": int(mobile) if re.match(r'^\d{10}$', mobile) else None,
            "Data": []
        }
        accounts.insert_one(user)
        return True
    except Exception as e:
        print(f"Error while creating account: {e}")
        return False


def verify_password(username, password):
    try:
        userdata = accounts.find_one({"Username": username})
        if userdata:
            return bcrypt.checkpw(password.encode('utf-8'), userdata["Password"])
        return False
    except Exception as e:
        print(f"Error while verifying password: {e}")
        return False


def get_user_contacts(username):
    user_doc = accounts.find_one({"Username": username})
    if user_doc and user_doc.get("Data"):
        return user_doc["Data"]
    return []


def create_contact_in_db(username: str, fname, lname, mobile, email):
    try:
        contact_data = {
            "Name": f"{fname} {lname}".strip(),
            "Contact": mobile,
            "Email": email
        }
        accounts.update_one(
            {"Username": username},
            {"$push": {"Data": contact_data}}
        )
        return True, "Contact created successfully."
    except Exception as e:
        return False, f"Error creating contact: {e}"


def remove_contact_from_db(username: str, contact_name):
    try:
        accounts.update_one(
            {"Username": username},
            {"$pull": {"Data": {"Name": contact_name}}}
        )
        return True, f"Contact '{contact_name}' removed successfully."
    except Exception as e:
        return False, f"Error removing contact: {e}"


def get_contact_by_name(username: str, contact_name: str):
    user_doc = accounts.find_one({"Username": username})
    if user_doc and user_doc.get("Data"):
        for contact in user_doc["Data"]:
            if contact["Name"] == contact_name:
                return contact
    return None


def update_contact_in_db(username: str, old_contact_name: str, new_fname: str, new_lname: str, new_mobile: str, new_email: str):
    new_contact_name = f"{new_fname} {new_lname}".strip()
    try:
        accounts.update_one(
            {"Username": username, "Data.Name": old_contact_name},
            {"$set": {
                "Data.$.Name": new_contact_name,
                "Data.$.Contact": new_mobile,
                "Data.$.Email": new_email
            }}
        )
        return True, "Contact updated successfully."
    except Exception as e:
        return False, f"Error updating contact: {e}"


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('contacts'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
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
    if 'username' not in session:
        return redirect(url_for('login'))

    user_contacts = get_user_contacts(session['username'])
    return render_template('contacts.html', contacts=user_contacts)


@app.route('/create_contact', methods=['POST'])
def create_contact():
    if 'username' not in session:
        return redirect(url_for('login'))

    form = request.form
    fname = form.get('fname')
    lname = form.get('lname')
    mobile = form.get('mobile')
    email = form.get('email')

    if fname and mobile:
        success, message = create_contact_in_db(
            session['username'], fname, lname, mobile, email)

    return redirect(url_for('contacts'))


@app.route('/edit_contact/<contact_name>', methods=['GET', 'POST'])
def edit_contact(contact_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    contact = get_contact_by_name(session['username'], contact_name)
    if not contact:
        return redirect(url_for('contacts'))

    if request.method == 'POST':
        form = request.form
        fname = form.get('fname')
        lname = form.get('lname')
        mobile = form.get('mobile')
        email = form.get('email')

        if fname and mobile:
            success, message = update_contact_in_db(
                session['username'],
                contact_name,
                fname,
                lname,
                mobile,
                email
            )

        return redirect(url_for('contacts'))

    return render_template('edit_contact.html', contact=contact)


@app.route('/remove_contact/<contact_name>')
def remove_contact(contact_name):
    if 'username' not in session:
        return redirect(url_for('login'))

    success, message = remove_contact_from_db(
        session['username'], contact_name)

    return redirect(url_for('contacts'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


def initialize_db():
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
    except Exception as e:
        print(f"Error during database initialization: {e}")


if __name__ == '__main__':
    initialize_db()
