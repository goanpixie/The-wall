from flask import Flask, request, url_for, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import os, re
from flask.ext.bcrypt import Bcrypt

from functools import wraps

# from flask_bcrypt import generate_password_hash

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
NAME_REGEX = re.compile(r'^[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, "wall")
app.secret_key = "os.urandom(24)"

@app.route("/", methods=["GET"])
def index():
	# query= "SELECT *FROM users"
	# x = mysql.query_db(query)
	# return render_template("index.html")

	if 'alert_messages' not in session:
		session['alert_messages'] = ''
		print session['alert_messages']

	return render_template('index.html')

@app.route("/create_user", methods=["POST"])
def create_user():
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	email = request.form['email']
	password = request.form['password']
	re_password=request.form['re_password']

	if (validate_input_credentials(first_name, last_name, email, password, re_password)):
		pw_hash = bcrypt.generate_password_hash(password)
		create_entry_in_database(first_name, last_name, email, pw_hash)
		# return 'I CREATED YOUR RECORD';
		return redirect('/login')
	else:
		return redirect('/')

@app.route('/login', methods=["POST"])
def login():
	email= request.form['email']
	password = request.form['password']
	print email
	user_query = "SELECT * FROM users WHERE email = :email"
	query_data = {'email':email }
	user = mysql.query_db(user_query, query_data)
	if bcrypt.check_password_hash(user[0]['pw_hash'], password):
		print 'Login successful'
		session['uid'] = user[0]['id']
		return redirect('/wall')
	else:
		print 'Invalid user'
		return redirect('/')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'uid' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

# This is an authenticated route.

@app.route('/wall')
@login_required
def wall():
	return render_template('wall.html')

@app.route('/clear')
def clear():
	session.clear()
	return redirect('/')



# Utility functions used for registration and authentication purpose..

def create_entry_in_database(first_name, last_name, email, pw_hash):
	insert_query = "INSERT INTO users(first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
	mysql.query_db(insert_query, { 'first_name':first_name, 'last_name':last_name, 'email':email, 'pw_hash': pw_hash })

def validate_input_credentials(first_name, last_name, email, password, re_password):
	print first_name, last_name
	is_valid = False
	is_first_name_valid = validate_name(first_name, 'First Name')
	is_last_name_valid = validate_name(last_name,  'Last Name')
	is_email_address_valid = EMAIL_REGEX.match(email)
	is_password_acceptable = validate_password(password, re_password)
	# not blank min 3 all letters
	# if len(first_name) < 1:
	# 	message = 'First name can not be blank'
	# elif len(first_name) < 3:
	# 	message = 'This needs to be greater than 3'
	# elif not NAME_REGEX.match(first_name):
	# 	message = 'Name not valid'

	return is_first_name_valid and is_last_name_valid and is_email_address_valid and is_password_acceptable

def validate_password(password, re_password):
	if len(password) > 8 and password == re_password:
		return True
	else:
		session['alert_messages'] += '<p class="red">Passwords do not match </p>'
		return False

def validate_name(name, name_type):
	message = ''
	if len(name) < 1:
		message = name_type +' can not be blank'
	elif len(name) < 3:
		message = name_type + ' needs to be greater than 3'
	elif not NAME_REGEX.match(name):
		message = name_type + ' can only contain letters'
	if len(message) > 1:
		session['alert_messages'] += '<p class="red">'+ message + '</p>'
		return False
	else:
		return True

app.run(debug=True)




