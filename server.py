from flask import Flask, request, redirect, render_template, session, flash 
from mysqlconnection import MySQLConnector
import os, re
from flask.ext.bcrypt import Bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, "wall")
app.secret_key = "os.urandom(24)"

@app.route("/", methods=["GET"])
def index():
	query="SELECT *FROM users"
	x=mysql.query_db(query)
	return render_template("index.html")
	

@app.route("/create_user", methods=["POST"])
def create_user():
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	email = request.form['email']
	password = request.form['password']
	pw_hash = bcrypt.generate_password_hash(password) 
	re_password=request.form['re_password']
	

	insert_query = "INSERT INTO users(first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())"
	query_data = {
				'first_name':first_name,
				'last_name':last_name,
				'email':email,
				'pw_hash':pw_hash,
				}
	mysql.query_db(insert_query, query_data)
	return redirect('/')


@app.route('/login', methods=["POST"])
def login():
	print "something"
	email= request.form['email']
	password = request.form['password']
	print email
	user_query = "SELECT * FROM users WHERE email = :email"
	query_data = {'email':email }
	user=mysql.query_db(user_query,query_data)

	if len(request.form['email']) < 1:
		flash('Email cannot be blank')
	elif not EMAIL_REGEX.match(request.form['email']):
		flash("Invalid email id{}".format(request.form['email']))
	else:
		flash("You are now logged in")

	if bcrypt.check_password_hash(user[0]['pw_hash'], password):
		flash('Success')
	else:
		flash('Invalid Login')
	return redirect ('/')



@app.route('/clear')
def clear():
	session.clear()
	return redirect('/')

app.run(debug=True)




