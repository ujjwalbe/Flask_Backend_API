"""Author: Ujjwal Biswas
Date: 2021-06-03 01:49:40
GitHub: https://github.com/ujjwalbe
"""

import os
import sys
from flask import Flask
from flask import request, Response
from datetime import datetime
from flask import jsonify
import psycopg2
import hashlib
import random
import datetime
import jwt
import json
import re

app = Flask(__name__)

database = os.environ["DB_NAME"]
database_user = os.environ["DB_USER"]
database_password = os.environ["DB_PASSWORD"]
database_host = os.environ["DB_HOST"]
jwt_secret = os.environ["JWT_SECRET"]

reg = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,253}[a-zA-Z0-9])?)*$"
# JWT Validation and Generation
class JwtValidation:
    def encode(self, payload):
        jwt_token = jwt.encode(
            payload={
                "payload": payload,
                "exp": datetime.datetime.utcnow()
                + datetime.timedelta(minutes=2880),  # Expires in 2 days
                "iat": datetime.datetime.utcnow(),
            },
            key=jwt_secret,
            algorithm="HS256",
        )
        return jwt_token

    def decode(self, jwt_token):
        try:
            payload = jwt.decode(jwt_token, jwt_secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            print("Expired")
            return None, False
        except jwt.InvalidTokenError:
            print("Invalid")
            return None, False
        return payload, True


# Connection to database
class DbConnection:
    def __init__(
        self,
        database=database,
        user=database_user,
        host=database_host,
        password=database_password,
    ):
        try:
            self.conn = psycopg2.connect(
                database=database, password=database_password, user=database_user
            )
            self.cur = self.conn.cursor()
            print(f"Database connected on {host}")
        except psycopg2.DatabaseError as e:
            print(f"Error Message: Unable make database connection on {host}!")
            print(e)
            sys.exit(1)

    # Query returns multiple values
    def query_all(self, query):
        try:
            self.cur.execute(query)
            return self.cur.fetchall()
        except Exception as e:
            print(f"Error: {e}")

    # Query returns single value
    def query_one(self, query):
        try:
            self.cur.execute(query)
            return self.cur.fetchone()
        except Exception as e:
            print(f"Error: {e}")

    # Query adds data to tables
    def insert_one(self, query):
        try:
            self.cur.execute(query)
            self.conn.commit()
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            print(e)

    # close Cursors and connection
    def close(self):
        self.cur.close()
        self.conn.close()


class PasswordHasher:
	# Hashes password 
    def hash_password(self, password):
        hash = hashlib.sha256()
        hash.update(bytes(password, "utf-8"))
        hashed_password = hash.hexdigest()
        return hashed_password
	# Compares password with hashed
    def validated_password(self, password, hashed):
        hashed_password = self.hash_password(password)
        if hashed == hashed_password:
            return True
        return False


# db instance
db = DbConnection()
jwt_validation = JwtValidation()
hasher = PasswordHasher()


def generate_random():
    ran = random.randint(1, 10)  # 1 -10 for testing purposes
    return ran


@app.route("/api/v1/register", methods=["POST"])
def register_user():
    if not request.data:
        res = None
        print(res)
        return (
            jsonify({"error_message": "Invalid data.", "error_name": "bad_request"}),
            400,
        )

    data = request.get_json()
    full_name = str(data.get("name", None))
    password = data.get("password", None)
    email = data.get("email", None)

    # If no password and email is given returns invalid response
    if email is None and password is None:
        return (
            jsonify({"error_message": "Invalid email.", "error_name": "bad_request"}),
            400,
        )
    
    if not re.match(reg, str(email)):
        return (
            jsonify({"error_message": "Invalid email.", "error_name": "bad_request"}),
            400,
        )
    # Checks if user already exist
    email_exist = db.query_one(f"SELECT ID FROM CUSTOMERS WHERE EMAIL='{email}'")
    if email_exist:
        return (
            jsonify(
                {
                    "error_message": "User already exist with this Email!",
                    "error_name": "bad_request",
                }
            ),
            400,
        )
    # Password hashing
    hashed_password = hasher.hash_password(password)
    task_group_id = generate_random()
    query = f"INSERT INTO customers (NAME, EMAIL, PASSWORD, TASK_GROUP_ID) VALUES('{full_name}', '{email}', '{hashed_password}', {task_group_id})"
    db.insert_one(query)
    res = {"result": "ok"}
    return (jsonify(res), 201)


@app.route("/api/v1/signin", methods=["POST"])
def signin_user():
    """User Sign In method

    Returns:
       JWT Token: Returns JWT token
    """
    if not request.data:
        res = None
        print(res)
        # Response(res, status=400, mimetype='application/json')
        return (
            jsonify({"error_message": "Invalid data.", "error_name": "bad_request"}),
            400,
        )
    # Gets request data as json
    data = request.get_json()
    email = data.get("email", None)
    password = data.get("password", None)
    if not email:
        return (
            jsonify(
                {"error_message": "Please provide email.", "error_name": "bad_request"}
            ),
            400,
        )
    user = db.query_one(
        f"SELECT ID, PASSWORD , LAST_SIGNIN_ATTEMPT, FAILED_SIGNIN_ATTEMPT FROM CUSTOMERS WHERE EMAIL='{email}'"
    )
    print(user)
    if not user:
        return (
            jsonify(
                {
                    "error_message": "Invalid email or password.",
                    "error_name": "bad_request",
                }
            ),
            400,
        )
    if hasher.validated_password(hashed=user[1], password=password):
        # Updates user last login
        db.insert_one(
            f"UPDATE CUSTOMERS SET LAST_SIGNIN_ATTEMPT=TIMESTAMP '{str(datetime.datetime.now()).split('.')[0]}' WHERE ID='{user[0]}'"
        )
        jwt_token = jwt_validation.encode({"id": user[0]})
        return (jsonify({"auth_token": jwt_token}), 200)
    # Updates failed sign in and last login
    db.insert_one(
        f"UPDATE CUSTOMERS SET LAST_SIGNIN_ATTEMPT=TIMESTAMP '{str(datetime.datetime.now()).split('.')[0]}', FAILED_SIGNIN_ATTEMPT={1 if user[3] == None else user[3] + 1} WHERE ID='{user[0]}'"
    )
    return (
        jsonify(
            {
                "error_message": "Invalid email or password.",
                "error_name": "bad_request",
            }
        ),
        400,
    )


@app.route("/api/v1/tasks", methods=["GET"])
def get_user_tasks():
    """Get Users Task from database

    Returns:
            JSON: List of tasks

    """
    token = request.headers.get("Authorization")
    # Prevents if no authorization headers passed in the request
    if not token:
        return (
            jsonify(
                {"error_message": "Unauthorized Access.", "error_name": "unauthorized"}
            ),
            401,
        )
    # 0 1
    # Bearer token
    token = token.split(" ")[1]

    jwt_data, state = jwt_validation.decode(token)
    if not state:
        return (
            jsonify(
                {"error_message": "Unauthorized Access.", "error_name": "unauthorized"}
            ),
            401,
        )
    # User verified to get user task
    user_id = jwt_data["payload"]["id"]
    group_id = db.query_one(f"SELECT task_group_id FROM CUSTOMERS WHERE ID='{user_id}'")
    tasks = db.query_all(f"SELECT * FROM TASKS WHERE GROUP_ID='{group_id[0]}'")

    results = []
    if len(tasks) > 0:
        for task in tasks:
            obj = {"id": task[0], "description": task[2]}
            results.append(obj)
    return (jsonify(results), 200)
