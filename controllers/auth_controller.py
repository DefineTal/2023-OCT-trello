from datetime import timedelta

from flask import Blueprint, request
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import create_access_token
from psycopg2 import errorcodes

from init import db, bcrypt
from models.user import User, user_schema

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route("/register", methods=["POST"]) # /auth/resister
def auth_register():
    try:
        # the data that we get in the body of the request
        body_data = request.get_json()

        # create the user instance
        user = User(
            name=body_data.get('name'),
            email=body_data.get('email')
        )

        # password from the request body
        password = body_data.get('password')

        # if password exists, hash the password
        if password:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')

        # add and commit to db
        db.session.add(user)
        db.session.commit()
        # respond back to client
        return user_schema.dump(user), 201
    
    except IntegrityError as err:
        if err.orig.pgcode == errorcodes.NOT_NULL_VIOLATION:
            return {"error": f"{err.orig.diag.column_name} is null"}, 409
        if err.orig.pgcode == errorcodes.UNIQUE_VIOLATION:
            return {"error": "Email address already in use"}, 409
    
@auth_bp.route("/login", methods=["POST"])
def auth_login():
    # get the request body
    body_data = request.get_json()
    # find the user with matching email address
    stmt = db.Select(User).filter_by(email=body_data.get("email"))
    user = db.session.scalar(stmt)
    # if user exists is password correct
    if user and bcrypt.check_password_hash(user.password, body_data.get("password")):
        # create jwt
        token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))
        # return jwt along with user info
        return {"email": user.email, "token": token, "is_admin": user.is_admin}
    # else
    else:
        # return error email and password is incorrect
        return {"error": "email and password combination is incorrect"}, 401