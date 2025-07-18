
from flask import Flask, render_template, request
from flask_restful import Resource, Api
from flask_jwt_extended import (
  JWTManager, create_access_token,
  jwt_required,get_jwt_identity
)
from pyexpat.errors import messages
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select
from flask_migrate import Migrate ,upgrade


app = Flask(__name__)
api = Api(app)
jwt =JWTManager(app)
db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] =  'postgresql://postgres:zmhqsLQymtAYubCvGhYCTvCIZMUrjPxB@shinkansen.proxy.rlwy.net:17087/railway'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)


migrate = Migrate(app, db)

app.config['JWT_SECRET_KEY'] = "mykey"


class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(80), unique= True,nullable = False)
    password = db.Column(db.String(200),nullable = False)
    role = db.Column(db.String(80),nullable = False, default = 'user')

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course = db.Column(db.String(80), unique=True, nullable=False)
    price = db.Column(db.String(80), unique=True, nullable=False)



class RegisterUser(Resource):
    def post(self):
        execute_user = db.session.execute(select(User)).scalars().all()
        if not execute_user:
            data = request.get_json()
            password = data["password"]
            hashed_password = generate_password_hash(password)
            new_user = User(username=data["username"], password=hashed_password, role='admin')
            db.session.add(new_user)
            db.session.commit()
            access_token = create_access_token(identity=new_user.username)
            return {
                "message": "User created successfully",
                "access_token": access_token
            }, 201
        else:
            data = request.get_json()
            username = data["username"]
            user = User.query.filter_by(username=username).first()

            if user:
                return {
                    "message": "User already registered", }, 400
            password = data["password"]
            hashed_password = generate_password_hash(password)
            new_user = User(username=data["username"], password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            access_token = create_access_token(identity=new_user.username)
            return {
                "message": "User created successfully",
                "access_token": access_token
            }, 201


class LoginUser(Resource):
    def post(self):
        data = request.get_json()
        query= User.query.filter_by(password = data['password'])
        user = db.session.execute(query)
        access_token = create_access_token(identity=data.get("username"))
        if user:
            return {
                "message": "Login successful",
                "access_token": access_token
            }, 200
        else:
            return {
                "message": "Invalid Credentials"
            }, 400


class ShowAll(Resource):
    def get(self):
        select_course = select(Course)
        selected_courses = db.session.execute(select_course).scalars().all()
        myList = []
        if selected_courses:
            for x in selected_courses:
                course = {
                    "course": x.course,
                    "price": x.price
                }
                myList.append(course)
            return myList, 200
        else:
            return {"message": "no available course at the moment "}, 404

class Admin(Resource):
    @jwt_required()
    def post(self):
        identity = get_jwt_identity()
        data = request.get_json()
        check_user = User.query.filter_by(username = identity).first()

        if check_user.role == 'admin':
            #check if course exists
            # check_course = Course.query.filter_by(course = data.get('course'))
            # if check_course:
            #     return {
            #         "message": "course already exists"
            #     }
            new_course = Course(price= data.get('price'),course= data.get('course'))
            db.session.add(new_course)
            db.session.commit()
            return {
                    "message": "course added successfully"
                     },201

        else:
            return {
                "message":"You are not an admin!"}

api.add_resource(RegisterUser,'/register')
api.add_resource(LoginUser,'/login')
api.add_resource(ShowAll,'/all')
api.add_resource(Admin,'/admin')


if __name__ == '__main__':
    with app.app_context():
        upgrade()
    app.run(debug=True)
