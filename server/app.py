#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from flask_bcrypt import Bcrypt

from config import app, db, api
from models import User

bcrypt = Bcrypt()

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):

    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201

    #Create a Signup resource with a post() method that responds to a POST /signup request. It should: create a new user; save their hashed password in the database; save the user's ID in the session object; and return the user object in the JSON response.

class CheckSession(Resource):

    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify({"username": user.username})
            else:
                return '', 204
        else:
            return '', 204

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        if not json_data:
            return jsonify({"message": "No input data provided"}), 400

        username = json_data.get('username')
        password = json_data.get('password')

        if not username or not password:
            return jsonify({"message": "Missing username or password"}), 400

        user = User.query.filter_by(username=username).first()
        if user and password:
            session['user_id'] = user.id
            return jsonify({"username": user.username})
        else:
            return jsonify({"message": "Invalid username or password"}), 401

class Logout(Resource):
    
    def delete(self):
        session.pop('user_id', None)
        return {"message": "Successfully logged out"}, 200

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
