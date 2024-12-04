#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

from flask import request, make_response
from flask_restful import Resource
from app import db
from models import User  # Assuming User is defined in models.py

class Signup(Resource):
    def post(self):
        data = request.get_json()

        if not data:
            return make_response({"message": "Invalid JSON. No data provided."}, 400)
        
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        if not username or not password:
            return make_response({"message": "Username and password are required."}, 422)
        
        user = User.query.filter(User.username == username).first()
        if user:
            return make_response({"message": "Username already taken."}, 422)

        new_user = User(
            username=username,
            image_url=image_url,  
            bio=bio  
        )
        new_user.password_hash = password  

        db.session.add(new_user)
        db.session.commit()

        
        new_user_dict = new_user.to_dict()

        return make_response(new_user_dict, 201)


class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get('user_id')).first()
        if user:
            user_dict = user.to_dict()
            return make_response(
                user_dict,
                200
            )
        else:
            return {}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter(
            User.username == data['username']
        ).first()
        if user:
            session['user_id'] = user.id
            user_dict = user.to_dict()
            return make_response(
                user_dict,
                200
            )
        else:
            return make_response(
                {},
                401
            )


class Logout(Resource):
    def delete(self):
        if session['user_id'] is None:
            return make_response({"message": "Unauthorized"}, 401)
        
        else:    
            session['user_id'] = None
            return make_response({}, 204)

class RecipeIndex(Resource):

    def get(self):
        if session['user_id'] is None:
            return make_response(
                {},
                401
            )
        else:
            recipes = [recipe.to_dict() for recipe in Recipe.query.all()]
            return make_response(
                recipes,
                200
            )
        
   
    def post(self):
        data = request.get_json()
        user_id = session.get('user_id')

        if not user_id:
            return make_response({"message": "Unauthorized"}, 401)

        # Perform validation and recipe creation
        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id 
            )
        except ValueError as e:
            return make_response({"message": str(e)}, 422)

        # Fetch the user using the correct user_id with session.get()
        user = db.session.get(User, user_id)  # Replaced query.get() with session.get()
        
        if not user:
            return make_response({"message": "User not found"}, 404)  # Handle case if user doesn't exist

        db.session.add(new_recipe)
        db.session.commit()

        return make_response({
            "title": new_recipe.title,
            "instructions": new_recipe.instructions,
            "minutes_to_complete": new_recipe.minutes_to_complete,
            "user": {"id": user_id, "username": user.username},  # Return user info
        }, 201)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)