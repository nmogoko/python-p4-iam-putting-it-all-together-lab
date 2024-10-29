#!/usr/bin/env python3
from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        if username is not None:
            user = User(username=username, image_url=image_url, bio=bio)
            user.password_hash = password

            db.session.add(user)
            db.session.commit()
            session["user_id"] = user.id
            return make_response(user.to_dict(), 201)
        
        return make_response({"error":"Invalid user"}, 422)


class CheckSession(Resource):
    def get(self):
        if session["user_id"] is not None:
            user = User.query.filter_by(id=session["user_id"]).first()
            return make_response(user.to_dict(), 200)
        
        return make_response({"error":"Unauthorized"}, 401)

class Login(Resource):
    def post(self):
        data = request.get_json()
        password = data.get("password")

        user = User.query.filter_by(username=data["username"]).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return make_response(user.to_dict(), 200)
        return make_response({"error":"Unauthorized"}, 401)
        

class Logout(Resource):
    def delete(self):
        if session["user_id"] is None:
            return make_response({}, 401)
        session["user_id"] = None
        return make_response({}, 204)

class RecipeIndex(Resource):
    def get(self):
        if session["user_id"] is None:
            return make_response({"error":"Unauthorized"}, 401)
        
        recipes = Recipe.query.filter_by(user_id=session["user_id"]).all()
        return make_response([recipe.to_dict() for recipe in recipes], 200)

    def post(self):
        try:
            if session["user_id"] is None:
                return make_response({"error":"Unauthorized"}, 401)
            
            data = request.get_json()
            recipe = Recipe(title=data["title"], instructions=data["instructions"], minutes_to_complete=data["minutes_to_complete"], user_id=session["user_id"])
            db.session.add(recipe)
            db.session.commit()

            return make_response(recipe.to_dict(), 201)
        except:
            return make_response({"error":"Unprocessable Entity"}, 422)


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)