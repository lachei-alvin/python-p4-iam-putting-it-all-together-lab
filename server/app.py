#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api, bcrypt
from models import User, Recipe


# ---------------------------
# Signup Resource
# ---------------------------
class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            user = User(
                username=data["username"],
                image_url=data.get("image_url"),
                bio=data.get("bio"),
            )
            user.password_hash = data["password"]  # must use setter
            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id
            return user.to_dict(), 201

        except (KeyError, IntegrityError, ValueError):
            return {"error": "Invalid user data"}, 422


# ---------------------------
# Check Session Resource
# ---------------------------
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        return {"error": "401 Unauthorized"}, 401


# ---------------------------
# Login Resource
# ---------------------------
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get("username")).first()
        if user and user.authenticate(data.get("password", "")):
            session["user_id"] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid username or password"}, 401


# ---------------------------
# Logout Resource
# ---------------------------
class Logout(Resource):
    def delete(self):
        if session.get("user_id"):
            session.pop("user_id", None)
            return "", 204
        return {"error": "401 Unauthorized"}, 401


# ---------------------------
# RecipeIndex Resource
# ---------------------------
class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "401 Unauthorized"}, 401

        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return [recipe.to_dict(rules=("user",)) for recipe in recipes], 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "401 Unauthorized"}, 401

        data = request.get_json()
        try:
            recipe = Recipe(
                title=data["title"],
                instructions=data["instructions"],
                minutes_to_complete=data.get("minutes_to_complete"),
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(rules=("user",)), 201

        except (KeyError, ValueError):
            return {"error": "Invalid recipe data"}, 422


# ---------------------------
# Register Resources
# ---------------------------
api.add_resource(Signup, "/signup")
api.add_resource(CheckSession, "/check_session")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")
api.add_resource(RecipeIndex, "/recipes")


# ---------------------------
# Create Database Tables
# ---------------------------
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(port=5555, debug=True)
