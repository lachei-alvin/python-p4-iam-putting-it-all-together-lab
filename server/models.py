from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt


# ---------------------------
# User Model
# ---------------------------
class User(db.Model, SerializerMixin):
    __tablename__ = "users"
    serialize_rules = ("-_password_hash", "-recipes.user")  # hide password in JSON

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship("Recipe", backref="user")

    # ---------------------------
    # Password hashing
    # ---------------------------
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        hashed = bcrypt.generate_password_hash(password.encode("utf-8"))
        self._password_hash = hashed.decode("utf-8")

    def authenticate(self, password):
        if not self._password_hash:
            return False
        return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8"))

    # ---------------------------
    # Username validation
    # ---------------------------
    @validates("username")
    def validate_username(self, key, username):
        if not username or username.strip() == "":
            raise ValueError("Username is required")
        return username

    def __repr__(self):
        return f"<User {self.username}>"


# ---------------------------
# Recipe Model
# ---------------------------
class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )  # make nullable

    serialize_rules = ("-user.recipes",)

    @validates("instructions")
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

    def __repr__(self):
        return f"<Recipe {self.title}>"
