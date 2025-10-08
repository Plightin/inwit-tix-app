import os
import uuid
import base64
from io import BytesIO
from datetime import datetime
from pathlib import Path
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from weasyprint import HTML, CSS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# --- App Configuration ---
load_dotenv()
app = Flask(__name__)

# Production configuration for Render
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-default-secret-key-for-local-dev')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'static/uploads') # For Render's persistent disk
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4 MB max upload size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    events = db.relationship('Event', backref='creator', lazy=True)
    tickets = db.relationship('Ticket', backref='owner', lazy=True)

    def __init__(self, username, email, password, phone_number=None):
        self.username = username
        self.email = email
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.phone_number = phone_number

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    venue = db.Column(db.String(150), nullable=False)
    event_datetime = db.Column(db.DateTime, nullable=False)
    artwork = db.Column(db.String(100), nullable=False, default='default.jpg')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    price_ordinary = db.Column(db.Float, nullable=True)
    price_vip = db.Column(db.Float, nullable=True)
    price_vvip = db.Column(db.Float, nullable=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_uid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    is_scanned = db.Column(db.Boolean, default=False)
    ticket_type = db.Column(db.String(50), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event = db.relationship('Event', backref='tickets')

# NEW: Add a command to initialize the database
@app.cli.command("db-init")
def db_init():
    """Initializes the database and creates all tables."""
    with app.app_context():
        db.create_all()
    print("Database initialized and tables created.")

# --- Helper Functions ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# ... (rest of the file is unchanged) ...

