import os
import uuid
import base64
from io import BytesIO
from datetime import datetime
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') # Must be set in production
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Add robust session cookie settings for production
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


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

# --- Initialize Database ---
with app.app_context():
    db.create_all()

# --- Helper Functions & Routes ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_qr_code(ticket_uid):
    import qrcode
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(ticket_uid)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    events = Event.query.order_by(Event.event_datetime.asc()).all()
    return render_template('index.html', events=events)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone_number')

        if not all([username, email, password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password, phone_number=phone)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Both username and password are required.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', tickets=current_user.tickets, events=current_user.events)

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        if 'artwork' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['artwork']
        if file.filename == '' or not allowed_file(file.filename):
            flash('No selected file or file type not allowed', 'danger')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        unique_filename = str(uuid.uuid4().hex[:16]) + '_' + filename
        
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        name = request.form.get('name')
        description = request.form.get('description')
        venue = request.form.get('venue')
        event_datetime_str = request.form.get('event_datetime')
        event_datetime = datetime.strptime(event_datetime_str, '%Y-%m-%dT%H:%M')
        price_ordinary = request.form.get('price_ordinary', type=float)
        price_vip = request.form.get('price_vip', type=float)
        price_vvip = request.form.get('price_vvip', type=float)

        new_event = Event(name=name, description=description, venue=venue, 
                          event_datetime=event_datetime, artwork=unique_filename,
                          creator=current_user, price_ordinary=price_ordinary,
                          price_vip=price_vip, price_vvip=price_vvip)
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('create_event.html')

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('event_detail.html', event=event)

@app.route('/purchase/<int:event_id>', methods=['POST'])
@login_required
def purchase_ticket(event_id):
    event = Event.query.get_or_404(event_id)
    ticket_type = request.form.get('ticket_type')
    
    if not ticket_type:
        flash('Please select a ticket type.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))

    new_ticket = Ticket(
        owner=current_user,
        event=event,
        ticket_type=ticket_type
    )
    db.session.add(new_ticket)
    db.session.commit()
    flash('Ticket purchased successfully!', 'success')
    return redirect(url_for('view_ticket', ticket_id=new_ticket.id))

@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user:
        return "Unauthorized", 403
    qr_code_img = generate_qr_code(ticket.ticket_uid)
    return render_template('ticket.html', ticket=ticket, qr_code_img=qr_code_img)


@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/verify_ticket', methods=['POST'])
@login_required
def verify_ticket():
    ticket_uid = request.form.get('ticket_uid')
    ticket = Ticket.query.filter_by(ticket_uid=ticket_uid).first()
    if not ticket:
        flash(f"INVALID TICKET: UID {ticket_uid} not found.", 'danger')
    elif ticket.is_scanned:
        flash(f"ALREADY SCANNED: Ticket for {ticket.owner.username} was already used.", 'warning')
    else:
        ticket.is_scanned = True
        db.session.commit()
        flash(f"SUCCESS: Welcome, {ticket.owner.username}! Ticket for '{ticket.event.name}' is valid.", 'success')
    return redirect(url_for('scan'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

