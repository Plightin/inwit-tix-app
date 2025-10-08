import os
import uuid
import base64
from io import BytesIO
from datetime import datetime
from pathlib import Path
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from weasyprint import HTML, CSS

# --- App Configuration ---
app = Flask(__name__)

# Production configuration for Render
# These will be set in the Render dashboard
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-default-secret-key-for-local-dev')
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuration for file uploads
# On Render, this path will point to a persistent disk
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads'))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB
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
        self.phone_number = phone_number
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    venue = db.Column(db.String(150), nullable=False)
    event_datetime = db.Column(db.DateTime, nullable=False)
    artwork = db.Column(db.String(100), nullable=False, default='default.jpg')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    price_ordinary = db.Column(db.Float, nullable=False, default=0)
    price_vip = db.Column(db.Float, nullable=True)
    price_vvip = db.Column(db.Float, nullable=True)
    tickets = db.relationship('Ticket', backref='event', lazy=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_uid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    is_scanned = db.Column(db.Boolean, default=False)
    ticket_type = db.Column(db.String(20), nullable=False, default='Ordinary')
    price_paid = db.Column(db.Float, nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Utility Functions ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

# --- Web Routes ---
@app.route('/')
def index():
    events = Event.query.order_by(Event.event_datetime.asc()).all()
    return render_template('index.html', events=events)

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('event_detail.html', event=event)

@app.route('/purchase/<int:event_id>', methods=['POST'])
@login_required
def purchase_ticket(event_id):
    event = Event.query.get_or_404(event_id)
    ticket_type = request.form.get('ticket_type')
    price_map = {
        'Ordinary': event.price_ordinary,
        'VIP': event.price_vip,
        'VVIP': event.price_vvip
    }
    price_paid = price_map.get(ticket_type)

    if price_paid is None:
        flash('Invalid ticket type selected.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))

    new_ticket = Ticket(
        owner=current_user,
        event=event,
        ticket_type=ticket_type,
        price_paid=price_paid
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
        abort(403)
    qr_code_img = generate_qr_code(ticket.ticket_uid)
    return render_template('ticket.html', ticket=ticket, qr_code_img=qr_code_img)

@app.route('/ticket/download/<int:ticket_id>')
@login_required
def download_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user:
        abort(403)
    qr_code_img = generate_qr_code(ticket.ticket_uid)
    logo_path_obj = Path(os.path.join(app.root_path, 'static', 'logo.png'))
    logo_uri = logo_path_obj.as_uri() if logo_path_obj.exists() else None
    
    html_out = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_uri)
    pdf = HTML(string=html_out, base_url=app.root_path).write_pdf()
    
    return send_file(
        BytesIO(pdf),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'inwit_tix_{ticket.id}.pdf'
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form.get('phone_number')
        
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash('Email address already exists.', 'warning')
            return redirect(url_for('register'))
            
        new_user = User(username=username, email=email, password=password, phone_number=phone)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    user_tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.id.desc()).all()
    user_events = Event.query.filter_by(user_id=current_user.id).order_by(Event.event_datetime.desc()).all()
    return render_template('profile.html', tickets=user_tickets, events=user_events)

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        if 'artwork' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['artwork']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            try:
                img = Image.open(file)
                if img.width > 2000 or img.height > 2000:
                    flash('Image dimensions cannot exceed 2000x2000 pixels.', 'danger')
                    return redirect(request.url)

                file.seek(0)
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4())[:8] + '_' + filename
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                
                file.save(save_path)
            except Exception as e:
                flash(f'Error processing image: {e}', 'danger')
                return redirect(request.url)

            new_event = Event(
                name=request.form['name'],
                description=request.form['description'],
                venue=request.form['venue'],
                event_datetime=datetime.fromisoformat(request.form['event_datetime']),
                artwork=unique_filename,
                creator=current_user,
                price_ordinary=float(request.form.get('price_ordinary', 0)),
                price_vip=float(request.form.get('price_vip')) if request.form.get('price_vip') else None,
                price_vvip=float(request.form.get('price_vvip')) if request.form.get('price_vvip') else None,
            )
            db.session.add(new_event)
            db.session.commit()
            flash('Event has been created!', 'success')
            return redirect(url_for('index'))
    return render_template('create_event.html')

@app.route('/scan')
@login_required
def scan():
    return render_template('scan.html')

@app.route('/verify_ticket', methods=['POST'])
@login_required
def verify_ticket():
    ticket_uid = request.form['ticket_uid']
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

# Error handler for file size
@app.errorhandler(413)
def request_entity_too_large(error):
    return 'File Too Large. Please upload an image smaller than 5 MB.', 413

