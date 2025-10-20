import os
import uuid
import base64
from io import BytesIO
from datetime import datetime
from pathlib import Path
import re
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from weasyprint import HTML, CSS
from flask_mail import Mail, Message
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
import click
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- App Configuration ---
load_dotenv()
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
serializer = URLSafeTimedSerializer(app.config.get("SECRET_KEY", "default-secret-for-local-runs"))
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='buyer')
    approval_status = db.Column(db.String(20), nullable=False, default='approved')
    rejection_reason = db.Column(db.Text, nullable=True)
    is_email_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    company_profile_doc = db.Column(db.String(100), nullable=True)
    tax_clearance_doc = db.Column(db.String(100), nullable=True)
    banking_details_doc = db.Column(db.String(100), nullable=True)
    events = db.relationship('Event', backref='creator', lazy=True)
    tickets = db.relationship('Ticket', backref='owner', lazy=True)

    def __init__(self, username, email, password, role='buyer', phone_number=None):
        self.username = username
        self.email = email
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role
        self.phone_number = phone_number
        if self.role == 'organizer':
            self.approval_status = 'pending'

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    artwork = db.Column(db.String(100), nullable=False, default='default.jpg')
    venue = db.Column(db.String(150), nullable=False)
    event_datetime = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    price_ordinary = db.Column(db.Float, nullable=True)
    price_vip = db.Column(db.Float, nullable=True)
    price_vvip = db.Column(db.Float, nullable=True)
    tickets_ordinary = db.Column(db.Integer, nullable=True)
    tickets_vip = db.Column(db.Integer, nullable=True)
    tickets_vvip = db.Column(db.Integer, nullable=True)
    sales_start_date = db.Column(db.DateTime, nullable=True)
    sales_end_date = db.Column(db.DateTime, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    organizer_name = db.Column(db.String(100), nullable=True)
    contact_info = db.Column(db.String(100), nullable=True)
    external_link = db.Column(db.String(200), nullable=True)
    purchase_limit = db.Column(db.Integer, nullable=True)
    is_unlisted = db.Column(db.Boolean, default=False)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_uid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    is_scanned = db.Column(db.Boolean, default=False)
    ticket_type = db.Column(db.String(50), nullable=False)
    price_paid = db.Column(db.Float, nullable=False, default=0.0)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event = db.relationship('Event', backref='tickets')

# --- Admin & Authorization ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
    print("Database initialized.")

@app.cli.command("make-admin")
@click.argument("username")
def make_admin(username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.role = 'admin'
            user.approval_status = 'approved'
            user.is_email_confirmed = True
            db.session.commit()
            print(f"User '{username}' is now an admin.")
        else:
            print(f"User '{username}' not found.")

# --- Helper Functions ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

def is_password_strong(password):
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain a lowercase letter."
    if not re.search(r"[0-9]", password): return False, "Password must contain a number."
    return True, ""

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

def save_document(file_storage, user_id):
    if file_storage and file_storage.filename != '' and allowed_file(file_storage.filename):
        filename = secure_filename(file_storage.filename)
        unique_filename = f"user_{user_id}_{uuid.uuid4().hex[:8]}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file_storage.save(file_path)
        return unique_filename
    return None

def send_activation_email(user):
    try:
        token = serializer.dumps(user.email, salt='email-confirm')
        activation_link = url_for('activate_account', token=token, _external=True)
        logo_url = url_for('static', filename='logo.png', _external=True)
        email_html = render_template('activate_email.html', username=user.username, activation_link=activation_link, logo_url=logo_url)
        msg = Message(subject="Activate Your Inwit Tix Account", recipients=[user.email], html=email_html)
        mail.send(msg)
    except Exception as e:
        print(f"Error sending activation email: {e}")

def send_password_reset_email(user):
    try:
        token = serializer.dumps(user.email, salt='password-reset')
        reset_link = url_for('reset_password', token=token, _external=True)
        logo_url = url_for('static', filename='logo.png', _external=True)
        email_html = render_template('reset_email.html', username=user.username, reset_link=reset_link, logo_url=logo_url)
        msg = Message(subject="Reset Your Inwit Tix Password", recipients=[user.email], html=email_html)
        mail.send(msg)
    except Exception as e:
        print(f"Error sending password reset email: {e}")

def create_and_email_ticket(ticket):
    try:
        qr_code_img = generate_qr_code(ticket.ticket_uid)
        logo_url = url_for('static', filename='logo.png', _external=True)
        html_for_pdf = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_url)
        pdf_bytes = HTML(string=html_for_pdf, base_url=request.url_root).write_pdf()
        email_html = render_template('email_ticket.html', ticket=ticket, logo_url=logo_url)
        msg = Message(subject=f"Your Ticket for {ticket.event.name}", recipients=[ticket.owner.email])
        msg.html = email_html
        msg.attach(f"inwit-tix-ticket-{ticket.id}.pdf", "application/pdf", pdf_bytes)
        mail.send(msg)
        flash('Your ticket has been sent to your email address.', 'success')
    except Exception as e:
        print(f"Error emailing ticket: {e}")
        flash('There was an issue emailing your ticket. Please configure your email settings.', 'danger')

def send_organizer_status_email(user, status, reason=None):
    try:
        logo_url = url_for('static', filename='logo.png', _external=True)
        resubmit_link = url_for('resubmit_application', _external=True) if status == 'rejected' else None
        email_html = render_template('organizer_status_email.html', user=user, status=status, reason=reason, resubmit_link=resubmit_link, logo_url=logo_url)
        subject = f"Your Inwit Tix Organizer Application has been {status.capitalize()}"
        msg = Message(subject=subject, recipients=[user.email], html=email_html)
        mail.send(msg)
    except Exception as e:
        print(f"Error sending organizer status email: {e}")

# --- Web Routes ---
@app.route('/')
def index():
    try:
        now = datetime.utcnow()
        events = Event.query.filter(Event.is_unlisted == False, Event.event_datetime > now).order_by(Event.event_datetime.asc()).all()
    except Exception as e:
        print(f"Database error on index: {e}")
        events = []
    return render_template('index.html', events=events)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/register')
def register():
    return render_template('register_options.html')

@app.route('/register/buyer', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register_buyer():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        phone = request.form.get('phone_number')
        if not all([username, email, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register_buyer'))
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register_buyer'))
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message, 'danger')
            return redirect(url_for('register_buyer'))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register_buyer'))
        new_user = User(username=username, email=email, password=password, phone_number=phone, role='buyer')
        new_user.is_email_confirmed = False
        db.session.add(new_user)
        db.session.commit()
        send_activation_email(new_user)
        flash('A confirmation email has been sent. Please check your inbox to activate your account.', 'success')
        return redirect(url_for('login'))
    return render_template('register_buyer.html')

@app.route('/register/organizer', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register_organizer():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        phone = request.form.get('phone_number')
        if not all([username, email, password, confirm_password, phone]):
            flash('All text fields are required for organizer registration.', 'danger')
            return redirect(url_for('register_organizer'))
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register_organizer'))
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message, 'danger')
            return redirect(url_for('register_organizer'))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register_organizer'))
        profile_doc = request.files.get('company_profile_doc')
        tax_doc = request.files.get('tax_clearance_doc')
        banking_doc = request.files.get('banking_details_doc')
        if not profile_doc or profile_doc.filename == '' or \
           not tax_doc or tax_doc.filename == '' or \
           not banking_doc or banking_doc.filename == '':
            flash('All document uploads are required.', 'danger')
            return redirect(url_for('register_organizer'))
        new_user = User(username=username, email=email, password=password, phone_number=phone, role='organizer')
        db.session.add(new_user)
        db.session.commit()
        new_user.company_profile_doc = save_document(profile_doc, new_user.id)
        new_user.tax_clearance_doc = save_document(tax_doc, new_user.id)
        new_user.banking_details_doc = save_document(banking_doc, new_user.id)
        new_user.is_email_confirmed = False
        db.session.commit()
        send_activation_email(new_user)
        flash('Thank you for registering. Please check your email to activate your account. Your application will then be reviewed.', 'info')
        return redirect(url_for('login'))
    return render_template('register_organizer.html')

@app.route('/activate/<token>')
def activate_account(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_email_confirmed:
        flash('Account already confirmed. Please log in.', 'success')
    else:
        user.is_email_confirmed = True
        db.session.commit()
        flash('Your account has been activated! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    user = User.query.filter_by(email=email).first_or_404()
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Both username and password are required.', 'danger')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_email_confirmed:
                flash('Please activate your account first. Check your email for the confirmation link.', 'warning')
                return redirect(url_for('login'))
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

@app.route('/resubmit-application', methods=['GET', 'POST'])
@login_required
def resubmit_application():
    if not (current_user.role == 'organizer' and current_user.approval_status == 'rejected'):
        abort(403)
    
    if request.method == 'POST':
        current_user.phone_number = request.form.get('phone_number')
        
        if 'company_profile_doc' in request.files:
            new_profile = save_document(request.files['company_profile_doc'], current_user.id)
            if new_profile: current_user.company_profile_doc = new_profile
        
        if 'tax_clearance_doc' in request.files:
            new_tax = save_document(request.files['tax_clearance_doc'], current_user.id)
            if new_tax: current_user.tax_clearance_doc = new_tax
            
        if 'banking_details_doc' in request.files:
            new_banking = save_document(request.files['banking_details_doc'], current_user.id)
            if new_banking: current_user.banking_details_doc = new_banking
        
        current_user.approval_status = 'pending'
        current_user.rejection_reason = None
        db.session.commit()
        flash('Your application has been resubmitted for review.', 'success')
        return redirect(url_for('profile'))

    return render_template('resubmit_application.html')

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if not (current_user.role == 'organizer' and current_user.approval_status == 'approved'):
        flash('Your organizer account must be approved to create an event.', 'danger')
        return redirect(url_for('profile'))
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
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        name = request.form.get('name')
        description = request.form.get('description')
        venue = request.form.get('venue')
        event_datetime_str = request.form.get('event_datetime')
        event_datetime = datetime.strptime(event_datetime_str, '%Y-%m-%dT%H:%M')
        price_ordinary = request.form.get('price_ordinary', type=float) or None
        price_vip = request.form.get('price_vip', type=float) or None
        price_vvip = request.form.get('price_vvip', type=float) or None
        tickets_ordinary=request.form.get('tickets_ordinary', type=int) or None
        tickets_vip=request.form.get('tickets_vip', type=int) or None
        tickets_vvip=request.form.get('tickets_vvip', type=int) or None
        sales_start_date=datetime.strptime(request.form.get('sales_start_date'), '%Y-%m-%dT%H:%M') if request.form.get('sales_start_date') else None
        sales_end_date=datetime.strptime(request.form.get('sales_end_date'), '%Y-%m-%dT%H:%M') if request.form.get('sales_end_date') else None
        category=request.form.get('category')
        organizer_name=request.form.get('organizer_name')
        contact_info=request.form.get('contact_info')
        external_link=request.form.get('external_link')
        purchase_limit=request.form.get('purchase_limit', type=int) or None
        is_unlisted='is_unlisted' in request.form
        
        new_event = Event(
            name=name, description=description, venue=venue, event_datetime=event_datetime, artwork=unique_filename, creator=current_user,
            price_ordinary=price_ordinary, price_vip=price_vip, price_vvip=price_vvip,
            tickets_ordinary=tickets_ordinary, tickets_vip=tickets_vip, tickets_vvip=tickets_vvip,
            sales_start_date=sales_start_date, sales_end_date=sales_end_date, category=category,
            organizer_name=organizer_name, contact_info=contact_info, external_link=external_link,
            purchase_limit=purchase_limit, is_unlisted=is_unlisted
        )
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('create_event.html')

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('event_detail.html', event=event, datetime=datetime)

@app.route('/purchase/<int:event_id>', methods=['POST'])
@login_required
def purchase_ticket(event_id):
    event = Event.query.get_or_404(event_id)
    ticket_type = request.form.get('ticket_type')
    if not ticket_type:
        flash('Please select a ticket type.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))
    
    now = datetime.utcnow()
    if event.sales_start_date and now < event.sales_start_date:
        flash('Ticket sales have not started for this event yet.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))
    if event.sales_end_date and now > event.sales_end_date:
        flash('Ticket sales for this event have ended.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))

    ticket_count = Ticket.query.filter_by(event_id=event.id, ticket_type=ticket_type).count()
    max_tickets = 0
    if ticket_type == 'Ordinary': max_tickets = event.tickets_ordinary
    elif ticket_type == 'VIP': max_tickets = event.tickets_vip
    elif ticket_type == 'VVIP': max_tickets = event.tickets_vvip
    
    if max_tickets is not None and ticket_count >= max_tickets:
        flash(f'Sorry, {ticket_type} tickets are sold out.', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))
        
    price_paid = 0
    if ticket_type == 'Ordinary':
        price_paid = event.price_ordinary
    elif ticket_type == 'VIP':
        price_paid = event.price_vip
    elif ticket_type == 'VVIP':
        price_paid = event.price_vvip
    new_ticket = Ticket(owner=current_user, event=event, ticket_type=ticket_type, price_paid=price_paid)
    db.session.add(new_ticket)
    db.session.commit()
    create_and_email_ticket(new_ticket)
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
    logo_url = url_for('static', filename='logo.png', _external=True)
    html_out = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_url)
    pdf = HTML(string=html_out, base_url=request.url_root).write_pdf()
    return send_file(BytesIO(pdf), mimetype='application/pdf', as_attachment=True, download_name=f'inwit-tix-ticket-{ticket.id}.pdf')

@app.route('/ticket/email/<int:ticket_id>')
@login_required
def resend_email_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user:
        abort(403)
    create_and_email_ticket(ticket)
    return redirect(url_for('view_ticket', ticket_id=ticket.id))

@app.route('/scanner')
@login_required
def scanner():
    return render_template('scanner.html')

@app.route('/verify_ticket', methods=['POST'])
@login_required
def verify_ticket():
    data = request.get_json()
    if not data or 'ticket_uid' not in data:
        return jsonify({'status': 'danger', 'message': 'Invalid request.'}), 400
    ticket_uid = data['ticket_uid']
    ticket = Ticket.query.filter_by(ticket_uid=ticket_uid).first()
    if not ticket:
        return jsonify({'status': 'danger', 'message': f'INVALID: Ticket not found.'})
    if ticket.event.creator != current_user:
        return jsonify({'status': 'danger', 'message': 'UNAUTHORIZED: You did not create this event.'})
    if ticket.is_scanned:
        return jsonify({'status': 'warning', 'message': f'ALREADY SCANNED: Ticket for {ticket.owner.username} was used.'})
    else:
        ticket.is_scanned = True
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'SUCCESS: Welcome, {ticket.owner.username}! ({ticket.ticket_type})'})

@app.route('/dashboard/<int:event_id>')
@login_required
def event_dashboard(event_id):
    event = Event.query.get_or_404(event_id)
    if event.creator != current_user:
        abort(403)
    tickets = event.tickets
    total_tickets_sold = len(tickets)
    total_revenue = sum(ticket.price_paid for ticket in tickets)
    sales_by_type = {'Ordinary': {'count': 0, 'revenue': 0}, 'VIP': {'count': 0, 'revenue': 0}, 'VVIP': {'count': 0, 'revenue': 0}}
    for ticket in tickets:
        if ticket.ticket_type in sales_by_type:
            sales_by_type[ticket.ticket_type]['count'] += 1
            sales_by_type[ticket.ticket_type]['revenue'] += ticket.price_paid
    return render_template('dashboard.html', event=event, total_tickets_sold=total_tickets_sold, total_revenue=total_revenue, sales_by_type=sales_by_type, tickets=tickets)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/approvals')
@login_required
@admin_required
def admin_approvals():
    pending_organizers = User.query.filter_by(role='organizer', approval_status='pending').all()
    return render_template('admin_approvals.html', organizers=pending_organizers)

@app.route('/admin/review/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def review_organizer(user_id):
    organizer = User.query.get_or_404(user_id)
    action = request.form.get('action')
    
    if action == 'approve':
        organizer.approval_status = 'approved'
        organizer.rejection_reason = None
        db.session.commit()
        send_organizer_status_email(organizer, 'approved')
        flash(f"Organizer '{organizer.username}' has been approved.", 'success')
    elif action == 'deny':
        reason = request.form.get('reason')
        if not reason:
            flash('A reason is required to deny an application.', 'danger')
            return redirect(url_for('admin_approvals'))
        organizer.approval_status = 'rejected'
        organizer.rejection_reason = reason
        db.session.commit()
        send_organizer_status_email(organizer, 'rejected', reason=reason)
        flash(f"Organizer '{organizer.username}' has been denied.", 'warning')
        
    return redirect(url_for('admin_approvals'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
