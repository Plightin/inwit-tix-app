import os
import uuid
import base64
import requests
import time
import json
from io import BytesIO
from datetime import datetime
from pathlib import Path
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from weasyprint import HTML
from flask_mail import Mail, Message
from werkzeug.middleware.proxy_fix import ProxyFix
import pytz

# --- App Configuration ---
load_dotenv()
app = Flask(__name__)

# Essential for handling HTTPS and custom domains (tix.inwitsystems.com) correctly on Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Database Setup
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', '/var/data/uploads')
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Domain & SSL Configuration
app.config['PREFERRED_URL_SCHEME'] = 'https'
if os.environ.get('SERVER_NAME'):
    app.config['SERVER_NAME'] = os.environ.get('SERVER_NAME')

# Airtel Credentials (Staging defaults)
AIRTEL_CLIENT_ID = os.environ.get('AIRTEL_CLIENT_ID', 'deb7ec0c-a35e-4089-85aa-2ffac3bdfbcb')
AIRTEL_CLIENT_SECRET = os.environ.get('AIRTEL_CLIENT_SECRET', '2a6f724c-c42e-4ef7-9b43-8a3c20868a26')
AIRTEL_BASE_URL = os.environ.get('AIRTEL_BASE_URL', 'https://openapiuat.airtel.co.zm')
AIRTEL_COUNTRY = "ZM"
AIRTEL_CURRENCY = "ZMW"

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'hello@tix.inwitsystems.com')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(15), nullable=True)
    role = db.Column(db.String(20), default='user') # user, organizer, admin
    approval_status = db.Column(db.String(20), default='approved')
    is_email_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    is_suspended = db.Column(db.Boolean, default=False, nullable=False)
    events = db.relationship('Event', backref='creator', lazy=True)
    tickets = db.relationship('Ticket', backref='owner', lazy=True)

    def __init__(self, username, email, password, phone_number=None, role='user', is_email_confirmed=False, is_suspended=False):
        self.username = username
        self.email = email
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.phone_number = phone_number
        self.role = role
        self.is_email_confirmed = is_email_confirmed
        self.is_suspended = is_suspended

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    venue = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(50), default='Other')
    event_datetime = db.Column(db.DateTime, nullable=False)
    artwork = db.Column(db.String(100), nullable=False, default='default.jpg')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    price_ordinary = db.Column(db.Float, default=0.0)
    price_vip = db.Column(db.Float, default=0.0)
    price_vvip = db.Column(db.Float, default=0.0)
    is_featured = db.Column(db.Boolean, default=False)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_uid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    is_scanned = db.Column(db.Boolean, default=False)
    ticket_type = db.Column(db.String(50), nullable=False)
    price_paid = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), default='pending') # pending, success, failed
    airtel_id = db.Column(db.String(100), nullable=True)
    partner_id = db.Column(db.String(100), unique=True, nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event = db.relationship('Event', backref='tickets')

# --- Template Filters ---

@app.template_filter('to_local_time')
def to_local_time_filter(dt, fmt='%d %b %Y, %I:%M %p'):
    """Converts UTC datetime to CAT (Central Africa Time) for display."""
    if not dt: return ""
    tz = pytz.timezone('Africa/Lusaka')
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(tz).strftime(fmt)

@app.context_processor
def inject_now():
    return {
        'current_year': datetime.now().year,
        'current_user': current_user
    }

# --- CLI Commands ---

@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
        admin_email = "admin@inwittix.com"
        admin_user = User.query.filter_by(email=admin_email).first()
        if not admin_user:
            new_admin = User(username="System Admin", email=admin_email, password="admin123", role="admin", is_email_confirmed=True, is_suspended=False)
            db.session.add(new_admin)
            db.session.commit()
            print(f"Created default admin user: {admin_email}")
        else:
            print("Admin user already exists.")
    print("Database initialized.")

# --- Helper Functions ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr_code(ticket_uid):
    import qrcode
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(ticket_uid)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")

def create_and_email_ticket(ticket):
    """Generates PDF and sends email to the ticket owner."""
    try:
        qr_code_img = generate_qr_code(ticket.ticket_uid)
        logo_url = url_for('static', filename='logo.png', _external=True)
        html_for_pdf = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_url)
        pdf_bytes = HTML(string=html_for_pdf, base_url=request.url_root).write_pdf()
        email_html = render_template('email_ticket.html', ticket=ticket, logo_url=logo_url)
        msg = Message(subject=f"Your Ticket for {ticket.event.name}", recipients=[ticket.owner.email])
        msg.html = email_html
        msg.attach(f"ticket-{ticket.id}.pdf", "application/pdf", pdf_bytes)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

# --- Airtel API Helpers ---

def get_airtel_token():
    url = f"{AIRTEL_BASE_URL}/auth/oauth2/token"
    payload = {
        "client_id": AIRTEL_CLIENT_ID,
        "client_secret": AIRTEL_CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    try:
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        # Return both token and full response for debugging
        if response.status_code == 200:
            return response.json().get('access_token'), response.json()
        return None, response.json()
    except Exception as e:
        print(f"Airtel Auth Error: {e}")
        return None, {"error": str(e)}

def initiate_ussd_push(msisdn, amount, partner_id):
    """Initiates a USSD push and returns raw response data for debugging/testing."""
    token, auth_res = get_airtel_token()
    
    # If no token, return the error details from auth
    if not token: 
        return {"error": "Auth Failed", "details": auth_res}, {"auth_status": "failed"}
    
    url = f"{AIRTEL_BASE_URL}/merchant/v1/payments/"
    headers = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "X-Country": AIRTEL_COUNTRY,
        "X-Currency": AIRTEL_CURRENCY,
        "Authorization": f"Bearer {token}"
    }
    
    clean_phone = msisdn.replace("+", "").replace(" ", "")
    if clean_phone.startswith('260'): clean_phone = clean_phone[3:]
    elif clean_phone.startswith('0'): clean_phone = clean_phone[1:]

    payload = {
        "reference": "Inwit Ticket Purchase",
        "subscriber": {
            "country": AIRTEL_COUNTRY,
            "currency": AIRTEL_CURRENCY,
            "msisdn": clean_phone
        },
        "transaction": {
            "amount": amount,
            "id": partner_id
        }
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        res_json = response.json()
        return res_json, payload
    except Exception as e:
        return {"error": str(e)}, payload

# --- Routes ---

@app.route('/')
def index():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    events_query = Event.query
    if query:
        events_query = events_query.filter(Event.name.ilike(f'%{query}%') | Event.venue.ilike(f'%{query}%'))
    if category:
        events_query = events_query.filter_by(category=category)
    events = events_query.order_by(Event.event_datetime.asc()).all()
    return render_template('index.html', events=events, query=query, category=category)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone_number')
        
        if User.query.filter_by(username=username).first():
            flash('Username taken.', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
        else:
            new_user = User(username, email, password, phone)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('profile'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('profile')
            return redirect(next_page)
        flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', tickets=current_user.tickets, events=current_user.events)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    events = Event.query.all()
    return render_template('admin.html', users=users, events=events)

@app.route('/airtel-tester', methods=['GET', 'POST'])
def airtel_tester():
    test_result = None
    raw_req = None
    if request.method == 'POST':
        msisdn = request.form.get('phone')
        amount = float(request.form.get('amount', 1))
        partner_id = f"TEST-{uuid.uuid4().hex[:8]}"
        test_result, raw_req = initiate_ussd_push(msisdn, amount, partner_id)
    return render_template('airtel_tester.html', result=test_result, request_body=raw_req)

# NEW: Public JSON API endpoint for Postman testing
@app.route('/api/test-payment', methods=['POST'])
def api_test_payment():
    """
    Public API endpoint to trigger USSD push.
    Input JSON: { "phone": "097...", "amount": 1.0 }
    """
    data = request.json
    msisdn = data.get('phone')
    amount = data.get('amount', 1.0)
    partner_id = f"TEST-{uuid.uuid4().hex[:8]}"
    
    result, payload = initiate_ussd_push(msisdn, amount, partner_id)
    
    return jsonify({
        "status": "initiated",
        "request_sent_to_airtel": payload,
        "response_from_airtel": result
    })

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('If an account exists for that email, a reset link has been sent.', 'info')
        else:
            flash('If an account exists for that email, a reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/resend-activation', methods=['GET', 'POST'])
def resend_activation():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Activation link has been resent to your email.', 'info')
        else:
            flash('Email not found.', 'danger')
        return redirect(url_for('login'))
    return render_template('resend_activation.html')

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        file = request.files['artwork']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_name = f"{uuid.uuid4().hex[:10]}_{filename}"
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
            new_event = Event(
                name=request.form.get('name'),
                description=request.form.get('description'),
                venue=request.form.get('venue'),
                category=request.form.get('category'),
                event_datetime=datetime.strptime(request.form.get('event_datetime'), '%Y-%m-%dT%H:%M'),
                artwork=unique_name,
                creator=current_user,
                price_ordinary=float(request.form.get('price_ordinary') or 0),
                price_vip=float(request.form.get('price_vip') or 0),
                price_vvip=float(request.form.get('price_vvip') or 0)
            )
            db.session.add(new_event)
            db.session.commit()
            flash('Event created!', 'success')
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
    phone = request.form.get('phone_number')
    price = 0
    if ticket_type == 'Ordinary': price = event.price_ordinary
    elif ticket_type == 'VIP': price = event.price_vip
    elif ticket_type == 'VVIP': price = event.price_vvip
    partner_id = str(uuid.uuid4())
    new_ticket = Ticket(
        owner=current_user, event=event, ticket_type=ticket_type,
        price_paid=price, partner_id=partner_id, payment_status='pending'
    )
    db.session.add(new_ticket)
    db.session.commit()
    airtel_id, msg = initiate_ussd_push(phone, price, partner_id)
    if isinstance(airtel_id, dict) and airtel_id.get('status', {}).get('success'):
        new_ticket.airtel_id = airtel_id.get('data', {}).get('transaction', {}).get('id')
        db.session.commit()
        flash(f'USSD Push sent! Enter PIN on your phone to pay K{price}.', 'info')
        return redirect(url_for('view_ticket', ticket_id=new_ticket.id))
    else:
        db.session.delete(new_ticket)
        db.session.commit()
        error_msg = msg
        if isinstance(airtel_id, dict):
             error_msg = airtel_id.get('status', {}).get('message', 'Airtel API Error')
        flash(f'Payment Failed: {error_msg}', 'danger')
        return redirect(url_for('event_detail', event_id=event.id))

@app.route('/airtel/callback', methods=['POST'])
def airtel_callback():
    data = request.json
    txn = data.get('transaction', {})
    partner_id = txn.get('id')
    status = txn.get('status')
    ticket = Ticket.query.filter_by(partner_id=partner_id).first()
    if ticket:
        if status == 'TS':
            ticket.payment_status = 'success'
            with app.app_context():
                create_and_email_ticket(ticket)
        else:
            ticket.payment_status = 'failed'
        db.session.commit()
    return jsonify({"status": "ok"}), 200

@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user: return "Unauthorized", 403
    qr_code_img = generate_qr_code(ticket.ticket_uid)
    return render_template('ticket.html', ticket=ticket, qr_code_img=qr_code_img)

@app.route('/ticket/download/<int:ticket_id>')
@login_required
def download_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user: return "Unauthorized", 403
    qr_code_img = generate_qr_code(ticket.ticket_uid)
    logo_url = url_for('static', filename='logo.png', _external=True)
    html_out = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_url)
    pdf = HTML(string=html_out, base_url=request.url_root).write_pdf()
    return send_file(BytesIO(pdf), mimetype='application/pdf', as_attachment=True, download_name=f'ticket-{ticket.id}.pdf')

@app.route('/ticket/email/<int:ticket_id>')
@login_required
def resend_email_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user: return "Unauthorized", 403
    if ticket.payment_status != 'success':
        flash('Ticket must be paid before emailing.', 'warning')
    else:
        if create_and_email_ticket(ticket):
            flash('Ticket emailed successfully!', 'success')
        else:
            flash('Error sending email.', 'danger')
    return redirect(url_for('view_ticket', ticket_id=ticket.id))

@app.route('/scan')
@login_required
def scanner():
    if current_user.role not in ['organizer', 'admin']: 
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('index'))
    return render_template('scan.html')

@app.route('/verify_ticket', methods=['POST'])
@login_required
def verify_ticket():
    ticket_uid = request.form.get('ticket_uid')
    ticket = Ticket.query.filter_by(ticket_uid=ticket_uid).first()
    if not ticket:
        flash("Invalid Ticket UID.", 'danger')
    elif ticket.is_scanned:
        flash(f"Already Scanned! Used by {ticket.owner.username}.", 'warning')
    elif ticket.payment_status != 'success':
        flash("Unpaid Ticket.", 'danger')
    else:
        ticket.is_scanned = True
        db.session.commit()
        flash(f"Valid! Welcome {ticket.owner.username}.", 'success')
    return redirect(url_for('scanner'))

@app.route('/help')
def help_page():
    return render_template('help.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
```

### How to use this new endpoint in Postman:

1.  **Method:** `POST`
2.  **URL:** `https://tix.inwitsystems.com/api/test-payment`
3.  **Body:** Select `raw` and `JSON`.
    ```json
    {
      "phone": "097...", 
      "amount": 1.0
    }
    ```
4.  **Send:** You will get a JSON response containing the exact `request` payload sent to Airtel and the `response` received from them.

This will allow you to generate all the evidence you need for your Excel sheet without logging into the app.
