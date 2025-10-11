import os
import uuid
import base64
from io import BytesIO
from datetime import datetime
from pathlib import Path
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from weasyprint import HTML, CSS
from flask_mail import Mail, Message

# --- App Configuration ---
load_dotenv()
app = Flask(__name__)

# Production configuration for Render
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'static/uploads')
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Session Cookie Settings
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email Configuration (use environment variables in production)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't']
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'hello@inwittix.com')

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

@app.cli.command("db-init")
def db_init():
    with app.app_context():
        db.create_all()
    print("Database initialized.")

# --- Helper Functions ---
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

def create_and_email_ticket(ticket):
    """Generates a PDF ticket and emails it to the ticket owner."""
    try:
        with app.app_context():
            qr_code_img = generate_qr_code(ticket.ticket_uid)
            basedir = os.path.abspath(os.path.dirname(__file__))
            logo_path_obj = Path(basedir) / 'static' / 'logo.png'
            logo_uri = logo_path_obj.as_uri()

            html_out = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_uri)
            pdf_bytes = HTML(string=html_out).write_pdf()

            msg = Message(
                subject=f"Your Ticket for {ticket.event.name}",
                recipients=[ticket.owner.email]
            )
            msg.body = f"Hello {ticket.owner.username},\n\nYour ticket for {ticket.event.name} is attached.\n\nThank you for using Inwit Tix!"
            msg.attach(
                f"inwit-tix-ticket-{ticket.id}.pdf",
                "application/pdf",
                pdf_bytes
            )
            mail.send(msg)
            flash('Your ticket has been sent to your email address.', 'success')
    except Exception as e:
        print(f"Error emailing ticket: {e}")
        flash('There was an issue emailing your ticket. Please try again from your profile.', 'danger')

# --- Web Routes ---
@app.route('/')
def index():
    try:
        events = Event.query.order_by(Event.event_datetime.asc()).all()
    except Exception:
        events = []
    return render_template('index.html', events=events)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # ... (code remains the same)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ... (code remains the same)
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
    # ... (code remains the same)
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

    new_ticket = Ticket(owner=current_user, event=event, ticket_type=ticket_type)
    db.session.add(new_ticket)
    db.session.commit()
    
    # Email the ticket right after purchase
    create_and_email_ticket(new_ticket)
    
    return redirect(url_for('view_ticket', ticket_id=new_ticket.id))

@app.route('/ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user:
        return "Unauthorized", 403
    qr_code_img = generate_qr_code(ticket.ticket_uid)
    return render_template('ticket.html', ticket=ticket, qr_code_img=qr_code_img)

@app.route('/ticket/download/<int:ticket_id>')
@login_required
def download_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user:
        return "Unauthorized", 403

    qr_code_img = generate_qr_code(ticket.ticket_uid)
    basedir = os.path.abspath(os.path.dirname(__file__))
    logo_path_obj = Path(basedir) / 'static' / 'logo.png'
    logo_uri = logo_path_obj.as_uri()

    html_out = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_uri)
    pdf = HTML(string=html_out).write_pdf()
    
    return send_file(
        BytesIO(pdf),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'inwit-tix-ticket-{ticket.id}.pdf'
    )

@app.route('/ticket/email/<int:ticket_id>')
@login_required
def resend_email_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.owner != current_user:
        return "Unauthorized", 403
    create_and_email_ticket(ticket)
    return redirect(url_for('view_ticket', ticket_id=ticket.id))

@app.route('/scan')
def scan():
    return render_template('scan.html')

@app.route('/verify_ticket', methods=['POST'])
@login_required
def verify_ticket():
    # ... (code remains the same)
    return redirect(url_for('scan'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
