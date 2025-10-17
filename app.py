import os
import uuid
import base64
from io import BytesIO
from datetime import datetime
from pathlib import Path
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
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Email Configuration (Set these in your Render Environment Variables)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

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
    price_paid = db.Column(db.Float, nullable=False, default=0.0)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event = db.relationship('Event', backref='tickets')

@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
    print("Database initialized.")

# --- Helper Functions ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

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

# --- Web Routes ---
@app.route('/')
def index():
    try:
        events = Event.query.order_by(Event.event_datetime.asc()).all()
    except Exception as e:
        print(f"Database error on index: {e}")
        events = []
    return render_template('index.html', events=events)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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

        user_by_username = User.query.filter_by(username=username).first()
        if user_by_username:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email:
            flash('Email address already registered.', 'danger')
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
        return redirect(url_for('profile'))
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
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        name = request.form.get('name')
        description = request.form.get('description')
        venue = request.form.get('venue')
        event_datetime_str = request.form.get('event_datetime')
        event_datetime = datetime.strptime(event_datetime_str, '%Y-%m-%dT%H:%M')
        price_ordinary = request.form.get('price_ordinary', type=float) or 0
        price_vip = request.form.get('price_vip', type=float) or 0
        price_vvip = request.form.get('price_vvip', type=float) or 0

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

    price_paid = 0
    if ticket_type == 'Ordinary':
        price_paid = event.price_ordinary
    elif ticket_type == 'VIP':
        price_paid = event.price_vip
    elif ticket_type == 'VVIP':
        price_paid = event.price_vvip

    new_ticket = Ticket(
        owner=current_user,
        event=event,
        ticket_type=ticket_type,
        price_paid=price_paid
    )
    db.session.add(new_ticket)
    db.session.commit()
    
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
    logo_url = url_for('static', filename='logo.png', _external=True)

    html_out = render_template('ticket_pdf.html', ticket=ticket, qr_code_img=qr_code_img, logo_path=logo_url)
    pdf = HTML(string=html_out, base_url=request.url_root).write_pdf()
    
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
    
    sales_by_type = {
        'Ordinary': {'count': 0, 'revenue': 0},
        'VIP': {'count': 0, 'revenue': 0},
        'VVIP': {'count': 0, 'revenue': 0}
    }

    for ticket in tickets:
        if ticket.ticket_type in sales_by_type:
            sales_by_type[ticket.ticket_type]['count'] += 1
            sales_by_type[ticket.ticket_type]['revenue'] += ticket.price_paid

    return render_template('dashboard.html', event=event, total_tickets_sold=total_tickets_sold,
                           total_revenue=total_revenue, sales_by_type=sales_by_type, tickets=tickets)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
