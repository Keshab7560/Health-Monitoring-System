from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure application from environment variables
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'your-secret-key-here-change-me'),
    SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'users.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_REFRESH_EACH_REQUEST=True
)

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    join_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.email}>'

# Password Reset Token model
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))

# Create tables and admin user within application context
with app.app_context():
    # Ensure the instance folder exists
    instance_path = os.path.join(app.root_path, 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    
    db.create_all()
    
    # Create admin user if not exists
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@health.ai')
    admin_password = os.getenv('ADMIN_PASSWORD', 'Admin@123')
    
    if not User.query.filter_by(email=admin_email).first():
        admin = User(
            name="Admin",
            email=admin_email,
            password=generate_password_hash(admin_password, method='pbkdf2:sha256'),
            is_admin=True,
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user '{admin_email}' created with default password.")
    else:
        print(f"Admin user '{admin_email}' already exists.")

# Email configuration from environment variables
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

def send_reset_email(user, reset_url):
    """Sends a password reset email to the user."""
    if not EMAIL_USER:
        print("Error: EMAIL_USER environment variable not set. Cannot send reset email.")
        return False
    if not EMAIL_PASSWORD:
        print("Error: EMAIL_PASSWORD environment variable not set. Cannot send reset email.")
        return False
        
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = user.email
    msg['Subject'] = 'Password Reset Request for Health.AI'
    
    body = f"""
    <h3>Password Reset Request</h3>
    <p>Hello {user.name},</p>
    <p>You requested to reset your password for Health.AI.</p>
    <p>Click the link below to reset your password:</p>
    <p><a href="{reset_url}">{reset_url}</a></p>
    <p>This link will expire in 1 hour.</p>
    <p>If you didn't request this, please ignore this email.</p>
    <p>Thanks,<br>Health.AI Team</p>
    """
    
    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls() # Enable TLS encryption
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Password reset email successfully sent to {user.email}")
        return True
    except smtplib.SMTPAuthenticationError:
        print(f"SMTP Authentication Error: Could not log in to email server with provided credentials for {EMAIL_USER}.")
        print("Please check EMAIL_USER and EMAIL_PASSWORD in your .env file.")
        print("If using Gmail with 2FA, ensure EMAIL_PASSWORD is an 'App password'.")
        return False
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.before_request
def make_session_permanent():
    """Makes the session permanent for the configured lifetime."""
    session.permanent = True

@app.route('/')
def index():
    """Renders the main landing page."""
    if 'user_id' in session and request.args.get('redirect') == 'dashboard':
        return redirect(url_for('dashboard'))
    
    login_error = request.args.get('login_error')
    return render_template('index.html', login_error=login_error)

@app.route('/dashboard')
def dashboard():
    """Renders the user dashboard, requires login."""
    if 'user_id' not in session:
        return redirect(url_for('login', next=url_for('dashboard')))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login', next=url_for('dashboard')))
    
    return render_template('dashboard.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    """Renders the admin dashboard, requires admin login."""
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('admin_login'))
    
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Handles admin login."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email, is_admin=True).first()
        
        if user and check_password_hash(user.password, password):
            session.clear() # Clear any existing session
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['is_admin'] = True
            session.modified = True
            return redirect(url_for('admin_dashboard'))
        
        return render_template('admin_login.html', error="Invalid admin credentials")
    
    return render_template('admin_login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        next_page = request.args.get('next') or url_for('index')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            if not user.is_active:
                return redirect(url_for('index', login_error="Your account has been banned"))
            
            session.clear()
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['is_admin'] = user.is_admin
            session.modified = True
            
            return redirect(next_page)
        
        return redirect(url_for('index', login_error="Invalid email or password"))
    
    return redirect(url_for('index'))

@app.route('/signup', methods=['POST'])
def signup():
    """Handles user registration."""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not name or not email or not password:
            return redirect(url_for('index', signup_error="All fields are required"))
        
        if User.query.filter_by(email=email).first():
            return redirect(url_for('index', signup_error="Email already registered"))
        
        if len(password) < 6:
            return redirect(url_for('index', signup_error="Password must be at least 6 characters"))
        
        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            is_admin=False,
            is_active=True
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        session.clear()
        session['user_id'] = new_user.id
        session['user_name'] = new_user.name
        session['is_admin'] = False
        session.modified = True
        
        return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Logs out the current user by clearing the session."""
    session.clear()
    return redirect(url_for('index'))

@app.route('/check_session')
def check_session():
    """Checks if a user is currently logged in and returns their details."""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return jsonify({
                'logged_in': True,
                'name': user.name,
                'is_admin': user.is_admin
            })
    return jsonify({'logged_in': False})

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handles the 'forgot password' request, sending a reset email."""
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            PasswordResetToken.query.filter_by(user_id=user.id).delete()
            
            token = secrets.token_urlsafe(32)
            expiration = datetime.utcnow() + timedelta(hours=1)
            
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expiration=expiration
            )
            
            db.session.add(reset_token)
            db.session.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            if send_reset_email(user, reset_url):
                return render_template('forgot_password.html', success=True)
            else:
                return render_template('forgot_password.html', error="Failed to send email. Please try again later.")
        
        return render_template('forgot_password.html', error="If an account with that email exists, a password reset link has been sent.")
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handles the password reset process using a token."""
    reset_token = PasswordResetToken.query.filter_by(token=token).first()
    
    if not reset_token or reset_token.expiration < datetime.utcnow():
        return render_template('reset_password.html', error="Invalid or expired password reset link.")
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        
        if not password or not confirm:
            return render_template('reset_password.html', token=token, error="Both password fields are required.")

        if password != confirm:
            return render_template('reset_password.html', token=token, error="Passwords don't match.")
        
        if len(password) < 6:
            return render_template('reset_password.html', token=token, error="Password must be at least 6 characters long.")
        
        user = User.query.get(reset_token.user_id)
        if not user:
            return render_template('reset_password.html', error="User associated with this token not found.")

        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        
        db.session.delete(reset_token)
        db.session.commit()
        
        return render_template('reset_password.html', success=True)
    
    return render_template('reset_password.html', token=token)

@app.route('/admin/toggle_user_status/<int:user_id>', methods=['POST'])
def toggle_user_status(user_id):
    """Toggles user active status (ban/unban)."""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.get_json()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    try:
        user.is_active = data.get('is_active', False)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    """Handles editing user details."""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    try:
        user.name = request.form.get('name', user.name)
        user.email = request.form.get('email', user.email)
        user.is_admin = bool(int(request.form.get('is_admin', user.is_admin)))
        user.is_active = bool(int(request.form.get('is_active', user.is_active)))
        
        new_password = request.form.get('password')
        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/create_user', methods=['POST'])
def create_user():
    """Handles creating new users from admin dashboard."""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = bool(int(request.form.get('is_admin', 0)))
        is_active = bool(int(request.form.get('is_active', 1)))
        
        if not name or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        new_user = User(
            name=name,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            is_admin=is_admin,
            is_active=is_active
        )
        
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """Handles deleting users."""
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat_api():
    """Enhanced Health.AI chatbot with disease, symptoms, and risk analysis information."""
    data = request.get_json()
    user_message = data.get('message', '').lower()
    
    # Disease database with symptoms and risk factors
    disease_db = {
        'diabetes': {
            'symptoms': ['frequent urination', 'excessive thirst', 'hunger', 'fatigue', 'blurred vision'],
            'risk_factors': ['family history', 'overweight', 'high blood pressure', 'physical inactivity'],
            'prevention': ['maintain healthy weight', 'regular exercise', 'balanced diet', 'regular checkups'],
            'description': "A chronic condition that affects how your body turns food into energy."
        },
        'hypertension': {
            'symptoms': ['headaches', 'shortness of breath', 'nosebleeds', 'dizziness'],
            'risk_factors': ['age', 'family history', 'obesity', 'high salt diet', 'stress'],
            'prevention': ['reduce salt intake', 'regular exercise', 'limit alcohol', 'manage stress'],
            'description': "High blood pressure that can lead to serious health complications."
        },
        'heart disease': {
            'symptoms': ['chest pain', 'shortness of breath', 'pain in arms/neck/jaw', 'fatigue'],
            'risk_factors': ['high blood pressure', 'high cholesterol', 'smoking', 'diabetes', 'obesity'],
            'prevention': ['healthy diet', 'regular exercise', 'no smoking', 'manage stress'],
            'description': "A range of conditions that affect your heart's structure and function."
        }
    }
    
    # Service information
    services_info = {
        'risk analysis': {
            'description': "Our AI analyzes your health data to identify potential risks.",
            'process': "Upload your health records or connect wearable devices for analysis.",
            'benefits': "Early detection of health issues, personalized recommendations",
            'how_to_use': "Login and upload your health data to get started."
        },
        'disease prediction': {
            'description': "Predicts potential health issues based on your metrics.",
            'process': "Our models analyze patterns in your health data over time.",
            'benefits': "Proactive healthcare, prevention-focused approach",
            'how_to_use': "Provide your health history and current metrics for analysis."
        },
        'patient segmentation': {
            'description': "Groups patients with similar characteristics.",
            'process': "Cluster analysis of demographic and health metrics.",
            'benefits': "Personalized treatment plans, efficient resource allocation",
            'how_to_use': "Available to healthcare providers for population health management."
        },
        'data visualization': {
            'description': "Interactive dashboards for health data insights.",
            'process': "Connect your health data sources to visualize trends.",
            'benefits': "Better understanding of health patterns, data-driven decisions",
            'how_to_use': "Access through our dashboard after login."
        }
    }

    # Generate response based on user input
    if any(word in user_message for word in ['hello', 'hi', 'hey']):
        response = "Hello! I'm your Health.AI assistant. I can help with:\n- Disease information\n- Symptoms analysis\n- Risk assessment\n- Our services\nHow can I help you today?"
    
    # Disease information
    elif 'disease' in user_message or any(d in user_message for d in disease_db.keys()):
        disease = next((d for d in disease_db.keys() if d in user_message), None)
        if disease:
            info = disease_db[disease]
            response = f"""**{disease.title()} Information**:
📝 Description: {info['description']}
🩺 Symptoms: {', '.join(info['symptoms'])}
⚠️ Risk Factors: {', '.join(info['risk_factors'])}
🛡️ Prevention: {', '.join(info['prevention'])}"""
        else:
            response = "I can provide information about:\n- " + "\n- ".join(disease_db.keys()) + "\nWhich disease would you like to know about?"
    
    # Symptoms analysis
    elif 'symptom' in user_message or any(s in user_message for d in disease_db.values() for s in d['symptoms']):
        symptom = next((s for d in disease_db.values() for s in d['symptoms'] if s in user_message), None)
        if symptom:
            related_diseases = [d for d, info in disease_db.items() if symptom in info['symptoms']]
            response = f"🔍 Symptom '{symptom}' may be associated with:\n- " + "\n- ".join(related_diseases) + "\n\nPlease consult a doctor for proper diagnosis."
        else:
            response = "Please describe your symptoms for analysis. I can help with symptoms related to:\n- " + "\n- ".join(disease_db.keys())
    
    # Risk analysis
    elif 'risk' in user_message or any(f in user_message for d in disease_db.values() for f in d['risk_factors']):
        factor = next((f for d in disease_db.values() for f in d['risk_factors'] if f in user_message), None)
        if factor:
            related_diseases = [d for d, info in disease_db.items() if factor in info['risk_factors']]
            prevention_tips = set()
            for d in related_diseases:
                prevention_tips.update(disease_db[d]['prevention'])
            
            response = f"""⚠️ Risk factor '{factor}' is associated with:
- """ + "\n- ".join(related_diseases) + f"""

💡 Prevention tips:
- """ + "\n- ".join(prevention_tips) + """
  
Our Risk Analysis service can provide personalized recommendations."""
        else:
            response = """Our Risk Analysis service evaluates:
- Family history
- Lifestyle factors
- Current health metrics

Common risk factors I can discuss:
- """ + "\n- ".join(set(f for d in disease_db.values() for f in d['risk_factors'])) + """

Would you like to know about a specific risk factor?"""
    
    # Service information
    elif any(word in user_message for word in ['service', 'feature', 'function']):
        service = next((s for s in services_info.keys() if s in user_message), None)
        if service:
            info = services_info[service]
            response = f"""**{service.title()} Service**:
📝 Description: {info['description']}
🔄 Process: {info['process']}
✅ Benefits: {info['benefits']}
🔧 How to Use: {info['how_to_use']}"""
        else:
            response = "Our services include:\n- " + "\n- ".join(services_info.keys()) + "\nWhich service would you like details about?"
    
    # Contact information
    elif any(word in user_message for word in ['contact', 'email', 'phone']):
        response = """📞 Contact Health.AI:
Phone: +91 8144138550
Email: keshabsasmal204@gmail.com
Location: Chandaka, Bhubaneswar, India"""
    
    # Help section
    elif any(word in user_message for word in ['help', 'support']):
        response = """🆘 I can help with:
1. Disease Information (symptoms, risk factors)
2. Health Risk Analysis
3. Service Details (Risk Analysis, Disease Prediction, etc.)
4. Contact Information

What would you like to know?"""
    
    # Default response
    else:
        response = "I'm trained to discuss health topics. You can ask about:\n- Specific diseases\n- Symptoms\n- Risk factors\n- Our services\n\nHow can I assist you?"

    return jsonify({'response': response})

if __name__ == '__main__':
    app.run(debug=True)
