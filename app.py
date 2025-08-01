from flask import Flask, render_template, request, redirect, url_for, flash, session
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Replace with your email password
mail = Mail(app)

# Serializer for generating and verifying tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# In-memory storage for users and tokens (replace with DB in production)
users = {
    "admin": "password123",
    "user": "pass"
}
login_attempts = {}
reset_tokens = {}

@app.route('/')
def index():
    return "Welcome to the app! Go to /login to log in."

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            if not username or not password:
                flash('Please provide both username and password', 'danger')
                return render_template('login.html')

            # Check if the user is locked out
            if login_attempts.get(username, 0) >= 3:
                flash('Account locked due to too many failed login attempts', 'danger')
                logger.warning(f'Account locked for username: {username}')
                return render_template('login.html')

            if username in users and users[username] == password:
                session['username'] = username
                flash('Logged in successfully!', 'success')
                login_attempts[username] = 0  # Reset attempts on successful login
                return redirect(url_for('dashboard'))
            else:
                login_attempts[username] = login_attempts.get(username, 0) + 1
                flash('Invalid username or password', 'danger')
                logger.warning(f'Failed login attempt for username: {username}')
    except Exception as e:
        logger.error(f'Login error: {str(e)}')
        flash('An error occurred during login', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('You need to log in first', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        email = request.form.get('email')
        if not email:
            flash('Please provide an email address', 'danger')
            return redirect(url_for('login'))

        # Check if the email exists in the users dictionary
        if email not in users:
            flash('Email not found', 'danger')
            return redirect(url_for('login'))

        # Generate a reset token
        token = serializer.dumps(email, salt='password-reset-salt')
        expiration_time = datetime.now() + timedelta(hours=1)
        reset_tokens[email] = {'token': token, 'expires_at': expiration_time}

        # Send the token via email
        reset_url = url_for('reset_password_form', token=token, _external=True)
        msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Click the link to reset your password: {reset_url}'
        mail.send(msg)

        flash('Password reset email sent. Please check your inbox.', 'success')
        logger.info(f'Password reset email sent to {email}')
    except Exception as e:
        logger.error(f'Error in reset-password: {str(e)}')
        flash('An error occurred while processing your request', 'danger')

    return redirect(url_for('login'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_form(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
        if request.method == 'POST':
            new_password = request.form.get('password')
            if not new_password:
                flash('Please provide a new password', 'danger')
                return render_template('reset_password.html', token=token)

            # Update the user's password
            users[email] = new_password
            flash('Password reset successfully. You can now log in.', 'success')
            return redirect(url_for('login'))

        return render_template('reset_password.html', token=token)
    except Exception as e:
        logger.error(f'Error in reset-password-form: {str(e)}')
        flash('The reset link is invalid or has expired', 'danger')
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
