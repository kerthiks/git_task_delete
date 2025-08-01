from flask import Flask, render_template, request, redirect, url_for, flash, session
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

users = {
    "admin": "password123",
    "user": "pass"
}

# Track login attempts
login_attempts = {}

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

if __name__ == '__main__':
    app.run(debug=True)
