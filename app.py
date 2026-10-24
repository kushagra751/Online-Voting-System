import hmac
import os
import secrets
from collections import Counter
from datetime import datetime
from functools import wraps

import bcrypt
from bson import ObjectId
from bson.errors import InvalidId
from flask import (Flask, abort, redirect, render_template, request, session,
                   url_for)
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

app = Flask(__name__)

_secret = os.environ.get('FLASK_SECRET_KEY')
if not _secret:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set. "
                       "Set it to a long random string (see .env.example).")
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', '0') == '1',
    MAX_CONTENT_LENGTH=64 * 1024,
)

# MongoDB connection (credentials come from the environment, never from source)
MONGO_URI = os.environ.get('MONGO_URI')
if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is not set. "
                       "Copy .env.example to .env and fill in your MongoDB connection string.")
client = MongoClient(MONGO_URI)

db = client['polls_database']
users_collection = db['users']
polls_collection = db['polls']
votes_collection = db['votes']
polls_history_collection = db['polls_history']
reports_collection = db['reports']

# One vote per user per poll, enforced by the database.
try:
    votes_collection.create_index([('poll_id', 1), ('username', 1)], unique=True)
except Exception as exc:  # e.g. existing duplicate votes or DB unreachable at import time
    app.logger.warning("Could not create unique vote index: %s", type(exc).__name__)

MIN_PASSWORD_LENGTH = 8
MAX_OPTIONS = 10


# ---------------------------------------------------------------- helpers
def get_csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(16)
    return session['_csrf']


app.jinja_env.globals['csrf_token'] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        sent = request.form.get('csrf_token', '')
        expected = session.get('_csrf', '')
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, description='Invalid or missing CSRF token. Please reload the page and try again.')


@app.after_request
def security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    return resp


@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', message=getattr(e, 'description', 'Bad request'), code=400), 400


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', message='The page or poll you asked for was not found.', code=404), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', message='Something went wrong on our side. Please try again.', code=500), 500


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def to_object_id(value):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        abort(404)


def parse_dt(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


@app.route('/')
def root():
    """Redirect to the login page."""
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user signup."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or len(username) > 50:
            return render_template('signup.html', error='Username is required (max 50 characters).'), 400
        if len(password) < MIN_PASSWORD_LENGTH:
            return render_template('signup.html', error=f'Password must be at least {MIN_PASSWORD_LENGTH} characters.'), 400
        if users_collection.find_one({'username': username}):
            return render_template('signup.html', error='Username already exists.'), 409
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({'username': username, 'password': hashed_password, 'joined_date': datetime.now()})
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = users_collection.find_one({'username': username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session.clear()  # drop any pre-login session state (session fixation)
            session['username'] = username
            return redirect(url_for('second_page'))
        return render_template('login.html', error='Invalid username or password.'), 401
    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset is disabled: it previously reset any account to a known
    password without any verification, which allowed account takeover.
    A proper flow needs an emailed single-use token."""
    if request.method == 'POST':
        return render_template(
            'forgot_password.html',
            message='Self-service password reset is not available. Please contact the site administrator.')
    return render_template('forgot_password.html')


@app.route('/second_page')
@login_required
def second_page():
    """Render the second page with public polls."""
    current_time = datetime.now()
    public_polls = list(polls_collection.find({
        'is_public': True,
        'start_time': {'$lte': current_time},
        'end_time': {'$gte': current_time}
    }))
    for poll in public_polls:
        poll['time_left'] = poll['end_time'] - current_time
    return render_template('second_page.html', public_polls=public_polls)


@app.route('/public_polls')
def public_polls():
    """Redirect to the second page which displays public polls."""
    return redirect(url_for('second_page'))


@app.route('/third_page', methods=['GET', 'POST'])
@login_required
def third_page():
    """Render the poll creation page and handle poll creation."""
    if request.method == 'POST':
        question = request.form.get('question', '').strip()
        options = []
        for i in range(1, MAX_OPTIONS + 1):
            value = request.form.get(f'option{i}', '').strip()
            if value and value not in options:
                options.append(value)
        start_time = parse_dt(request.form.get('start_time'))
        end_time = parse_dt(request.form.get('end_time'))

        error = None
        if not question or len(question) > 300:
            error = 'A question is required (max 300 characters).'
        elif len(options) < 2:
            error = 'Please provide at least two different options.'
        elif any(len(o) > 200 for o in options):
            error = 'Options must be 200 characters or fewer.'
        elif not start_time or not end_time:
            error = 'Please provide valid start and end times.'
        elif end_time <= start_time:
            error = 'End time must be after the start time.'
        if error:
            return render_template('third_page.html', error=error), 400

        poll_data = {
            'question': question,
            'options': options,
            'creator': session['username'],
            'is_public': request.form.get('is_public') == 'public',
            'start_time': start_time,
            'end_time': end_time,
            'creation_date': datetime.now()
        }
        poll_id = polls_collection.insert_one(poll_data).inserted_id
        return redirect(url_for('fourth_page', poll_id=poll_id))

    return render_template('third_page.html')


@app.route('/vote', methods=['POST'])
@login_required
def vote():
    """Handle voting (one vote per user per poll)."""
    poll_id = request.form.get('poll_id', '')
    poll_data = polls_collection.find_one({'_id': to_object_id(poll_id)})
    if not poll_data:
        abort(404)
    now = datetime.now()
    if poll_data['end_time'] < now:
        return render_template('error.html', message='This poll has expired. Voting is not allowed.', code=403), 403
    if poll_data['start_time'] > now:
        return render_template('error.html', message='This poll has not started yet.', code=403), 403

    selected_option = request.form.get('vote_option')
    if selected_option not in poll_data['options']:
        return render_template('error.html', message='Please select a valid option.', code=400), 400

    try:
        votes_collection.insert_one({'poll_id': poll_id, 'selected_option': selected_option,
                                     'username': session['username'], 'timestamp': now})
    except DuplicateKeyError:
        return render_template('error.html', message='You have already voted in this poll.', code=409), 409
    return redirect(url_for('result', poll_id=poll_id))


@app.route('/fourth_page')
@login_required
def fourth_page():
    """Render the poll details / voting page."""
    poll_data = polls_collection.find_one({'_id': to_object_id(request.args.get('poll_id'))})
    if not poll_data:
        abort(404)
    already_voted = votes_collection.find_one(
        {'poll_id': str(poll_data['_id']), 'username': session['username']}) is not None
    return render_template('fourth_page.html', poll_data=poll_data, already_voted=already_voted)


@app.route('/result')
@login_required
def result():
    """Render the poll result page."""
    poll_id = request.args.get('poll_id')
    poll_data = polls_collection.find_one({'_id': to_object_id(poll_id)})
    if not poll_data:
        abort(404)
    votes = Counter(v['selected_option'] for v in votes_collection.find({'poll_id': str(poll_data['_id'])}))
    total_votes = sum(votes.values())
    return render_template('result.html', poll_data=poll_data, votes=votes, total_votes=total_votes)


@app.route('/join_poll', methods=['POST'])
@login_required
def join_poll():
    """Handle joining a poll by ID."""
    poll_id = request.form.get('poll_id', '').strip()
    if not polls_collection.find_one({'_id': to_object_id(poll_id)}):
        abort(404)
    return redirect(url_for('fourth_page', poll_id=poll_id))


@app.route('/sixth_page')
@login_required
def sixth_page():
    """Render the join-poll page."""
    return render_template('sixth_page.html')


@app.route('/profile')
@login_required
def profile_page():
    """Render the profile page."""
    user = users_collection.find_one({'username': session['username']})
    if user:
        return render_template('profile.html', user=user)
    session.clear()
    return redirect(url_for('login'))


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Handle editing user profile."""
    username = session['username']
    user = users_collection.find_one({'username': username})
    if not user:
        session.clear()
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_email = request.form.get('email', '').strip()
        error = None
        if not new_username or len(new_username) > 50:
            error = 'Username is required (max 50 characters).'
        elif len(new_email) > 254:
            error = 'Email is too long.'
        elif new_username != username and users_collection.find_one({'username': new_username}):
            error = 'That username is already taken.'
        if error:
            return render_template('edit_profile.html', user=user, error=error), 400
        users_collection.update_one({'username': username}, {'$set': {'username': new_username, 'email': new_email}})
        if new_username != username:
            # keep ownership/vote history attached to the renamed user
            polls_collection.update_many({'creator': username}, {'$set': {'creator': new_username}})
            polls_history_collection.update_many({'creator': username}, {'$set': {'creator': new_username}})
            votes_collection.update_many({'username': username}, {'$set': {'username': new_username}})
            reports_collection.update_many({'username': username}, {'$set': {'username': new_username}})
        session['username'] = new_username
        return redirect(url_for('profile_page'))
    return render_template('edit_profile.html', user=user)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Handle changing user password."""
    username = session['username']
    user = users_collection.find_one({'username': username})
    if not user:
        session.clear()
        return redirect(url_for('login'))
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            error = 'Current password is incorrect'
        elif new_password != confirm_password:
            error = 'New passwords do not match'
        elif len(new_password) < MIN_PASSWORD_LENGTH:
            error = f'New password must be at least {MIN_PASSWORD_LENGTH} characters'
        else:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            users_collection.update_one({'username': username}, {'$set': {'password': hashed_password}})
            return redirect(url_for('profile_page'))
        return render_template('change_password.html', user=user, error=error), 400
    return render_template('change_password.html', user=user)


@app.route('/logout')
def logout():
    """Handle user logout."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/joined_history')
@login_required
def joined_history():
    """Render the history of joined polls page."""
    joined_polls_ids = []
    for v in votes_collection.find({'username': session['username']}):
        try:
            joined_polls_ids.append(ObjectId(v['poll_id']))
        except InvalidId:
            continue
    joined_polls = polls_collection.find({'_id': {'$in': joined_polls_ids}})
    joined_polls_history = polls_history_collection.find({'_id': {'$in': joined_polls_ids}})
    return render_template('joined_history.html', polls=joined_polls, polls_history=joined_polls_history)


@app.route('/created_history')
@login_required
def created_history():
    """Render the history of created polls page."""
    username = session['username']
    return render_template('created_history.html',
                           polls=polls_collection.find({'creator': username}),
                           polls_history=polls_history_collection.find({'creator': username}))


@app.route('/report')
@login_required
def report():
    """Render the report form page."""
    return render_template('report.html')


@app.route('/submit_report', methods=['POST'])
@login_required
def submit_report():
    """Handle the report form submission."""
    message = request.form.get('message', '').strip()
    if not message or len(message) > 2000:
        return render_template('error.html', message='Please enter a message (max 2000 characters).', code=400), 400
    reports_collection.insert_one({'username': session['username'], 'message': message, 'timestamp': datetime.now()})
    return render_template('error.html', message='Thank you for your report. We will review it soon.', code=200, title='Report sent')


@app.route('/guide_and_help')
def guide_and_help():
    """Render the guide and help page."""
    return render_template('guide_and_help.html')


@app.route('/manage_polls')
@login_required
def manage_polls():
    """Render the manage polls page."""
    user_polls = polls_collection.find({'creator': session['username']}).sort('creation_date', -1)
    return render_template('manage_polls.html', user_polls=user_polls)


@app.route('/delete_poll', methods=['POST'])
@login_required
def delete_poll():
    """Handle poll deletion (creator only)."""
    poll_id = request.form.get('poll_id', '')
    oid = to_object_id(poll_id)
    poll = polls_collection.find_one({'_id': oid, 'creator': session['username']})
    if not poll:
        abort(404)
    polls_collection.delete_one({'_id': oid})
    votes_collection.delete_many({'poll_id': poll_id})
    return redirect(url_for('manage_polls'))


@app.route('/edit_poll/<poll_id>', methods=['GET', 'POST'])
@login_required
def edit_poll(poll_id):
    """Render the edit poll page and handle updating poll schedule (creator only)."""
    oid = to_object_id(poll_id)
    poll = polls_collection.find_one({'_id': oid, 'creator': session['username']})
    if not poll:
        abort(404)
    if request.method == 'POST':
        start_time = parse_dt(request.form.get('start_time'))
        end_time = parse_dt(request.form.get('end_time'))
        if not start_time or not end_time or end_time <= start_time:
            return render_template('edit_poll.html', poll=poll, error='End time must be after the start time.'), 400
        polls_collection.update_one({'_id': oid}, {'$set': {'start_time': start_time, 'end_time': end_time}})
        return redirect(url_for('manage_polls'))
    return render_template('edit_poll.html', poll=poll)


def archive_expired_polls():
    """Move expired polls to the history collection."""
    current_time = datetime.now()
    for poll in list(polls_collection.find({'end_time': {'$lt': current_time}})):
        polls_history_collection.insert_one(poll)
        polls_collection.delete_one({'_id': poll['_id']})


if __name__ == '__main__':
    # Never run with debug=True in production; opt in locally with FLASK_DEBUG=1.
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG') == '1')
