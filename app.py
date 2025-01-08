from flask import Flask, render_template, request, redirect, url_for, session
from pymongo import MongoClient
import bcrypt
from collections import Counter
from bson import ObjectId
from datetime import datetime
import os
from collections.abc import MutableMapping  # Correct import for Python 3.10+

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key')  # Set a secret key for session management



client = MongoClient("mongodb+srv://admin:admin123@cluster0.jtetl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

# MongoDB connection
# MONGO_URI = os.getenv('MONGODB_URI')  # Use environment variable
# if not MONGO_URI:
#     raise EnvironmentError("MONGODB_URI environment variable is not set")

# client = MongoClient(MONGO_URI)

db = client['polls_database']  # Access 'polls_database' database
users_collection = db['users']  # Access 'users' collection for storing user data
polls_collection = db['polls']  # Access 'polls' collection for storing poll data
votes_collection = db['votes']  # Access 'votes' collection for storing vote data
polls_history_collection = db['polls_history']  # Access 'polls_history' collection for storing expired poll data
reports_collection = db['reports']  # Access 'reports' collection for storing report data


@app.route('/')
def root():
    """Redirect to the login page."""
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user signup."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        if not users_collection.find_one({'username': username}):
            # Insert user data into MongoDB
            users_collection.insert_one({'username': username, 'password': hashed_password, 'joined_date': datetime.now()})
            return redirect(url_for('login'))  # Redirect to login page after successful signup
        else:
            return 'Username already exists'  # Inform user if username already exists
    return render_template('signup.html')  # Render the signup form template for GET requests

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_collection.find_one({'username': username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username  # Store username in session
            return redirect(url_for('second_page'))  # Redirect to second page after successful login
        else:
            return 'Invalid username or password'  # Inform user if login credentials are invalid
    return render_template('login.html')  # Render the login form template for GET requests

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgot password."""
    if request.method == 'POST':
        username = request.form['username']
        user = users_collection.find_one({'username': username})
        if user:
            # Here, you could implement an email reset link or a simple reset mechanism
            # For simplicity, let's reset the password to 'newpassword123'
            new_password = 'newpassword123'
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            users_collection.update_one({'username': username}, {'$set': {'password': hashed_password}})
            return 'Password reset successful. Your new password is "newpassword123". Please change it after logging in.'
        else:
            return 'Username not found'  # Inform user if username does not exist
    return render_template('forgot_password.html')  # Render the forgot password form template for GET requests

@app.route('/second_page')
def second_page():
    """Render the second page with public polls."""
    current_time = datetime.now()
    public_polls = list(polls_collection.find({'is_public': True, 'start_time': {'$lte': current_time}, 'end_time': {'$gte': current_time}}))  # Fetch only active public polls
    for poll in public_polls:
        poll['time_left'] = poll['end_time'] - current_time
    return render_template('second_page.html', public_polls=public_polls)

@app.route('/public_polls')
def public_polls():
    """Redirect to the second page which displays public polls."""
    return redirect(url_for('second_page'))

@app.route('/third_page', methods=['GET', 'POST'])
def third_page():
    """Render the third page and handle poll creation."""
    if request.method == 'POST':
        question = request.form['question']
        options = [request.form[f'option{i}'] for i in range(1, 6) if request.form.get(f'option{i}')]
        is_public = request.form['is_public'] == 'public'
        start_time = datetime.fromisoformat(request.form['start_time'])
        end_time = datetime.fromisoformat(request.form['end_time'])

        poll_data = {
            'question': question,
            'options': options,
            'creator': session['username'],
            'is_public': is_public,
            'start_time': start_time,
            'end_time': end_time,
            'creation_date': datetime.now()  # Add creation date
        }
        poll_id = polls_collection.insert_one(poll_data).inserted_id
        return redirect(url_for('fourth_page', poll_id=poll_id))  # Redirect to voting page

    return render_template('third_page.html')


    return render_template('third_page.html')

@app.route('/vote', methods=['POST'])
def vote():
    """Handle voting."""
    if request.method == 'POST':
        poll_id = request.form['poll_id']
        poll_data = polls_collection.find_one({'_id': ObjectId(poll_id)})
        current_time = datetime.now()
        
        if poll_data['end_time'] < current_time:
            return 'This poll has expired. Voting is not allowed.'

        selected_option = request.form['vote_option']
        # Insert vote into MongoDB
        votes_collection.insert_one({'poll_id': poll_id, 'selected_option': selected_option, 'username': session['username']})
        return redirect(url_for('result', poll_id=poll_id))  # Redirect to result page after voting

@app.route('/fourth_page')
def fourth_page():
    """Render the fourth page (poll details page)."""
    poll_id = request.args.get('poll_id')
    poll_data = polls_collection.find_one({'_id': ObjectId(poll_id)})  # Retrieve poll data from MongoDB
    return render_template('fourth_page.html', poll_data=poll_data)

@app.route('/result')
def result():
    """Render the poll result page."""
    poll_id = request.args.get('poll_id')
    poll_data = polls_collection.find_one({'_id': ObjectId(poll_id)})  # Retrieve poll data from MongoDB
    if poll_data:
        options = poll_data['options']
        votes_data = votes_collection.find({'poll_id': poll_id})
        votes = Counter(vote['selected_option'] for vote in votes_data)
        total_votes = sum(votes.values())
        return render_template('result.html', poll_data=poll_data, votes=votes, total_votes=total_votes)
    else:
        return 'No poll data available'  # Inform if no poll data found

@app.route('/join_poll', methods=['POST'])
def join_poll():
    """Handle joining a poll."""
    poll_id = request.form.get('poll_id')
    return redirect(url_for('fourth_page', poll_id=poll_id))  # Redirect to fourth_page with poll ID

@app.route('/sixth_page')
def sixth_page():
    """Render the sixth page."""
    return render_template('sixth_page.html')

@app.route('/profile')
def profile_page():
    """Render the profile page."""
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if user:
            return render_template('profile.html', user=user)
    return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    """Handle editing user profile."""
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if request.method == 'POST':
            new_username = request.form['username']
            new_email = request.form['email']
            # Update user data in MongoDB
            users_collection.update_one({'username': username}, {'$set': {'username': new_username, 'email': new_email}})
            # Update session username after edit
            session['username'] = new_username
            return redirect(url_for('profile_page'))  # Redirect to profile page after editing
        return render_template('edit_profile.html', user=user)
    return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """Handle changing user password."""
    if 'username' in session:
        username = session['username']
        user = users_collection.find_one({'username': username})
        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            if bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
                if new_password == confirm_password:
                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    # Update user's password in MongoDB
                    users_collection.update_one({'username': username}, {'$set': {'password': hashed_password}})
                    return redirect(url_for('profile_page'))  # Redirect to profile page after password change
                else:
                    error = 'New passwords do not match'
            else:
                error = 'Current password is incorrect'
            return render_template('change_password.html', user=user, error=error)
        return render_template('change_password.html', user=user)
    return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.pop('username', None)
    return redirect(url_for('login'))  # Redirect to login page after logout

@app.route('/joined_history')
def joined_history():
    """Render the history of joined polls page."""
    if 'username' in session:
        username = session['username']
        # Retrieve the joined poll history for the user from the database
        joined_votes = votes_collection.find({'username': username})
        joined_polls_ids = [vote['poll_id'] for vote in joined_votes]
        joined_polls = polls_collection.find({'_id': {'$in': [ObjectId(poll_id) for poll_id in joined_polls_ids]}})
        joined_polls_history = polls_history_collection.find({'_id': {'$in': [ObjectId(poll_id) for poll_id in joined_polls_ids]}})
        return render_template('joined_history.html', polls=joined_polls, polls_history=joined_polls_history)
    
    return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/created_history')
def created_history():
    """Render the history of created polls page."""
    if 'username' in session:
        username = session['username']
        # Retrieve the created poll history for the user from the database
        created_polls = polls_collection.find({'creator': username})
        created_polls_history = polls_history_collection.find({'creator': username})
        return render_template('created_history.html', polls=created_polls, polls_history=created_polls_history)
    
    return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/report')
def report():
    """Render the report form page."""
    return render_template('report.html')

@app.route('/submit_report', methods=['POST'])
def submit_report():
    """Handle the report form submission."""
    if 'username' in session:
        username = session['username']
        message = request.form['message']
        reports_collection.insert_one({'username': username, 'message': message, 'timestamp': datetime.now()})
        return 'Thank you for your report. We will review it soon.'
    return redirect(url_for('login'))  # Redirect to login if not logged in

@app.route('/guide_and_help')
def guide_and_help():
    """Render the guide and help page."""
    return render_template('guide_and_help.html')

@app.route('/manage_polls')
def manage_polls():
    """Render the manage polls page."""
    if 'username' in session:
        username = session['username']
        # Retrieve user's polls sorted by creation date in descending order
        user_polls = polls_collection.find({'creator': username}).sort('creation_date', -1)
        return render_template('manage_polls.html', user_polls=user_polls)
    return redirect(url_for('login'))  # Redirect to login if not logged in


@app.route('/delete_poll', methods=['POST'])
def delete_poll():
    """Handle poll deletion."""
    if 'username' in session:
        poll_id = request.form['poll_id']
        poll = polls_collection.find_one({'_id': ObjectId(poll_id), 'creator': session['username']})
        if poll:
            polls_collection.delete_one({'_id': ObjectId(poll_id)})
            votes_collection.delete_many({'poll_id': poll_id})
            return redirect(url_for('manage_polls'))
    return redirect(url_for('login'))

@app.route('/edit_poll/<poll_id>', methods=['GET', 'POST'])
def edit_poll(poll_id):
    """Render the edit poll page and handle updating poll details."""
    if 'username' in session:
        poll = polls_collection.find_one({'_id': ObjectId(poll_id), 'creator': session['username']})
        if poll:
            if request.method == 'POST':
                start_time = datetime.fromisoformat(request.form['start_time'])
                end_time = datetime.fromisoformat(request.form['end_time'])
                polls_collection.update_one({'_id': ObjectId(poll_id)}, {'$set': {'start_time': start_time, 'end_time': end_time}})
                return redirect(url_for('manage_polls'))
            return render_template('edit_poll.html', poll=poll)
    return redirect(url_for('login'))

def archive_expired_polls():
    """Move expired polls to the history collection."""
    current_time = datetime.now()
    expired_polls = list(polls_collection.find({'end_time': {'$lt': current_time}}))
    for poll in expired_polls:
        polls_history_collection.insert_one(poll)
        polls_collection.delete_one({'_id': poll['_id']})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
