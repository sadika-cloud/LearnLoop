import random
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import pytz






app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def format_timestamp(timestamp_str):
    if not timestamp_str:
        return "Unknown"
        
    try:
        # Handle timestamps with milliseconds
        if '.' in timestamp_str:
            dt = datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        else:
            # Try different formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %I:%M %p', '%Y-%m-%d']:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    break
                except ValueError:
                    continue
            else:
                return "Unknown"
            
    except Exception:
        return "Unknown"
            
    return dt.strftime('%b %d, %Y')  # Consistent date format everywhere


def init_db():
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    
    # Users table with profile photo
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  skills TEXT,
                  learning_interests TEXT,
                  profile_photo TEXT,
                  bio TEXT,
                  pin TEXT)''')
    
    # Messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER,
                  receiver_id INTEGER,
                  content TEXT,
                  timestamp DATETIME,
                  status TEXT DEFAULT 'sent',
                  FOREIGN KEY (sender_id) REFERENCES users (id),
                  
                  FOREIGN KEY (receiver_id) REFERENCES users (id))''')
    
    # Portfolio/Projects table with stars and reviews
    c.execute('''CREATE TABLE IF NOT EXISTS portfolios
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  title TEXT,
                  description TEXT,
                  file_path TEXT,
                  timestamp DATETIME,
                  stars INTEGER DEFAULT 0,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Stars table for user-project stars
    c.execute('''CREATE TABLE IF NOT EXISTS stars
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  project_id INTEGER,
                  timestamp DATETIME,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (project_id) REFERENCES portfolios (id))''')
    
    # Reviews table
    c.execute('''CREATE TABLE IF NOT EXISTS reviews
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  project_id INTEGER,
                  content TEXT,
                  timestamp DATETIME,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (project_id) REFERENCES portfolios (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS notifications
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  message TEXT NOT NULL,
                  type TEXT NOT NULL,
                  timestamp DATETIME NOT NULL,
                  is_read BOOLEAN DEFAULT 0,
                  user_id INTEGER,
                  actor_username TEXT,
                  project_id INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (project_id) REFERENCES portfolios (id))''')
    
    conn.commit()
    conn.close()



@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        pin = request.form['pin']  # Added PIN field
        skills = request.form['skills']
        learning_interests = request.form['learning_interests']
        bio = request.form.get('bio', '')

        # Validate PIN (must be exactly 4 digits)
        if not re.match(r'^\d{4}$', pin):
            flash('PIN must be exactly 4 digits.', 'error')
            return redirect(url_for('register'))

        # Handle profile photo upload
        profile_photo = None
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"profile_{username}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_photo = filename

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('learnloop.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, email, password, pin, skills, learning_interests, profile_photo, bio) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (username, email, hashed_password, pin, skills, learning_interests, profile_photo, bio))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!')
        finally:
            conn.close()

    return render_template('register.html') 



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        pin = request.form['pin']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Ensure passwords match
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('forgot_password'))

        conn = sqlite3.connect('learnloop.db')
        c = conn.cursor()

        # Check if email and PIN match
        c.execute('SELECT id FROM users WHERE email = ? AND pin = ?', (email, pin))
        user = c.fetchone()

        if not user:
            conn.close()
            flash('Invalid email or PIN!', 'error')
            return redirect(url_for('forgot_password'))

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Update the password
        c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user[0]))
        conn.commit()
        conn.close()

        flash('Password changed successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')





@app.route('/profile', methods=['GET', 'POST'])
@app.route('/profile/<username>')
def profile(username=None):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    
    # Get user info
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        flash('User not found!')
        return redirect(url_for('dashboard'))
    
    # Get user's projects with star counts
    c.execute('''
        SELECT 
            p.id,
            p.user_id,
            p.title,
            p.description,
            p.file_path,
            strftime('%Y-%m-%d', p.timestamp) as formatted_timestamp,
            COUNT(s.id) as star_count 
        FROM portfolios p 
        LEFT JOIN stars s ON p.id = s.project_id 
        WHERE p.user_id = ? 
        GROUP BY p.id
        ORDER BY star_count DESC
    ''', (user[0],))
    projects = c.fetchall()

    # **Fetch projects the logged-in user has already starred**
    c.execute('SELECT project_id FROM stars WHERE user_id = ?', (session['user_id'],))
    starred_projects = [row[0] for row in c.fetchall()]  # Convert to a list of IDs

    conn.close()
    
    # **Pass starred_projects to the template**
    return render_template('profile.html', user=user, projects=projects, starred_projects=starred_projects)

    
    
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bio = request.form.get('bio', '')
    skills = request.form.get('skills', '')
    learning_interests = request.form.get('learning_interests', '')

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Check if a new profile photo is uploaded
    file = request.files.get('profile_photo')
    if file and file.filename and allowed_file(file.filename):
        filename = secure_filename(f"profile_{session['username']}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Update with new photo
        c.execute(''' 
            UPDATE users 
            SET bio = ?, skills = ?, learning_interests = ?, profile_photo = ? 
            WHERE id = ? 
        ''', (bio, skills, learning_interests, filename, session['user_id']))
    else:
        # Only update bio, skills, and learning interests (keep existing profile photo)
        c.execute('''
            UPDATE users 
            SET bio = ?, skills = ?, learning_interests = ? 
            WHERE id = ? 
        ''', (bio, skills, learning_interests, session['user_id']))

    conn.commit()
    conn.close()

    flash('Profile updated successfully!')
    return redirect(url_for('profile'))


@app.route('/delete_project/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Check if the project exists and belongs to the user
    c.execute('SELECT user_id, file_path FROM portfolios WHERE id = ?', (project_id,))
    project = c.fetchone()

    if not project:
        conn.close()
        return jsonify({'error': 'Project not found'}), 404

    if project[0] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    # Delete notifications related to this project
    c.execute('DELETE FROM notifications WHERE project_id = ?', (project_id,))

    # Delete the project from the database
    c.execute('DELETE FROM portfolios WHERE id = ?', (project_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})



@app.route('/edit_project/<int:project_id>', methods=['POST'])
def edit_project(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    new_title = data.get('title')
    new_description = data.get('description')

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Check if the project belongs to the logged-in user
    c.execute('SELECT user_id FROM portfolios WHERE id = ?', (project_id,))
    project = c.fetchone()

    if not project:
        conn.close()
        return jsonify({'error': 'Project not found'}), 404

    if project[0] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    # Update the project in the database
    c.execute('UPDATE portfolios SET title = ?, description = ? WHERE id = ?', (new_title, new_description, project_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})
@app.route('/search')
def search():
    query = request.args.get('q', '')
    search_type = request.args.get('type', 'projects')

    # Retrieve the current user id from session
    user_id = session.get('user_id', None)

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Initialize starred_projects to an empty list by default
    starred_projects = []

    if search_type == 'users':
        c.execute(''' 
            SELECT id, username, email, skills, learning_interests, profile_photo, bio 
            FROM users 
            WHERE username LIKE ? OR skills LIKE ? OR bio LIKE ?
        ''', (f'%{query}%', f'%{query}%', f'%{query}%'))
        users = [dict(zip(['id', 'username', 'email', 'skills', 'learning_interests', 'profile_photo', 'bio'], row)) 
                 for row in c.fetchall()]
        projects = []
    else:
        c.execute(''' 
            SELECT p.id, p.user_id, p.title, p.description, p.file_path, 
                   strftime('%Y-%m-%d', p.timestamp) as formatted_timestamp, 
                   u.username, u.profile_photo, COUNT(s.id) as star_count, 
                   (SELECT COUNT(*) FROM reviews WHERE project_id = p.id) as review_count
            FROM portfolios p 
            JOIN users u ON p.user_id = u.id 
            LEFT JOIN stars s ON p.id = s.project_id 
            WHERE p.title LIKE ? OR p.description LIKE ? 
            GROUP BY p.id 
            ORDER BY star_count DESC, p.timestamp DESC
        ''', (f'%{query}%', f'%{query}%'))
        projects = c.fetchall()
        users = []

        # Fetch projects the logged-in user has already starred
        if user_id:
            c.execute("SELECT project_id FROM stars WHERE user_id = ?", (user_id,))
            starred_projects = [row[0] for row in c.fetchall()]

    conn.close()

    return render_template('search_results.html', 
                           projects=projects, 
                           users=users, 
                           query=query, 
                           search_type=search_type, 
                           user_id=user_id, 
                           starred_projects=starred_projects)  # Pass starred projects
  # Pass starred projects


    
    
@app.route('/star/<int:project_id>', methods=['POST'])
def star_project(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Get project owner
    c.execute('SELECT user_id FROM portfolios WHERE id = ?', (project_id,))
    project_owner = c.fetchone()
    
    if not project_owner:
        conn.close()
        return jsonify({'error': 'Project not found'}), 404

    project_owner_id = project_owner[0]

    # Check if the user already starred the project
    c.execute('SELECT id FROM stars WHERE user_id = ? AND project_id = ?', (session['user_id'], project_id))
    existing_star = c.fetchone()

    if existing_star:
        # Remove star
        c.execute('DELETE FROM stars WHERE user_id = ? AND project_id = ?', (session['user_id'], project_id))
        action = 'unstarred'
    else:
        # Add star
        c.execute('INSERT INTO stars (user_id, project_id, timestamp) VALUES (?, ?, ?)',
                  (session['user_id'], project_id, datetime.now()))
        action = 'starred'

        # Add notification for project owner
        if session['user_id'] != project_owner_id:  # Avoid self-notification
            c.execute('''INSERT INTO notifications (user_id, message, type, timestamp, is_read, actor_username, project_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (project_owner_id, 'starred your project', 'star', datetime.now(), 0, session['username'], project_id))

    # Get updated star count
    c.execute('SELECT COUNT(*) FROM stars WHERE project_id = ?', (project_id,))
    star_count = c.fetchone()[0]

    conn.commit()
    conn.close()

    return jsonify({'action': action, 'starCount': star_count})

@app.route('/review/<int:project_id>', methods=['POST'])
def add_review(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    content = request.form.get('content')
    if not content:
        return jsonify({'error': 'Review content is required'}), 400

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Get project owner
    c.execute('SELECT user_id FROM portfolios WHERE id = ?', (project_id,))
    project_owner = c.fetchone()

    if not project_owner:
        conn.close()
        return jsonify({'error': 'Project not found'}), 404

    project_owner_id = project_owner[0]

    # Insert review
    c.execute('INSERT INTO reviews (user_id, project_id, content, timestamp) VALUES (?, ?, ?, ?)',
              (session['user_id'], project_id, content, datetime.now()))

    # Add notification for project owner
    if session['user_id'] != project_owner_id:  # Avoid self-notification
        c.execute('''
            INSERT INTO notifications (user_id, message, type, timestamp, is_read, actor_username, project_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (project_owner_id, 'reviewed your project', 'review', datetime.now(), 0, session['username'], project_id))

    conn.commit()
    conn.close()

    return jsonify({'success': True})




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('learnloop.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!')
    
    return render_template('login.html')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    
    # Get projects with star counts
    c.execute('''
        SELECT 
            p.id,
            p.user_id,
            p.title,
            p.description,
            p.file_path,
            strftime('%Y-%m-%d', p.timestamp) as timestamp,
            u.username,
            u.profile_photo,
            (SELECT COUNT(*) FROM stars WHERE project_id = p.id) as star_count,
            (SELECT COUNT(*) FROM reviews WHERE project_id = p.id) as review_count
        FROM portfolios p
        JOIN users u ON p.user_id = u.id
        ORDER BY RANDOM()
        LIMIT 10
    ''')
    random_projects = c.fetchall()
    
    # Get starred projects for the current user
    c.execute('''
        SELECT project_id 
        FROM stars 
        WHERE user_id = ?
    ''', (session['user_id'],))
    starred_projects = [row[0] for row in c.fetchall()]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         random_projects=random_projects,
                         starred_projects=starred_projects)
    
@app.route('/unread_messages_count')
def unread_messages_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    
    # Count unread messages (where status is 'sent' and user is the receiver)
    c.execute('''
        SELECT COUNT(*) 
        FROM messages 
        WHERE receiver_id = ? AND status = 'sent'
    ''', (session['user_id'],))
    
    count = c.fetchone()[0]
    conn.close()
    
    return jsonify({'count': count})

@app.route('/unread_notifications_count')
def unread_notifications_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    
    # Count unread notifications
    c.execute('''
        SELECT COUNT(*) 
        FROM notifications 
        WHERE user_id = ? AND is_read = 0
    ''', (session['user_id'],))
    
    count = c.fetchone()[0]
    conn.close()
    
    return jsonify({'count': count})

@app.route('/navbar_reload')
def navbar_reload():
    return render_template('navbar_partial.html')  # A separate template for the navbar


@app.route('/mark_notifications_as_read', methods=['POST'])
def mark_notifications_as_read():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    c.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Fetch notifications, but only for existing projects
    c.execute('''
        SELECT n.id, n.message, n.type, strftime('%Y-%m-%d', p.timestamp) as timestamp, n.is_read, n.actor_username, 
               n.project_id, p.title, u.username
        FROM notifications n
        LEFT JOIN portfolios p ON n.project_id = p.id
        LEFT JOIN users u ON n.user_id = u.id
        WHERE n.user_id = ? AND p.id IS NOT NULL
        ORDER BY n.timestamp DESC
    ''', (session['user_id'],))
    
    notifications = c.fetchall()
    conn.close()

    return render_template('notifications.html', notifications=notifications)


@app.route('/delete_notification/<int:notification_id>', methods=['DELETE'])
def delete_notification(notification_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = sqlite3.connect('learnloop.db')
        c = conn.cursor()

        # Delete notification from the notifications table
        c.execute('''DELETE FROM notifications WHERE id = ? AND user_id = ?''', (notification_id, session['user_id']))
        conn.commit()

        conn.close()

        # Return a success response
        return '', 204  # No content, indicating success

    except Exception as e:
        print(e)
        return 'Error deleting notification', 500



@app.route('/get_unread_count')
def get_unread_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0',
             (session['user_id'],))
    count = c.fetchone()[0]
    conn.close()
    
    return jsonify({'count': count})


@app.route('/get_reviews/<int:project_id>')
def get_reviews(project_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    c.execute('''
        SELECT r.id, r.user_id, r.project_id, r.content, 
               strftime('%Y-%m-%d', r.timestamp) as timestamp,
               u.username, u.profile_photo
        FROM reviews r 
        JOIN users u ON r.user_id = u.id 
        WHERE r.project_id = ? 
        ORDER BY r.timestamp DESC
    ''', (project_id,))

    reviews = [{
        'id': row[0],
        'user_id': row[1],  # Send user_id so frontend can check ownership
        'project_id': row[2],
        'content': row[3],
        'timestamp': row[4],
        'username': row[5],
        'profile_picture': row[6]  # Include profile picture in response
    } for row in c.fetchall()]

    conn.close()
    return jsonify(reviews)


from datetime import datetime

@app.route('/send_message', methods=['POST'])
def send_message():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    recipient = data.get('recipient')
    content = data.get('content')
    
    if not recipient or not content:
        return jsonify({'error': 'Missing recipient or content'}), 400
    
    with sqlite3.connect('learnloop.db') as conn:
        c = conn.cursor()
        
        # Get recipient's user ID
        c.execute('SELECT id FROM users WHERE username = ?', (recipient,))
        recipient_data = c.fetchone()
        
        if not recipient_data:
            return jsonify({'error': 'Recipient not found'}), 404
        
        recipient_id = recipient_data[0]
        
        # Insert the message with initial status as 'sent'
        c.execute('''INSERT INTO messages (sender_id, receiver_id, content, timestamp, status) 
                     VALUES (?, ?, ?, datetime('now'), 'sent')''', 
                  (user_id, recipient_id, content))
        
        message_id = c.lastrowid
        conn.commit()
    
    return jsonify({'success': True, 'message_id': message_id, 'status': 'sent'})

@app.route('/mark_messages_as_read/<username>', methods=['POST'])
def mark_messages_as_read(username):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    with sqlite3.connect('learnloop.db') as conn:
        c = conn.cursor()
        # Get the sender's user ID
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        sender_data = c.fetchone()

        if not sender_data:
            return jsonify({'error': 'Sender not found'}), 404

        sender_id = sender_data[0]

        # Update all unread messages from this sender to this receiver
        c.execute('''UPDATE messages 
                     SET status = 'read' 
                     WHERE sender_id = ? AND receiver_id = ? AND status = 'sent' ''',
                  (sender_id, user_id))
        conn.commit()

    return jsonify({'success': True})

@app.route('/get_chat_history/<username>')
def get_chat_history(username):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    with sqlite3.connect('learnloop.db') as conn:
        c = conn.cursor()
        # Get other user's ID
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        other_user = c.fetchone()

        if not other_user:
            return jsonify({'error': 'User not found'}), 404

        other_user_id = other_user[0]

        # Get all messages with their status
        c.execute('''
            SELECT m.id, m.sender_id, m.receiver_id, m.content, m.status
            FROM messages m
            WHERE (m.sender_id = ? AND m.receiver_id = ?) 
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp ASC
        ''', (user_id, other_user_id, other_user_id, user_id))

        messages = [{
            'id': row[0],
            'sender_id': row[1],
            'receiver_id': row[2],
            'content': row[3],
            'status': row[4] if row[1] == user_id else ""
        } for row in c.fetchall()]

    return jsonify(messages)



from datetime import datetime


@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()
    
    # Get all unique conversations with latest message and status
    c.execute(''' 
        WITH LastMessages AS (
            SELECT 
                m1.*,
                ROW_NUMBER() OVER (
                    PARTITION BY 
                        CASE 
                            WHEN m1.sender_id = ? THEN m1.receiver_id 
                            ELSE m1.sender_id 
                        END
                    ORDER BY m1.timestamp DESC
                ) as rn
            FROM messages m1
            WHERE m1.sender_id = ? OR m1.receiver_id = ?
        )
        SELECT 
            m.sender_id,
            m.receiver_id,
            CASE 
                WHEN m.sender_id = ? THEN u_receiver.username
                ELSE u_sender.username
            END as username,
            CASE 
                WHEN m.sender_id = ? THEN u_receiver.profile_photo
                ELSE u_sender.profile_photo
            END as profile_photo,
            m.content as last_message,
            m.status,
            m.sender_id = ? as is_sender,
            m.timestamp,
            EXISTS (
                SELECT 1 
                FROM messages m2 
                WHERE m2.sender_id = CASE 
                    WHEN m.sender_id = ? THEN m.receiver_id
                    ELSE m.sender_id
                END 
                AND m2.receiver_id = ? 
                AND m2.status = 'sent'
            ) as unread
        FROM LastMessages m
        JOIN users u_sender ON m.sender_id = u_sender.id
        JOIN users u_receiver ON m.receiver_id = u_receiver.id
        WHERE rn = 1
        ORDER BY m.timestamp DESC
    ''', (session['user_id'],) * 8)
    
    conversations = []
    current_time = datetime.now(pytz.UTC)
    
    for row in c.fetchall():
        message_time = datetime.strptime(row[7], '%Y-%m-%d %H:%M:%S')
        time_diff = current_time - message_time.replace(tzinfo=pytz.UTC)
        
        # Calculate relative time
        minutes = time_diff.total_seconds() / 60
        if minutes < 1:
            relative_time = "just now"
        elif minutes < 60:
            mins = int(minutes)
            relative_time = f"{mins} min{'s' if mins != 1 else ''} ago"
        else:
            hours = int(minutes / 60)
            if hours < 24:
                relative_time = f"{hours} hour{'s' if hours != 1 else ''} ago"
            else:
                days = int(hours / 24)
                relative_time = f"{days} day{'s' if days != 1 else ''} ago"
        
        conversations.append({
            'username': row[2],
            'profile_photo': row[3],
            'last_message': row[4],
            'status': relative_time,  # Always show relative time, regardless of sender
            'is_sender': bool(row[6]),
            'unread': bool(row[8])
        })
    
    conn.close()
    return render_template('messages.html', conversations=conversations)








@app.route('/upload_portfolio', methods=['POST'])
def upload_portfolio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title']
    description = request.form['description']
    file = request.files['file']
    
    if file:
        filename = f"{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M')}_{file.filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        conn = sqlite3.connect('learnloop.db')
        c = conn.cursor()
        c.execute('INSERT INTO portfolios (user_id, title, description, file_path, timestamp) VALUES (?, ?, ?, ?, ?)',
                 (session['user_id'], title, description, filename, datetime.now()))
        conn.commit()
        conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/edit_review/<int:review_id>', methods=['POST'])
def edit_review(review_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.get_json()
    new_content = data.get('content')
    if not new_content:
        return jsonify({'error': 'Review content required'}), 400

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Ensure the review belongs to the logged-in user
    c.execute("SELECT user_id FROM reviews WHERE id = ?", (review_id,))
    review = c.fetchone()
    
    if not review:
        conn.close()
        return jsonify({'error': 'Review not found'}), 404

    if review[0] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    # Update review
    c.execute("UPDATE reviews SET content = ? WHERE id = ?", (new_content, review_id))
    conn.commit()
    conn.close()

    return jsonify({'success': True})
@app.route('/delete_review/<int:review_id>', methods=['POST'])
def delete_review(review_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = sqlite3.connect('learnloop.db')
    c = conn.cursor()

    # Ensure the review exists
    c.execute("SELECT user_id, project_id FROM reviews WHERE id = ?", (review_id,))
    review = c.fetchone()

    if not review:
        conn.close()
        return jsonify({'error': 'Review not found'}), 404

    review_user_id, project_id = review

    # Check if the logged-in user is either the review author or the project owner
    c.execute("SELECT user_id FROM portfolios WHERE id = ?", (project_id,))
    project = c.fetchone()

    if not project:
        conn.close()
        return jsonify({'error': 'Project not found'}), 404

    project_owner_id = project[0]

    if review_user_id != session['user_id'] and project_owner_id != session['user_id']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    # Delete review
    c.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})





@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    init_db()
    app.run(debug=True)