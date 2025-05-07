import sqlite3
import time
import os
import secrets
import json
from threading import Thread
from instagrapi import Client
from instagrapi.exceptions import ClientError, TwoFactorRequired, LoginRequired, ChallengeRequired
from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
import logging
import bcrypt
from functools import wraps
from dotenv import load_dotenv
import random
import re
import tenacity
from sqlite3 import dbapi2 as sqlite

# Code version for debugging
CODE_VERSION = "3.1.0"

# Load environment variables
load_dotenv()

# Set up logging with UTF-8 encoding
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('crm.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logging.info(f"Starting aa.py version {CODE_VERSION}")

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['TEMPLATES_AUTO_RELOAD'] = True

clients = {}
initial_messages = []
dm_count = 0  # Track total DMs sent
initial_dms_sent = False  # Global flag to gate auto_respond

# Database connection pool
db_pool = sqlite.connect('crm.db', timeout=50, check_same_thread=False, factory=sqlite.Connection)

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def get_user_info(user_id):
    conn = db_pool
    c = conn.cursor()
    c.execute('SELECT plan, credits FROM users WHERE id = ?', (user_id,))
    return c.fetchone()

def get_accounts(user_id, role):
    conn = db_pool
    c = conn.cursor()
    if role == 'admin':
        c.execute('SELECT username, needs_reauth FROM accounts')
    else:
        c.execute('SELECT username, needs_reauth FROM accounts WHERE user_id = ?', (user_id,))
    return c.fetchall()

@tenacity.retry(
    stop=tenacity.stop_after_attempt(5),
    wait=tenacity.wait_exponential(multiplier=2, min=5, max=30),
    retry=tenacity.retry_if_exception_type(sqlite3.OperationalError),
    before_sleep=lambda retry_state: logging.warning(f"Database locked, retrying attempt {retry_state.attempt_number}...")
)
def execute_with_retry(cursor, query, params=()):
    cursor.execute(query, params)
    return cursor

def init_db():
    try:
        conn = db_pool
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS accounts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      username TEXT NOT NULL,
                      session_file TEXT,
                      needs_reauth INTEGER DEFAULT 0,
                      has_sent_initial_dms INTEGER DEFAULT 0,
                      proxy_settings TEXT,
                      UNIQUE(user_id, username),
                      FOREIGN KEY (user_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS initial_dms
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      account_id INTEGER,
                      username TEXT NOT NULL,
                      sent_timestamp INTEGER,
                      UNIQUE(account_id, username),
                      FOREIGN KEY (account_id) REFERENCES accounts(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS dms
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      account_id INTEGER,
                      thread_id TEXT,
                      contact_name TEXT,
                      last_message TEXT,
                      message_id TEXT,
                      timestamp INTEGER,
                      responded INTEGER DEFAULT 0,
                      is_system_message INTEGER DEFAULT 0,
                      follow_up_stage INTEGER DEFAULT 0,
                      last_response TEXT,
                      waiting_for_contact INTEGER DEFAULT 0,
                      UNIQUE(thread_id, message_id),
                      FOREIGN KEY (account_id) REFERENCES accounts(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password_hash TEXT NOT NULL,
                      role TEXT NOT NULL DEFAULT 'customer',
                      credits INTEGER DEFAULT 0,
                      plan TEXT DEFAULT '')''')
        c.execute('PRAGMA table_info(accounts)')
        columns = [col[1] for col in c.fetchall()]
        if 'has_sent_initial_dms' not in columns:
            c.execute('ALTER TABLE accounts ADD COLUMN has_sent_initial_dms INTEGER DEFAULT 0')
        if 'proxy_settings' not in columns:
            c.execute('ALTER TABLE accounts ADD COLUMN proxy_settings TEXT')
        c.execute('PRAGMA table_info(dms)')
        columns = [col[1] for col in c.fetchall()]
        if 'follow_up_stage' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN follow_up_stage INTEGER DEFAULT 0')
        if 'message_id' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN message_id TEXT')
        if 'last_response' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN last_response TEXT')
        if 'waiting_for_contact' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN waiting_for_contact INTEGER DEFAULT 0')
        default_admin_username = 'admin'
        default_admin_password = 'supersecret123'
        hashed_password = bcrypt.hashpw(default_admin_password.encode(), bcrypt.gensalt()).decode()
        c.execute('SELECT id FROM users WHERE username = ?', (default_admin_username,))
        if not c.fetchone():
            c.execute('INSERT INTO users (username, password_hash, role, credits, plan) VALUES (?, ?, ?, ?, ?)',
                      (default_admin_username, hashed_password, 'admin', 0, ''))
        conn.commit()
        logging.info("Database initialized successfully")
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {str(e)}")
        raise

def load_instagrapi_client(session_file):
    try:
        if not os.path.exists(session_file):
            logging.warning(f"Session file {session_file} does not exist")
            return None
        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT proxy_settings FROM accounts WHERE session_file = ?', (session_file,))
        result = c.fetchone()
        proxy_settings = json.loads(result[0]) if result and result[0] else None
        cl = Client(request_timeout=15, proxy=proxy_settings["proxy"] if proxy_settings else None)
        cl.load_settings(session_file)
        logging.info(f"Instagrapi client loaded from {session_file} with proxy: {proxy_settings}")
        return cl
    except Exception as e:
        logging.error(f"Failed to load instagrapi client from {session_file}: {str(e)}")
        return None

def get_client(user_id, username):
    conn = db_pool
    c = conn.cursor()
    c.execute('SELECT needs_reauth, session_file FROM accounts WHERE user_id = ? AND username = ?', (user_id, username))
    result = c.fetchone()
    if not result:
        logging.error(f"Account {username} not found for user_id {user_id}")
        return None
    needs_reauth, session_file = result
    client_key = f"{user_id}_{username}"
    if needs_reauth:
        logging.warning(f"Account {username} (user_id {user_id}) marked as needs_reauth")
        if client_key in clients:
            del clients[client_key]
        return None
    if client_key not in clients:
        cl = load_instagrapi_client(session_file)
        if cl:
            try:
                if not cl.user_id:
                    logging.warning(f"No user_id in session for {username} (user_id {user_id})")
                    c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
                    conn.commit()
                    return None
                cl.user_info(cl.user_id)
                clients[client_key] = cl
                c.execute('UPDATE accounts SET needs_reauth = 0 WHERE user_id = ? AND username = ?', (user_id, username))
                conn.commit()
                logging.info(f"Valid session loaded for {username} (user_id {user_id})")
            except (LoginRequired, ClientError) as e:
                logging.warning(f"Session invalid for {username} (user_id {user_id}): {str(e)}")
                c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
                conn.commit()
                return None
        else:
            logging.warning(f"Failed to load client for {username} (user_id {user_id}), marking as needs_reauth")
            c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
            conn.commit()
            return None
    return clients.get(client_key)

def normalize_message(message):
    return re.sub(r'[^\w\s]', '', message.lower()).strip()

def is_contact_info(message):
    # Basic phone number regex (e.g., +1234567890, 123-456-7890, (123) 456-7890)
    phone_pattern = r'(\+\d{10,15}|\(\d{3}\)\s*\d{3}-\d{4}|\d{3}-\d{3}-\d{4})'
    # Basic email regex
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return bool(re.search(phone_pattern, message) or re.search(email_pattern, message))

def clean_response(response):
    music_keywords = ['music', 'song', 'artist', 'genre', 'recommendations', 'updates', 'musical']
    for keyword in music_keywords:
        response = re.sub(rf'\b{keyword}\b', '', response, flags=re.IGNORECASE)
    response = re.sub(r'\s+', ' ', response).strip()
    return response

def huggingface_chatbot(message):
    logging.debug(f"Processing message: {message}")
    normalized = normalize_message(message)
    logging.debug(f"Normalized message: {normalized}")
    
    if normalized in ['hey', 'hi', 'hello', 'yo', 'sup']:
        logging.debug("Detected greeting message, returning hardcoded greeting")
        response = "Hello! Thanks for your interest! :) How can I assist you today?"
    elif normalized in ['interested', 'imterested', 'intriguing', 'intrested', 'thrilled', 'excited']:
        logging.debug("Detected 'interested' message, returning contact request")
        response = "Awesome, glad you're intrigued! :) Could you share your email or phone number to dive deeper?"
    elif normalized in ['cool', 'nice', 'awesome']:
        logging.debug("Detected positive message, returning generic response")
        response = "Glad you think so! :) What's on your mind?"
    elif is_contact_info(message):
        logging.debug("Detected contact info, returning confirmation")
        response = "Thanks for sharing! I'll get back to you soon! :)"
    else:
        logging.debug("Using fallback response")
        response = "Thanks for replying! :) What's on your mind?"
    
    cleaned_response = clean_response(response)
    logging.debug(f"Cleaned response: {cleaned_response}")
    return cleaned_response

def auto_respond():
    global dm_count, initial_dms_sent
    THREAD_COOLDOWN = 300  # 5 minutes in seconds
    while True:
        if not initial_dms_sent:
            logging.debug("Initial DMs not sent yet, skipping auto_respond cycle")
            time.sleep(60)
            continue
        try:
            conn = db_pool
            c = conn.cursor()
            c.execute('SELECT DISTINCT user_id, username FROM accounts WHERE needs_reauth = 0 AND has_sent_initial_dms = 1')
            accounts = c.fetchall()
            logging.debug(f"Checking threads for {len(accounts)} accounts with initial DMs sent")
            pending_inserts = []
            for user_id, username in accounts:
                try:
                    c.execute('SELECT COUNT(*), MAX(sent_timestamp) FROM initial_dms WHERE account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', 
                              (user_id, username))
                    initial_dm_count, max_sent_timestamp = c.fetchone()
                    if initial_dm_count == 0:
                        logging.debug(f"No initial DMs sent for {username} (user_id {user_id}), skipping auto_respond")
                        continue
                    cl = get_client(user_id, username)
                    if not cl:
                        logging.warning(f"Skipping {username} (user_id {user_id}) due to invalid session")
                        continue
                    cl_user_id = cl.user_id
                    c.execute('SELECT username FROM initial_dms WHERE account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', 
                              (user_id, username))
                    initial_usernames = {row[0] for row in c.fetchall()}
                    try:
                        threads = cl.direct_threads(amount=10)
                    except (LoginRequired, ClientError) as e:
                        logging.error(f"API error for {username} (user_id {user_id}): {str(e)}")
                        c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
                        conn.commit()
                        client_key = f"{user_id}_{username}"
                        if client_key in clients:
                            del clients[client_key]
                        continue
                    threads.sort(key=lambda x: x.last_activity_at.timestamp() if x.last_activity_at else 0, reverse=True)
                    logging.info(f"Fetched {len(threads)} threads for {username} (user_id {user_id})")
                    for thread in threads:
                        if not thread.messages or not thread.users:
                            logging.debug(f"Thread {thread.id} has no messages or users, skipping")
                            continue
                        contact_name = thread.users[0].username
                        if contact_name not in initial_usernames:
                            logging.debug(f"Thread {thread.id} with {contact_name} not in initial_dms, skipping")
                            continue
                        # Check thread cooldown
                        c.execute('SELECT MAX(timestamp) FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)',
                                  (thread.id, user_id, username))
                        last_response_timestamp = c.fetchone()[0] or 0
                        current_time = int(time.time())
                        if last_response_timestamp and (current_time - last_response_timestamp) < THREAD_COOLDOWN:
                            logging.debug(f"Thread {thread.id} with {contact_name} is in cooldown (last response at {last_response_timestamp}), skipping")
                            continue
                        # Check if waiting for contact info
                        c.execute('SELECT waiting_for_contact FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?) ORDER BY timestamp DESC LIMIT 1',
                                  (thread.id, user_id, username))
                        waiting = c.fetchone()
                        waiting_for_contact = waiting[0] if waiting else 0
                        messages = sorted(thread.messages, key=lambda x: x.timestamp.timestamp() if x.timestamp else 0, reverse=True)[:10]
                        for msg in messages:
                            message_id = msg.id
                            last_message = msg.text if msg.text else ""
                            timestamp = int(msg.timestamp.timestamp()) if msg.timestamp else 0
                            is_user_message = msg.user_id != cl_user_id if msg.user_id else False
                            logging.debug(f"Processing message {message_id} in thread {thread.id} from {contact_name}: '{last_message}' (timestamp: {timestamp}, is_user: {is_user_message})")
                            if not is_user_message:
                                logging.debug(f"Message {message_id} is sent by viewer, skipping")
                                continue
                            if timestamp <= last_response_timestamp:
                                logging.debug(f"Message {message_id} (timestamp {timestamp}) is older than last response ({last_response_timestamp}), skipping")
                                continue
                            c.execute('SELECT id, responded, last_response FROM dms WHERE thread_id = ? AND message_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', 
                                      (thread.id, message_id, user_id, username))
                            existing = c.fetchone()
                            if existing:
                                existing_id, existing_responded, last_response = existing
                                if existing_responded:
                                    logging.debug(f"Message {message_id} already responded to, skipping")
                                    continue
                            if is_user_message and last_message:
                                if waiting_for_contact and not is_contact_info(last_message):
                                    logging.debug(f"Thread {thread.id} is waiting for contact info, skipping message {message_id}: '{last_message}'")
                                    continue
                                response = huggingface_chatbot(last_message)
                                # Check recent responses for repetition
                                c.execute('SELECT last_response FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?) ORDER BY timestamp DESC LIMIT 5',
                                          (thread.id, user_id, username))
                                recent_responses = {row[0] for row in c.fetchall() if row[0]}
                                if response in recent_responses:
                                    logging.debug(f"Response '{response}' is identical to a recent response in thread {thread.id}, skipping")
                                    continue
                                try:
                                    cl.direct_send(response, thread_ids=[thread.id])
                                    waiting_for_contact_new = 1 if response.startswith("Awesome, glad you're intrigued!") else 0
                                    pending_inserts.append((
                                        user_id, username, thread.id, contact_name, last_message, message_id, timestamp, response, waiting_for_contact_new
                                    ))
                                    dm_count += 1
                                    logging.info(f"Sent chatbot response to {contact_name} (thread {thread.id}, message {message_id}) for {username} (user_id {user_id}): {response}")
                                except Exception as e:
                                    logging.error(f"Failed to send chatbot response to {contact_name} (thread {thread.id}, message {message_id}): {str(e)}")
                                    raise
                    # Batch insert pending DMs
                    if pending_inserts:
                        try:
                            c.executemany(
                                'INSERT OR REPLACE INTO dms (account_id, thread_id, contact_name, last_message, message_id, timestamp, responded, is_system_message, follow_up_stage, last_response, waiting_for_contact) VALUES ((SELECT id FROM accounts WHERE user_id = ? AND username = ?), ?, ?, ?, ?, ?, 1, 1, 1, ?, ?)',
                                pending_inserts
                            )
                            conn.commit()
                            logging.debug(f"Batched {len(pending_inserts)} DM inserts for {username} (user_id {user_id})")
                            pending_inserts.clear()
                        except sqlite3.OperationalError as e:
                            logging.error(f"Batch insert failed for {username} (user_id {user_id}): {str(e)}")
                            raise
                except Exception as e:
                    logging.error(f"Auto-respond error for {username} (user_id {user_id}): {str(e)}")
            conn.commit()
        except sqlite3.OperationalError as e:
            logging.error(f"Database error in auto_respond: {str(e)}")
            if "database is locked" in str(e):
                logging.warning("Retrying after 10 seconds due to database lock")
                time.sleep(10)
                continue
        except Exception as e:
            logging.error(f"auto_respond loop error: {str(e)}")
        time.sleep(60)
        logging.debug("auto_respond loop completed, sleeping for 60 seconds")

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('login.html')
        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash, role, credits, plan FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and bcrypt.checkpw(password.encode(), user[2].encode()):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            session['credits'] = user[4]
            session['plan'] = user[5]
            flash(f"Welcome, {username}! Connected", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.", "danger")
        return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('credits', None)
    session.pop('plan', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))


@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    conn = db_pool
    c = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            username = request.form.get('username')
            password = request.form.get('password')
            if not username or not password:
                flash("Username and password are required.", "danger")
            else:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                try:
                    c.execute('INSERT INTO users (username, password_hash, role, credits, plan) VALUES (?, ?, ?, ?, ?)',
                              (username, hashed_password, 'customer', 0, ''))
                    conn.commit()
                    flash(f"User {username} created successfully.", "success")
                except sqlite3.IntegrityError:
                    flash("Username already exists.", "danger")
        elif action == 'delete':
            user_id = request.form.get('user_id')
            c.execute('DELETE FROM users WHERE id = ? AND role != ?', (user_id, 'admin'))
            conn.commit()
            flash("User deleted successfully.", "success")
        elif action == 'assign_plan':
            user_id = request.form.get('user_id')
            plan = request.form.get('plan')
            plan_configs = {
                'plan1': {'credits': 100, 'max_accounts': 5, 'credits_per_account': 20, 'credits_per_dm': 1},
                'plan2': {'credits': 300, 'max_accounts': 10, 'credits_per_account': 30, 'credits_per_dm': 1},
                'plan3': {'credits': 500, 'max_accounts': 15, 'credits_per_account': 34, 'credits_per_dm': 1}
            }
            if plan in plan_configs:
                c.execute('UPDATE users SET plan = ?, credits = ? WHERE id = ? AND role != ?',
                          (plan, plan_configs[plan]['credits'], user_id, 'admin'))
                conn.commit()
                flash(f"Plan {plan} assigned to user ID {user_id}.", "success")
            else:
                flash("Invalid plan selected.", "danger")

    # Fetch users regardless of GET or POST
    c.execute('SELECT id, username, role, credits, plan FROM users')
    users = c.fetchall()

    return render_template('admin_users.html', users=users)

@app.route('/add-account', methods=['GET', 'POST'])
@login_required
def add_account():
    user_id = session['user_id']
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        two_factor_code = request.form.get('two_factor_code', '')
        proxy_host = request.form.get('proxy_host')
        proxy_port = request.form.get('proxy_port')
        proxy_username = request.form.get('proxy_username')
        proxy_password = request.form.get('proxy_password')
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('add_account.html', two_factor_required=False)
        user_info = get_user_info(user_id)
        if not user_info:
            flash("User not found.", "danger")
            return render_template('add_account.html', two_factor_required=False)
        plan, credits = user_info
        plan_configs = {
            'plan1': {'max_accounts': 5, 'credits_per_account': 20, 'credits_per_dm': 1},
            'plan2': {'max_accounts': 10, 'credits_per_account': 30, 'credits_per_dm': 1},
            'plan3': {'max_accounts': 15, 'credits_per_account': 34, 'credits_per_dm': 1}
        }
        if not plan or plan not in plan_configs:
            flash("You must have an active plan to add accounts.", "danger")
            return render_template('add_account.html', two_factor_required=False)
        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM accounts WHERE user_id = ?', (user_id,))
        current_accounts = c.fetchone()[0]
        if current_accounts >= plan_configs[plan]['max_accounts']:
            flash(f"You have reached the maximum number of accounts ({plan_configs[plan]['max_accounts']}) for your plan.", "danger")
            return render_template('add_account.html', two_factor_required=False)
        credits_needed = plan_configs[plan]['credits_per_account']
        if credits < credits_needed:
            flash(f"Insufficient credits. You need {credits_needed} credits to add an account, but you have {credits}.", "danger")
            return render_template('add_account.html', two_factor_required=False)
        # Configure proxy
        proxy_settings = None
        if proxy_host and proxy_port:
            proxy_url = f"socks5://{proxy_host}:{proxy_port}"
            if proxy_username and proxy_password:
                proxy_url = f"socks5://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"
            proxy_settings = {"proxy": proxy_url}
            logging.info(f"Using proxy for {username}: {proxy_url}")
        session_file = f'session_{user_id}_{username}.json'
        try:
            cl = None
            if os.path.exists(session_file):
                cl = load_instagrapi_client(session_file)
                if cl:
                    try:
                        cl.user_info(cl.user_id)
                        logging.info(f"Reused existing session for {username} (user_id {user_id})")
                    except (LoginRequired, ClientError) as e:
                        logging.warning(f"Existing session invalid for {username} (user_id {user_id}): {str(e)}")
                        cl = None
                        os.remove(session_file)
            if not cl:
                cl = Client(request_timeout=15, proxy=proxy_settings["proxy"] if proxy_settings else None)
                time.sleep(2)
                try:
                    if two_factor_code:
                        cl.login(username, password, verification_code=two_factor_code)
                        logging.info(f"Logged in with 2FA code for {username} (user_id {user_id})")
                    else:
                        cl.login(username, password)
                        logging.info(f"Logged in without 2FA for {username} (user_id {user_id})")
                    cl.dump_settings(session_file)
                    logging.info(f"Session saved to {session_file}")
                except ChallengeRequired as e:
                    logging.error(f"Challenge required for {username} (user_id {user_id}): {str(e)}")
                    flash("Instagram requires a challenge verification. Please try logging in manually on the Instagram app to resolve this.", "danger")
                    return render_template('add_account.html', two_factor_required=False)
                except TwoFactorRequired as e:
                    logging.info(f"2FA required for {username} (user_id {user_id})")
                    flash("Two-factor authentication required. Please enter the 2FA code.", "warning")
                    return render_template('add_account.html', username=username, two_factor_required=True)
                except ClientError as e:
                    logging.error(f"Client error during login for {username} (user_id {user_id}): {str(e)}")
                    flash(f"Login failed: {str(e)}. Please check your credentials or try again later.", "danger")
                    return render_template('add_account.html', two_factor_required=False)
            new_credits = credits - credits_needed
            c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
            c.execute('INSERT OR REPLACE INTO accounts (user_id, username, session_file, needs_reauth, has_sent_initial_dms, proxy_settings) VALUES (?, ?, ?, 0, 0, ?)',
                     (user_id, username, session_file, json.dumps(proxy_settings) if proxy_settings else None))
            conn.commit()
            client_key = f"{user_id}_{username}"
            clients[client_key] = cl
            session['credits'] = new_credits
            flash(f"Account '{username}' added successfully! {credits_needed} credits deducted. Remaining credits: {new_credits}", "success")
            logging.info(f"Account {username} added successfully for user_id {user_id}, credits deducted: {credits_needed}, proxy: {proxy_settings}")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Unexpected error during login: {str(e)}", "danger")
            logging.error(f"Unexpected login error for {username}: {str(e)}")
            return render_template('add_account.html', two_factor_required=False)
    return render_template('add_account.html', two_factor_required=False)

@app.route('/dashboard', defaults={'selected_account': None})
@app.route('/dashboard/<selected_account>')
@login_required
def dashboard(selected_account):
    user_id = session['user_id']
    role = session['role']
    accounts = get_accounts(user_id, role)
    for username, needs_reauth in accounts:
        if needs_reauth:
            flash(f"Session for {username} has expired. Please re-authenticate the account.", "danger")
    valid_usernames = [acc[0] for acc in accounts]
    if selected_account and selected_account not in valid_usernames:
        flash("Invalid account selected.", "danger")
        selected_account = None
    user_info = get_user_info(user_id)
    credits, plan = user_info if user_info else (0, '')
    log_entries = []
    if os.path.exists('crm.log'):
        with open('crm.log', 'r', encoding='utf-8') as log_file:
            log_entries = log_file.readlines()[-10:]
    return render_template('dashboard.html', accounts=accounts, selected_account=selected_account, credits=credits, plan=plan, log_entries=log_entries, dm_count=dm_count)

@app.route('/send-dms', methods=['GET', 'POST'])
@login_required
def send_dms():
    global initial_messages, dm_count, initial_dms_sent
    user_id = session['user_id']
    role = session['role']
    accounts = get_accounts(user_id, role)
    if request.method == 'POST':
        account = request.form.get('account')
        usernames_file = request.files.get('usernames')
        messages_file = request.files.get('messages')
        num_messages = request.form.get('num_messages', '1')
        try :
            num_messages = max(1, min(10, int(num_messages)))
        except ValueError:
            num_messages = 1
            flash("Invalid number of messages. Using default value of 1.", "warning")
        if not account or not usernames_file or not messages_file:
            flash("Account, usernames file, and messages file are required.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT id FROM accounts WHERE username = ?' + (' AND user_id = ?' if role != 'admin' else ''),
                  (account, user_id) if role != 'admin' else (account,))
        account_id = c.fetchone()
        if not account_id:
            flash("Invalid account selected.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        account_id = account_id[0]
        user_info = get_user_info(user_id)
        if not user_info:
            flash("User not found.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        plan, credits = user_info
        plan_configs = {
            'plan1': {'credits_per_dm': 1},
            'plan2': {'credits_per_dm': 1},
            'plan3': {'credits_per_dm': 1}
        }
        if not plan or plan not in plan_configs:
            flash("You must have an active plan to send DMs.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        try:
            usernames = usernames_file.read().decode('utf-8').strip().splitlines()
            usernames = [u.strip() for u in usernames if u.strip()]
        except Exception as e:
            flash(f"Failed to read usernames file: {str(e)}", "danger")
            return render_template('dashboard.html', accounts=accounts)
        try:
            messages_raw = messages_file.read().decode('utf-8').strip()
            try:
                messages_json = json.loads(messages_raw)
                if isinstance(messages_json, dict):
                    initial_messages = [messages_json.get("text", messages_json.get("message", messages_raw.strip()))] * num_messages
                elif isinstance(messages_json, list):
                    initial_messages = [msg.get("text", msg.get("message", "")) for msg in messages_json if "text" in msg or "message" in msg]
                    if len(initial_messages) < num_messages:
                        initial_messages = initial_messages * (num_messages // len(initial_messages)) + initial_messages[:num_messages % len(initial_messages)]
                    initial_messages = initial_messages[:num_messages]
                else:
                    initial_messages = [messages_raw.strip()] * num_messages
            except json.JSONDecodeError:
                initial_messages = [messages_raw.strip()] * num_messages
            if not initial_messages or not all(m.strip() for m in initial_messages):
                flash("Messages file must contain valid message content.", "danger")
                return render_template('dashboard.html', accounts=accounts)
        except Exception as e:
            flash(f"Failed to read messages file: {str(e)}", "danger")
            return render_template('dashboard.html', accounts=accounts)
        credits_needed = len(usernames) * plan_configs[plan]['credits_per_dm']
        if credits < credits_needed:
            flash(f"Insufficient credits. You need {credits_needed} credits to send {len(usernames)} DMs, but you have {credits}.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        cl = get_client(user_id if role != 'admin' else 0, account)
        if not cl:
            flash(f"Cannot send DMs for {account}: Session expired.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        sent_count = 0
        current_timestamp = int(time.time())
        try:
            for username in usernames:
                try:
                    user_id_target = cl.user_id_from_username(username)
                    message = initial_messages[sent_count % len(initial_messages)]
                    cl.direct_send(message, [user_id_target])
                    c = execute_with_retry(c, 
                        'INSERT OR REPLACE INTO initial_dms (account_id, username, sent_timestamp) VALUES (?, ?, ?)',
                        (account_id, username, current_timestamp))
                    sent_count += 1
                    dm_count += 1
                    logging.info(f"Sent initial DM to {username} from {account} (user_id {user_id}): {message}")
                    time.sleep(0.2)
                except Exception as e:
                    logging.error(f"Failed to send DM to {username} from {account}: {str(e)}")
                    flash(f"Failed to send DM to {username}: {str(e)}", "warning")
            c.execute('UPDATE accounts SET has_sent_initial_dms = 1 WHERE id = ?', (account_id,))
            new_credits = credits - (sent_count * plan_configs[plan]['credits_per_dm'])
            c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
            conn.commit()
            session['credits'] = new_credits
            initial_dms_sent = True
            if sent_count > 0:
                flash(f"Sent {sent_count} DMs successfully! {sent_count * plan_configs[plan]['credits_per_dm']} credits deducted. Remaining credits: {new_credits}", "success")
                flash(f"Total DMs sent so far: {dm_count}", "info")
            else:
                flash("No DMs sent.", "info")
        except Exception as e:
            logging.error(f"Error sending DMs: {str(e)}")
            flash(f"Error sending DMs: {str(e)}", "danger")
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', accounts=accounts)

if __name__ == '__main__':
    init_db()
    Thread(target=auto_respond, daemon=True).start()
    app.run(debug=True, host='0.0.0.0', port=5000)
