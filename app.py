import sqlite3
import time
import os
import secrets
import json
from threading import Thread
from instagrapi import Client
from instagrapi.exceptions import ClientError, LoginRequired
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime
import logging
import bcrypt
from functools import wraps
from dotenv import load_dotenv
import random
import re
import tenacity
from sqlite3 import dbapi2 as sqlite
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# Code version for debugging
CODE_VERSION = "3.2.0"  # Updated version for headed Selenium with challenge support

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
logging.info(f"Starting app.py version {CODE_VERSION}")

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

def setup_selenium_driver(proxy_settings=None):
    chrome_options = Options()
    # Headed mode for visibility and manual interaction
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    if proxy_settings and proxy_settings.get('proxy'):
        proxy_url = proxy_settings['proxy'].replace('socks5://', '')
        chrome_options.add_argument(f'--proxy-server={proxy_url}')
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_window_size(1280, 800)  # Set a reasonable window size for visibility
        logging.info(f"Selenium WebDriver initialized in headed mode with proxy: {proxy_settings}")
        return driver
    except WebDriverException as e:
        logging.error(f"Failed to initialize Selenium WebDriver: {str(e)}")
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
    phone_pattern = r'(\+\d{10,15}|\(\d{3}\)\s*\d{3}-\d{4}|\d{3}-\d{3}-\d{4})'
    email_pattern = r'[a-zA-Z0.9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
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
                        c.execute('SELECT MAX(timestamp) FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)',
                                  (thread.id, user_id, username))
                        last_response_timestamp = c.fetchone()[0] or 0
                        current_time = int(time.time())
                        if last_response_timestamp and (current_time - last_response_timestamp) < THREAD_COOLDOWN:
                            logging.debug(f"Thread {thread.id} with {contact_name} is in cooldown (last response at {last_response_timestamp}), skipping")
                            continue
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
        proxy_host = request.form.get('proxy_host')
        proxy_port = request.form.get('proxy_port')
        proxy_username = request.form.get('proxy_username')
        proxy_password = request.form.get('proxy_password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': "Username and password are required."}), 400

        user_info = get_user_info(user_id)
        if not user_info:
            return jsonify({'success': False, 'message': "User not found."}), 404

        plan, credits = user_info
        plan_configs = {
            'plan1': {'max_accounts': 5, 'credits_per_account': 20, 'credits_per_dm': 1},
            'plan2': {'max_accounts': 10, 'credits_per_account': 30, 'credits_per_dm': 1},
            'plan3': {'max_accounts': 15, 'credits_per_account': 34, 'credits_per_dm': 1}
        }
        if not plan or plan not in plan_configs:
            return jsonify({'success': False, 'message': "You must have an active plan to add accounts."}), 403

        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM accounts WHERE user_id = ?', (user_id,))
        current_accounts = c.fetchone()[0]
        if current_accounts >= plan_configs[plan]['max_accounts']:
            return jsonify({'success': False, 'message': f"You have reached the maximum number of accounts ({plan_configs[plan]['max_accounts']}) for your plan."}), 403

        credits_needed = plan_configs[plan]['credits_per_account']
        if credits < credits_needed:
            return jsonify({'success': False, 'message': f"Insufficient credits. You need {credits_needed} credits to add an account, but you have {credits}."}), 403

        # Configure proxy
        proxy_settings = None
        if proxy_host and proxy_port:
            proxy_url = f"socks5://{proxy_host}:{proxy_port}"
            if proxy_username and proxy_password:
                proxy_url = f"socks5://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}"
            proxy_settings = {"proxy": proxy_url}
            logging.info(f"Using proxy for {username}: {proxy_url}")

        session_dir = f"sessions/{user_id}"
        os.makedirs(session_dir, exist_ok=True)
        session_file = f"{session_dir}/session_{username}.json"

        try:
            # Initialize Selenium WebDriver in headed mode
            driver = setup_selenium_driver(proxy_settings)
            driver.get('https://www.instagram.com/accounts/login/')
            
            # Step 1: Enter credentials
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, 'username'))
                )
                driver.find_element(By.NAME, 'username').send_keys(username)
                driver.find_element(By.NAME, 'password').send_keys(password)
                driver.find_element(By.XPATH, '//button[@type="submit"]').click()
                logging.info(f"Submitted login credentials for {username} (user_id {user_id})")
            except TimeoutException:
                driver.quit()
                logging.error(f"Login page elements not found for {username} (user_id {user_id})")
                return jsonify({'success': False, 'message': "Failed to load Instagram login page."}), 500

            # Step 2: Check for 2FA
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, 'verificationCode'))
                )
                logging.info(f"2FA code input detected for {username} (user_id {user_id})")
                session['verification_pending'] = {
                    'username': username,
                    'password': password,
                    'proxy_settings': proxy_settings,
                    'session_file': session_file,
                    'user_id': user_id,
                    'credits': credits,
                    'credits_needed': credits_needed,
                    'selenium_session': {
                        'session_id': driver.session_id,
                        'executor_url': driver.command_executor._url
                    },
                    'type': '2fa',
                    'message': f"Two-factor authentication required for {username}. Please enter the 6-digit code sent to your phone or email.",
                    'timeout': int(time.time()) + 180  # 3 minutes timeout
                }
                logging.info(f"2FA_PROMPT: Enter 2FA code (6 digits) for {username}")
                return jsonify({
                    'success': False,
                    'verification_required': True,
                    'message': session['verification_pending']['message'],
                    'verification_type': '2fa',
                    'username': username
                }), 401
            except TimeoutException:
                logging.debug(f"No 2FA required for {username} at this stage")

            # Step 3: Check for email verification challenge (e.g., verify_email)
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.NAME, 'securityCode'))
                )
                # Attempt to extract the email address from the page
                email_element = None
                try:
                    email_element = driver.find_element(By.XPATH, "//p[contains(text(), '@')]")
                    email_text = email_element.text
                except:
                    email_text = "your email"
                logging.info(f"Email verification challenge detected for {username} (user_id {user_id})")
                session['verification_pending'] = {
                    'username': username,
                    'password': password,
                    'proxy_settings': proxy_settings,
                    'session_file': session_file,
                    'user_id': user_id,
                    'credits': credits,
                    'credits_needed': credits_needed,
                    'selenium_session': {
                        'session_id': driver.session_id,
                        'executor_url': driver.command_executor._url
                    },
                    'type': 'email_verification',
                    'message': f"Instagram requires email verification for {username}. Please enter the 6-digit code sent to {email_text}.",
                    'timeout': int(time.time()) + 180  # 3 minutes timeout
                }
                logging.info(f"EMAIL_VERIFICATION_PROMPT: Enter email verification code (6 digits) for {username}")
                return jsonify({
                    'success': False,
                    'verification_required': True,
                    'message': session['verification_pending']['message'],
                    'verification_type': 'email_verification',
                    'username': username
                }), 401
            except TimeoutException:
                logging.debug(f"No email verification required for {username} at this stage")

            # Step 4: Check if login was successful
            try:
                WebDriverWait(driver, 10).until(
                    EC.url_contains('instagram.com')
                )
                if 'login' not in driver.current_url:
                    logging.info(f"Login successful for {username} (user_id {user_id}) without additional verification")
                    # Initialize instagrapi client to save session
                    cl = Client(request_timeout=15, proxy=proxy_settings["proxy"] if proxy_settings else None)
                    cl.login(username, password)  # Re-login to generate session file
                    cl.dump_settings(session_file)
                    driver.quit()
                else:
                    driver.quit()
                    logging.error(f"Login failed for {username} (user_id {user_id}): Unknown challenge or error")
                    return jsonify({
                        'success': False,
                        'message': "Instagram requires additional verification that cannot be automated. Please resolve manually on the Instagram app.",
                        'username': username
                    }), 401
            except TimeoutException:
                driver.quit()
                logging.error(f"Login failed for {username} (user_id {user_id}): Unknown error")
                return jsonify({'success': False, 'message': "Login failed: Unknown error."}), 400

            # Update database and session
            new_credits = credits - credits_needed
            c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
            c.execute('INSERT OR REPLACE INTO accounts (user_id, username, session_file, needs_reauth, has_sent_initial_dms, proxy_settings) VALUES (?, ?, ?, 0, 0, ?)',
                     (user_id, username, session_file, json.dumps(proxy_settings) if proxy_settings else None))
            conn.commit()
            client_key = f"{user_id}_{username}"
            clients[client_key] = cl
            session['credits'] = new_credits
            session.pop('verification_pending', None)
            logging.info(f"Account {username} added successfully for user_id {user_id}, credits deducted: {credits_needed}, proxy: {proxy_settings}")
            return jsonify({'success': True, 'message': f"Account '{username}' added successfully! {credits_needed} credits deducted. Remaining credits: {new_credits}"})

        except Exception as e:
            if 'driver' in locals():
                driver.quit()
            logging.error(f"Unexpected login error for {username}: {str(e)}")
            return jsonify({'success': False, 'message': f"Unexpected error during login: {str(e)}"}), 500

    return render_template('add_account.html')

@app.route('/verify-code', methods=['POST'])
@login_required
def verify_code():
    user_id = session.get('user_id')
    verification_code = request.form.get('verification_code')

    if not verification_code:
        return jsonify({'success': False, 'message': "Verification code is required."}), 400

    if 'verification_pending' not in session:
        return jsonify({'success': False, 'message': "No pending verification found."}), 400

    pending = session['verification_pending']
    username = pending['username']
    proxy_settings = pending['proxy_settings']
    session_file = pending['session_file']
    credits = pending['credits']
    credits_needed = pending['credits_needed']
    selenium_session = pending['selenium_session']
    verification_type = pending['type']

    # Check for timeout
    current_time = int(time.time())
    if current_time > pending['timeout']:
        try:
            options = Options()
            driver = webdriver.Remote(
                command_executor=selenium_session['executor_url'],
                options=options
            )
            driver.session_id = selenium_session['session_id']
            driver.quit()
        except:
            pass
        session.pop('verification_pending', None)
        logging.error(f"Verification timeout for {username} (user_id {user_id})")
        return jsonify({'success': False, 'message': "Verification timed out. Please try adding the account again."}), 408

    try:
        # Reattach to Selenium session
        options = Options()
        driver = webdriver.Remote(
            command_executor=selenium_session['executor_url'],
            options=options
        )
        driver.session_id = selenium_session['session_id']
        
        # Enter the verification code based on type
        if verification_type == '2fa':
            try:
                code_input = WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.NAME, 'verificationCode'))
                )
                code_input.clear()
                code_input.send_keys(verification_code)
                driver.find_element(By.XPATH, '//button[@type="submit"]').click()
                logging.info(f"Submitted 2FA code for {username} (user_id {user_id})")
            except TimeoutException:
                driver.quit()
                logging.error(f"2FA code input not found for {username} (user_id {user_id})")
                return jsonify({'success': False, 'message': "Failed to submit 2FA code: Input field not found."}), 400
        elif verification_type == 'email_verification':
            try:
                code_input = WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.NAME, 'securityCode'))
                )
                code_input.clear()
                code_input.send_keys(verification_code)
                driver.find_element(By.XPATH, '//button[@type="submit"]').click()
                logging.info(f"Submitted email verification code for {username} (user_id {user_id})")
            except TimeoutException:
                driver.quit()
                logging.error(f"Email verification code input not found for {username} (user_id {user_id})")
                return jsonify({'success': False, 'message': "Failed to submit email verification code: Input field not found."}), 400

        # Check for additional verification steps (e.g., 2FA after email verification)
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, 'verificationCode'))
            )
            logging.info(f"2FA code input detected after email verification for {username} (user_id {user_id})")
            session['verification_pending'] = {
                'username': username,
                'password': pending['password'],
                'proxy_settings': proxy_settings,
                'session_file': session_file,
                'user_id': user_id,
                'credits': credits,
                'credits_needed': credits_needed,
                'selenium_session': {
                    'session_id': driver.session_id,
                    'executor_url': driver.command_executor._url
                },
                'type': '2fa',
                'message': f"Two-factor authentication required for {username}. Please enter the 6-digit code sent to your phone or email.",
                'timeout': int(time.time()) + 180  # 3 minutes timeout
            }
            logging.info(f"2FA_PROMPT: Enter 2FA code (6 digits) for {username} after email verification")
            return jsonify({
                'success': False,
                'verification_required': True,
                'message': session['verification_pending']['message'],
                'verification_type': '2fa',
                'username': username
            }), 401
        except TimeoutException:
            logging.debug(f"No additional 2FA required for {username} after email verification")

        # Verify login success
        try:
            WebDriverWait(driver, 10).until(
                EC.url_contains('instagram.com')
            )
            if 'login' not in driver.current_url:
                logging.info(f"Verification successful for {username} (user_id {user_id})")
                # Initialize instagrapi client
                cl = Client(request_timeout=15, proxy=proxy_settings["proxy"] if proxy_settings else None)
                cl.login(username, pending['password'])  # Re-login to generate session file
                cl.dump_settings(session_file)
                driver.quit()
            else:
                driver.quit()
                logging.error(f"Verification failed for {username} (user_id {user_id}): Invalid code or additional challenge")
                return jsonify({'success': False, 'message': "Invalid verification code or additional challenge required."}), 400
        except TimeoutException:
            driver.quit()
            logging.error(f"Verification failed for {username} (user_id {user_id}): Login not completed")
            return jsonify({'success': False, 'message': "Verification failed: Login not completed."}), 400

        # Update database and session
        conn = db_pool
        c = conn.cursor()
        new_credits = credits - credits_needed
        c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
        c.execute('INSERT OR REPLACE INTO accounts (user_id, username, session_file, needs_reauth, has_sent_initial_dms, proxy_settings) VALUES (?, ?, ?, 0, 0, ?)',
                 (user_id, username, session_file, json.dumps(proxy_settings) if proxy_settings else None))
        conn.commit()

        client_key = f"{user_id}_{username}"
        clients[client_key] = cl
        session['credits'] = new_credits
        session.pop('verification_pending', None)

        logging.info(f"Account {username} added successfully for user_id {user_id}, credits deducted: {credits_needed}, proxy: {proxy_settings}")
        return jsonify({'success': True, 'message': f"Account '{username}' added successfully! {credits_needed} credits deducted. Remaining credits: {new_credits}"})

    except Exception as e:
        if 'driver' in locals():
            driver.quit()
        logging.error(f"Unexpected error during verification for {username}: {str(e)}")
        return jsonify({'success': False, 'message': f"Unexpected error: {str(e)}"}), 500

@app.route('/check-verification-status', methods=['GET'])
@login_required
def check_verification_status():
    logging.debug(f"Checking verification status for session: {session}")
    if 'verification_pending' in session:
        pending = session['verification_pending']
        current_time = int(time.time())
        if current_time > pending['timeout']:
            try:
                options = Options()
                driver = webdriver.Remote(
                    command_executor=pending['selenium_session']['executor_url'],
                    options=options
                )
                driver.session_id = pending['selenium_session']['session_id']
                driver.quit()
            except:
                pass
            session.pop('verification_pending', None)
            logging.error(f"Verification timeout for {pending['username']} (user_id {session.get('user_id')})")
            return jsonify({
                'needs_verification': True,
                'timeout': True,
                'message': "Verification timed out. Please try adding the account again.",
                'username': pending['username']
            })
        logging.info(f"Verification pending for user_id {session.get('user_id')}: {pending}")
        return jsonify({
            'needs_verification': True,
            'type': pending['type'],
            'message': pending['message'],
            'username': pending['username']
        })
    logging.debug(f"No verification pending for user_id {session.get('user_id')}")
    return jsonify({'needs_verification': False})

@app.route('/get-logs', methods=['GET'])
@login_required
def get_logs():
    log_entries = []
    if os.path.exists('crm.log'):
        with open('crm.log', 'r', encoding='utf-8') as log_file:
            log_entries = log_file.readlines()[-20:]  # Last 20 lines
    return jsonify({'logs': log_entries})

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
        try:
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
