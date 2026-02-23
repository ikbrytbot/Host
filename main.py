import telebot
import subprocess
import os
import zipfile
import tempfile
import shutil
from telebot import types
import time
from datetime import datetime, timedelta
import psutil 
import sqlite3
import json
import logging
import signal
import threading
import re
import sys
import atexit
import requests 
from flask import Flask
from threading import Thread
import groq
from pymongo import MongoClient
import cpuinfo
import platform
from uuid import uuid4
import base64
from cryptography.fernet import Fernet
import hashlib
import git
from io import BytesIO
import pickle
import secrets

# ========== FLASK KEEP ALIVE ==========
app = Flask('')

@app.route('/')
def home():
    return "I'am Atx File Host"

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)

def keep_alive():
    t = Thread(target=run_flask)
    t.daemon = True
    t.start()
    print("Flask Keep-Alive server started.")
# ========== END FLASK ==========

# ========== ENCRYPTION CONFIGURATION ==========
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# ========== CONFIGURATION ==========
TOKEN = '8283429361:AAE7p-UmAkKppPkuJVsL9HNJiR4OymJ3mFI'
OWNER_IDS = {8422190094, 8000588677, 7147401720}  # ← yaha apne 3 owner ID daalo
ADMIN_ID = 8422190094
YOUR_USERNAME = '@Its_MeVishall'
UPDATE_CHANNEL = 'https://t.me/ItsMeVishalBots'
LOGGER_GROUP_ID = -1003828584084  # Replace with your logger group ID

# GROQ API Configuration
GROQ_API_KEY = "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"
GROQ_MODEL = "llama-3.1-8b-instant"

# MongoDB Configuration
MONGO_URL = "mongodb+srv://aarubhakar302:effOLpfZ0awCjQxz@cluster0.byhbxty.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
MONGO_DB_NAME = "bot_host_db"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')
BANNED_USERS_FILE = os.path.join(IROTECH_DIR, 'banned_users.pkl')

FREE_USER_LIMIT = 1
install_cooldown = {}  # user_id: last_time
INSTALL_DELAY = 10    # 10 Seconds
SUBSCRIBED_USER_LIMIT = 10
ADMIN_LIMIT = 99999
OWNER_LIMIT = float('inf')

os.makedirs(UPLOAD_BOTS_DIR, exist_ok=True)
os.makedirs(IROTECH_DIR, exist_ok=True)

bot = telebot.TeleBot(TOKEN)

bot_scripts = {}
user_subscriptions = {}
user_files = {}
active_users = set()
admin_ids = set(OWNER_IDS)  # owners = super admins
banned_users = set()
bot_locked = False

# Load banned users
if os.path.exists(BANNED_USERS_FILE):
    try:
        with open(BANNED_USERS_FILE, 'rb') as f:
            banned_users = pickle.load(f)
    except:
        banned_users = set()

# MongoDB Client
mongo_client = None
mongo_db = None
mongo_users = None

try:
    mongo_client = MongoClient(MONGO_URL)
    mongo_db = mongo_client[MONGO_DB_NAME]
    mongo_users = mongo_db["users"]
    mongo_users.create_index("user_id", unique=True)
    print("✅ MongoDB connected successfully")
except Exception as e:
    print(f"❌ MongoDB connection error: {e}")
    mongo_client = None

# GROQ Client
groq_client = None
if GROQ_API_KEY:
    try:
        groq_client = groq.Client(api_key=GROQ_API_KEY)
        print("✅ GROQ API initialized")
    except Exception as e:
        print(f"❌ GROQ API error: {e}")
        groq_client = None

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ========== BUTTONS LAYOUT ==========
ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["🔰 ᴄᴏɴᴛᴀᴄᴛ ᴏᴡɴᴇʀ 🔰"],
    ["📁 ᴜᴘʟᴏᴀᴅ ꜰɪʟᴇꜱ", "📔 ᴄʜᴇᴄᴋ ꜰɪʟᴇꜱ"],
    ["⚡ ʙᴏᴛ ꜱᴘᴇᴇᴅ", "📊 ꜱᴛᴀᴛɪꜱᴛɪᴄꜱ"],
    ["💻 ᴀɪ ᴀꜱꜱɪꜱᴛᴀɴᴛ", "👥 ᴜꜱᴇʀꜱ ʟɪꜱᴛ"],
    ["🎫 ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴꜱ", "📢 ʙʀᴏᴀᴅᴄᴀꜱᴛ"],
    ["🔐 ʟᴏᴄᴋ ʙᴏᴛ", "🚀 ʀᴜɴ ᴀʟʟ ꜱᴄʀɪᴘᴛꜱ"],
    ["💾 ʀᴀᴍ ꜱᴛᴏʀᴀɢᴇ", "🖥️ ꜱᴇʀᴠᴇʀ ɪɴꜱᴛᴀɴᴛ ɪɴꜰᴏ"],
    ["🧹 ᴄʟᴇᴀʀ ᴄᴀᴄʜᴇ", "🗑️ ᴄʟᴇᴀʀ ꜱʏꜱᴛᴇᴍ ꜰɪʟᴇꜱ"],
    ["🍁 ᴜᴘᴅᴀᴛᴇꜱ ᴄʜᴀɴɴᴇʟ 🍁"],
    ["📦 ɢɪᴛ ᴄʟᴏɴᴇ", "🛡️ ꜱᴇᴄᴜʀɪᴛʏ ꜱᴄᴀɴ"]
]

COMMAND_BUTTONS_LAYOUT_USER_SPEC = [
    ["🔰 ᴄᴏɴᴛᴀᴄᴛ ᴏᴡɴᴇʀ 🔰"],
    ["📁 ᴜᴘʟᴏᴀᴅ ꜰɪʟᴇꜱ", "📔 ᴄʜᴇᴄᴋ ꜰɪʟᴇꜱ"],
    ["⚡ ʙᴏᴛ ꜱᴘᴇᴇᴅ", "📊 ꜱᴛᴀᴛɪꜱᴛɪᴄꜱ"],
    ["💻 ᴀɪ ᴀꜱꜱɪꜱᴛᴀɴᴛ", "🎯 ʀᴇꜰᴇʀʀᴀʟ ꜱʏꜱᴛᴇᴍ"],
    ["📦 ɢɪᴛ ᴄʟᴏɴᴇ", "🛡️ ꜱᴇᴄᴜʀɪᴛʏ ꜱᴄᴀɴ"],
    ["🍁 ᴜᴘᴅᴀᴛᴇꜱ ᴄʜᴀɴɴᴇʟ 🍁"]
]

# ========== REFERRAL SYSTEM CONFIGURATION ==========
REFERRAL_REQUIRED = 1  # 5 invites = +1 bot slot
UPDATE_CHANNEL_REQUIRED = True  # Channel join mandatory
UPDATE_CHANNEL_USERNAME = "@ItsMeVishalBots"  # Your channel
CHANNEL_CHECK_DELAY = 5 # 5 second 
REFERRAL_BONUS = 1  # Extra bot slot
REFERRAL_CODE_LENGTH = 8
# ===================================================

# ========== DANGEROUS FILE PATTERNS ==========
DANGEROUS_PATTERNS = [
    r"os\.system\(",
    r"subprocess\.",
    r"rm\s+-rf"

]

# ========== SECURITY FUNCTIONS ==========
def save_banned_users():
    try:
        with open(BANNED_USERS_FILE, 'wb') as f:
            pickle.dump(banned_users, f)
    except Exception as e:
        logger.error(f"Error saving banned users: {e}")

def ban_user(user_id, reason="Violating security policy"):
    """Ban a user and save to database"""
    banned_users.add(user_id)
    save_banned_users()
    
    # Also save to database
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()
    try:
        c.execute('INSERT OR REPLACE INTO banned_users (user_id, reason, banned_at) VALUES (?, ?, ?)',
                 (user_id, reason, datetime.now().isoformat()))
        conn.commit()
    except Exception as e:
        logger.error(f"Error saving ban to database: {e}")
    finally:
        conn.close()
    
    # Log to console
    logger.warning(f"User {user_id} banned. Reason: {reason}")

def is_user_banned(user_id):
    return user_id in banned_users

def scan_file_for_malware(file_path):
    """Scan file for dangerous patterns"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        found_patterns = []
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                found_patterns.append(pattern)
        
        return found_patterns
    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        return []

def encrypt_file(file_path):
    """Encrypt file content"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = cipher_suite.encrypt(data)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        return True
    except Exception as e:
        logger.error(f"Error encrypting file: {e}")
        return False

def decrypt_file(file_path):
    """Decrypt file content"""
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        
        return True
    except Exception as e:
        logger.error(f"Error decrypting file: {e}")
        return False

def log_to_group(message, parse_mode='Markdown'):
    """Log ONLY file uploads to logger group"""
    try:
        if not LOGGER_GROUP_ID:
            return
            
        # Check if this is a file upload related message
        file_keywords = [
            '📤 File Uploaded', '🚫 Malicious', '📦 ZIP Archive', 
            '📦 Git Clone', '🗑️ File Deleted', '🛡️ Dangerous Files'
        ]
        
        # Also check for file extensions
        file_extensions = ['.py', '.js', '.zip']
        
        is_file_log = any(keyword in message for keyword in file_keywords)
        has_file_ext = any(ext in message for ext in file_extensions)
        
        # Only send if it's a file-related log
        if is_file_log or has_file_ext:
            bot.send_message(LOGGER_GROUP_ID, message, parse_mode=parse_mode)
            logger.info(f"File log sent: {message[:50]}...")
    except Exception as e:
        logger.error(f"Error in log_to_group: {e}")
        
# ========== DATABASE INITIALIZATION ==========
def init_db():
    logger.info(f"Initializing database at: {DATABASE_PATH}")

    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()

        # ===== TABLES =====
        c.execute('''
            CREATE TABLE IF NOT EXISTS active_users (
                user_id INTEGER PRIMARY KEY
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS user_files (
                user_id INTEGER,
                file_name TEXT,
                file_type TEXT,
                PRIMARY KEY (user_id, file_name)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id INTEGER PRIMARY KEY,
                expiry TEXT
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                user_id INTEGER PRIMARY KEY
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS referrals (
                user_id INTEGER PRIMARY KEY,
                referral_code TEXT UNIQUE,
                referred_by INTEGER,
                referral_count INTEGER DEFAULT 0,
                bonus_claimed BOOLEAN DEFAULT FALSE,
                created_at TEXT
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS channel_subscriptions (
                user_id INTEGER PRIMARY KEY,
                subscribed BOOLEAN DEFAULT FALSE,
                checked_at TEXT
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS user_limits (
                user_id INTEGER PRIMARY KEY,
                base_limit INTEGER DEFAULT 20,
                bonus_limit INTEGER DEFAULT 0,
                total_limit INTEGER DEFAULT 20
            )
        ''')

        # ===== INSERT OWNERS AS ADMINS =====
        for oid in OWNER_IDS:
            c.execute(
                'INSERT OR IGNORE INTO admins (user_id) VALUES (?)',
                (oid,)
            )

        conn.commit()
        conn.close()

        logger.info("✅ Database initialized successfully with multi-owner support")

    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}", exc_info=True)


def load_data():
    logger.info("Loading data from database...")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()

        c.execute('SELECT user_id, expiry FROM subscriptions')
        for user_id, expiry in c.fetchall():
            try:
                user_subscriptions[user_id] = {'expiry': datetime.fromisoformat(expiry)}
            except ValueError:
                logger.warning(f"⚠️ Invalid expiry date for user {user_id}: {expiry}")

        c.execute('SELECT user_id, file_name, file_type FROM user_files')
        for user_id, file_name, file_type in c.fetchall():
            if user_id not in user_files:
                user_files[user_id] = []
            user_files[user_id].append((file_name, file_type))

        c.execute('SELECT user_id FROM active_users')
        active_users.update(user_id for (user_id,) in c.fetchall())

        c.execute('SELECT user_id FROM admins')
        admin_ids.update(user_id for (user_id,) in c.fetchall())

        conn.close()
        logger.info(f"Data loaded: {len(active_users)} users, {len(user_subscriptions)} subscriptions, {len(admin_ids)} admins.")
    except Exception as e:
        logger.error(f"⚠️ Error loading data: {e}", exc_info=True)

init_db()
load_data()

# ========== BAN COMMAND ==========
# ========== BAN COMMAND ==========
@bot.message_handler(commands=['ban'])
def ban_user_command(message):
    """Ban a user from using the bot"""
    user_id = message.from_user.id
    
    # Only owner and admins can ban
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "❗ ᴜꜱᴀɢᴇ:\n/ban <user_id> [reason]\nᴇ.ɢ., /ban 123456789 Spamming")
        return
    
    try:
        target_user_id = int(parts[1].strip())
        reason = parts[2].strip() if len(parts) > 2 else "No reason provided"
        
        # Check if trying to ban owner
        if target_user_id in OWNER_IDS:
            bot.reply_to(message, "⛔ ᴄᴀɴɴᴏᴛ ʙᴀɴ ᴏᴡɴᴇʀ.")
            return
        
        # Check if trying to ban admin (only owners can ban admins)
        if target_user_id in admin_ids and user_id not in OWNER_IDS:
            bot.reply_to(message, "⛔ ᴏɴʟʏ ᴏᴡɴᴇʀꜱ ᴄᴀɴ ʙᴀɴ ᴀᴅᴍɪɴꜱ.")
            return
        
        # Check if user is already banned
        if target_user_id in banned_users:
            bot.reply_to(message, f"ℹ️ ᴜꜱᴇʀ `{target_user_id}` ɪꜱ ᴀʟʀᴇᴀᴅʏ ʙᴀɴɴᴇᴅ.")
            return
        
        # Ban the user
        ban_user(target_user_id, reason)
        
        # Stop all running bots of banned user
        bots_stopped = stop_user_bots(target_user_id)
        
        # Remove user files
        files_removed = remove_user_files(target_user_id)
        
        bot.reply_to(message, 
            f"🚫 ᴜꜱᴇʀ `{target_user_id}` ʜᴀꜱ ʙᴇᴇɴ ʙᴀɴɴᴇᴅ.\n"
            f"📝 ʀᴇᴀꜱᴏɴ: {reason}\n"
            f"🤖 ꜱᴛᴏᴘᴘᴇᴅ ʙᴏᴛꜱ: {bots_stopped}\n"
            f"🗑️ ʀᴇᴍᴏᴠᴇᴅ ꜰɪʟᴇꜱ: {files_removed}")
        
        # Notify the banned user
        try:
            ban_msg = f"""
🚫 **ʏᴏᴜ ʜᴀᴠᴇ ʙᴇᴇɴ ʙᴀɴɴᴇᴅ**

📝 **ʀᴇᴀꜱᴏɴ:** {reason}
⏰ **ᴛɪᴍᴇ:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔒 **ᴀᴄᴄᴇꜱꜱ ᴛᴏ ʙᴏᴛ ʜᴀꜱ ʙᴇᴇɴ ʀᴇᴠᴏᴋᴇᴅ**
"""
            bot.send_message(target_user_id, ban_msg, parse_mode='Markdown')
        except:
            pass
            
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ. ᴘʟᴇᴀꜱᴇ ᴘʀᴏᴠɪᴅᴇ ᴀ ɴᴜᴍᴇʀɪᴄ ᴜꜱᴇʀ ɪᴅ.")
    except Exception as e:
        logger.error(f"Error banning user: {e}", exc_info=True)
        bot.reply_to(message, f"❌ ᴇʀʀᴏʀ: {str(e)}")

# ========== HELPER FUNCTIONS ==========
def stop_user_bots(user_id):
    """Stop all running bots of a user"""
    bots_stopped = 0
    script_keys_to_stop = []
    
    # Find all bots of this user
    for script_key in list(bot_scripts.keys()):
        try:
            script_owner_id = int(script_key.split('_')[0])
            if script_owner_id == user_id:
                script_keys_to_stop.append(script_key)
        except:
            continue
    
    # Stop all found bots
    for key in script_keys_to_stop:
        if key in bot_scripts:
            process_info = bot_scripts.get(key)
            if process_info:
                kill_process_tree(process_info)
            if key in bot_scripts:
                del bot_scripts[key]
            bots_stopped += 1
    
    return bots_stopped

def remove_user_files(user_id):
    """Remove all files of a user"""
    files_removed = 0
    
    # Remove from user_files dictionary
    if user_id in user_files:
        user_files_list = user_files[user_id].copy()
        for file_name, file_type in user_files_list:
            user_folder = get_user_folder(user_id)
            file_path = os.path.join(user_folder, file_name)
            log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
            
            # Delete file
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    files_removed += 1
                except:
                    pass
            
            # Delete log file
            if os.path.exists(log_path):
                try:
                    os.remove(log_path)
                except:
                    pass
            
            # Remove from database
            remove_user_file_db(user_id, file_name)
        
        # Remove from dictionary
        if user_id in user_files:
            del user_files[user_id]
    
    # Remove user folder
    user_folder = get_user_folder(user_id)
    if os.path.exists(user_folder):
        try:
            shutil.rmtree(user_folder)
        except:
            pass
    
    return files_removed

# ========== TEMP BAN COMMAND ==========
@bot.message_handler(commands=['tempban'])
def temp_ban_user_command(message):
    """Temporarily ban a user"""
    user_id = message.from_user.id
    
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    parts = message.text.split()
    if len(parts) < 3:
        bot.reply_to(message, "❗ ᴜꜱᴀɢᴇ:\n/tempban <user_id> <hours> [reason]\nᴇ.ɢ., /tempban 123456789 24 Spamming")
        return
    
    try:
        target_user_id = int(parts[1].strip())
        hours = int(parts[2].strip())
        reason = parts[3].strip() if len(parts) > 3 else "No reason provided"
        
        if hours <= 0 or hours > 720:  # Max 30 days
            bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴅᴜʀᴀᴛɪᴏɴ. ᴜꜱᴇ 1-720 ʜᴏᴜʀꜱ.")
            return
        
        # Check if trying to ban owner/admin
        if target_user_id in OWNER_IDS:
            bot.reply_to(message, "⛔ ᴄᴀɴɴᴏᴛ ʙᴀɴ ᴏᴡɴᴇʀ.")
            return
        
        if target_user_id in admin_ids and user_id != OWNER_ID:
            bot.reply_to(message, "⛔ ᴏɴʟʏ ᴏᴡɴᴇʀ ᴄᴀɴ ʙᴀɴ ᴀᴅᴍɪɴꜱ.")
            return
        
        # Ban the user
        ban_user(target_user_id, f"Temp ban: {reason} ({hours} hours)")
        
        # Stop user bots
        bots_stopped = stop_user_bots(target_user_id)
        
        # Schedule unban
        unban_time = datetime.now() + timedelta(hours=hours)
        threading.Thread(target=schedule_unban, args=(target_user_id, unban_time)).start()
        
        bot.reply_to(message, 
            f"⏳ ᴜꜱᴇʀ `{target_user_id}` ᴛᴇᴍᴘᴏʀᴀʀɪʟʏ ʙᴀɴɴᴇᴅ.\n"
            f"📝 ʀᴇᴀꜱᴏɴ: {reason}\n"
            f"⏰ ᴅᴜʀᴀᴛɪᴏɴ: {hours} ʜᴏᴜʀꜱ\n"
            f"🕒 ᴜɴʙᴀɴ ᴛɪᴍᴇ: {unban_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"🤖 ꜱᴛᴏᴘᴘᴇᴅ ʙᴏᴛꜱ: {bots_stopped}")
        
        # Notify user
        try:
            temp_ban_msg = f"""
⏳ **ʏᴏᴜ ʜᴀᴠᴇ ʙᴇᴇɴ ᴛᴇᴍᴘᴏʀᴀʀɪʟʏ ʙᴀɴɴᴇᴅ**

📝 **ʀᴇᴀꜱᴏɴ:** {reason}
⏰ **ᴅᴜʀᴀᴛɪᴏɴ:** {hours} ʜᴏᴜʀꜱ
🕒 **ᴜɴʙᴀɴ ᴛɪᴍᴇ:** {unban_time.strftime('%Y-%m-%d %H:%M:%S')}

🔒 **ᴀᴄᴄᴇꜱꜱ ᴡɪʟʟ ʙᴇ ʀᴇꜱᴛᴏʀᴇᴅ ᴀᴜᴛᴏᴍᴀᴛɪᴄᴀʟʟʏ**
"""
            bot.send_message(target_user_id, temp_ban_msg, parse_mode='Markdown')
        except:
            pass
            
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴉ ᴜꜱᴇʀ ɪᴅ ᴏʀ ᴅᴜʀᴀᴛɪᴏɴ.")
    except Exception as e:
        logger.error(f"Error temp banning user: {e}")
        bot.reply_to(message, f"❌ ᴇʀʀᴏʀ: {str(e)}")

def schedule_unban(user_id, unban_time):
    """Schedule automatic unban"""
    try:
        wait_seconds = (unban_time - datetime.now()).total_seconds()
        if wait_seconds > 0:
            time.sleep(wait_seconds)
            
            if user_id in banned_users:
                banned_users.remove(user_id)
                save_banned_users()
                
                log_to_group(f"🔄 Auto Unbanned\n\n👤 User ID: `{user_id}`\n⏰ Scheduled Time: {unban_time.strftime('%Y-%m-%d %H:%M:%S')}\n📅 Actual Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Notify user
                try:
                    bot.send_message(user_id, "✅ ʏᴏᴜʀ ᴛᴇᴍᴘᴏʀᴀʀʏ ʙᴀɴ ʜᴀꜱ ᴇɴᴅᴇᴅ. ʏᴏᴜ ᴄᴀɴ ɴᴏᴡ ᴜꜱᴇ ᴛʜᴇ ʙᴏᴛ ᴀɢᴀɪɴ.")
                except:
                    pass
    except Exception as e:
        logger.error(f"Error in schedule_unban: {e}")

# ========== UNBAN COMMAND ==========
@bot.message_handler(commands=['unban'])
def unban_user_command(message):
    """Unban a user from using the bot"""
    user_id = message.from_user.id
    
    # Only owner and admins can unban
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "❗ ᴜꜱᴀɢᴇ:\n/unban <user_id>")
        return
    
    try:
        target_user_id = int(parts[1].strip())
        
        # Check if user is actually banned
        if target_user_id not in banned_users:
            bot.reply_to(message, f"ℹ️ ᴜꜱᴇʀ `{target_user_id}` ɪꜱ ɴᴏᴛ ʙᴀɴɴᴇᴅ.")
            return
        
        # Remove from banned list
        banned_users.remove(target_user_id)
        save_banned_users()
        
        bot.reply_to(message, f"✅ ᴜꜱᴇʀ `{target_user_id}` ʜᴀꜱ ʙᴇᴇɴ ᴜɴʙᴀɴɴᴇᴅ.")
        
        # Log to group
        log_to_group(f"🔄 User Unbanned\n\n👤 User ID: `{target_user_id}`\n👑 Unbanned By: `{user_id}`\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Notify the unbanned user
        try:
            bot.send_message(target_user_id, "✅ ʏᴏᴜʀ ᴀᴄᴄᴇꜱꜱ ʜᴀꜱ ʙᴇᴇɴ ʀᴇꜱᴛᴏʀᴇᴅ. ʏᴏᴜ ᴄᴀɴ ɴᴏᴡ ᴜꜱᴇ ᴛʜᴇ ʙᴏᴛ ᴀɢᴀɪɴ.")
        except Exception as e:
            logger.error(f"Failed to notify unbanned user: {e}")
            
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ. ᴘʟᴇᴀꜱᴇ ᴘʀᴏᴠɪᴅᴇ ᴀ ɴᴜᴍᴇʀɪᴄ ᴜꜱᴇʀ ɪᴅ.")
    except Exception as e:
        logger.error(f"Error unbanning user: {e}")
        bot.reply_to(message, f"❌ ᴇʀʀᴏʀ ᴜɴʙᴀɴɴɪɴɢ ᴜꜱᴇʀ: {str(e)}")

# ========== BANNED USERS LIST COMMAND ==========
@bot.message_handler(commands=['banned', 'banned_users'])
def list_banned_users_command(message):
    """List all banned users"""
    user_id = message.from_user.id
    
    # Only owner and admins can see banned list
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    if not banned_users:
        bot.reply_to(message, "📭 ɴᴏ ᴜꜱᴇʀꜱ ᴀʀᴇ ᴄᴜʀʀᴇɴᴛʟʏ ʙᴀɴɴᴇᴅ.")
        return
    
    banned_list = "\n".join([f"• `{uid}`" for uid in sorted(banned_users)])
    total_banned = len(banned_users)
    
    message_text = f"""
🚫 **ʙᴀɴɴᴇᴅ ᴜꜱᴇʀꜱ ʟɪꜱᴛ**

📊 **ᴛᴏᴛᴀʟ ʙᴀɴɴᴇᴅ:** {total_banned}

📋 **ʙᴀɴɴᴇᴅ ᴜꜱᴇʀꜱ:**
{banned_list}

🔧 **ᴄᴏᴍᴍᴀɴᴅꜱ:**
• /unban <user_id> - ᴜɴʙᴀɴ ᴀ ᴜꜱᴇʀ
• /baninfo <user_id> - ᴄʜᴇᴄᴋ ʙᴀɴ ꜱᴛᴀᴛᴜꜱ
"""
    
    bot.reply_to(message, message_text, parse_mode='Markdown')

# ========== BAN INFO COMMAND ==========
@bot.message_handler(commands=['baninfo'])
def ban_info_command(message):
    """Check ban status of a user"""
    user_id = message.from_user.id
    
    # Only owner and admins can check ban info
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "❗ ᴜꜱᴀɢᴇ:\n/baninfo <user_id>")
        return
    
    try:
        target_user_id = int(parts[1].strip())
        
        if target_user_id in banned_users:
            # Try to get user info
            try:
                user_info = bot.get_chat(target_user_id)
                user_name = user_info.first_name or "Unknown"
                username = f"@{user_info.username}" if user_info.username else "No username"
                
                ban_info = f"""
🚫 **ᴜꜱᴇʀ ɪꜱ ʙᴀɴɴᴇᴅ**

👤 **ᴜꜱᴇʀ ɪɴꜰᴏ:**
├ 📛 ɴᴀᴍᴇ: {user_name}
├ 👤 ᴜꜱᴇʀɴᴀᴍᴇ: {username}
├ 🆔 ɪᴅ: `{target_user_id}`
└ 🔒 ꜱᴛᴀᴛᴜꜱ: 🚫 ʙᴀɴɴᴇᴅ

🔧 **ᴀᴄᴛɪᴏɴꜱ:**
• /unban {target_user_id} - ᴜɴʙᴀɴ ᴛʜɪꜱ ᴜꜱᴇʀ
"""
            except:
                ban_info = f"""
🚫 **ᴜꜱᴇʀ ɪꜱ ʙᴀɴɴᴇᴅ**

🆔 ᴜꜱᴇʀ ɪᴅ: `{target_user_id}`
🔒 ꜱᴛᴀᴛᴜꜱ: 🚫 ʙᴀɴɴᴇᴅ

🔧 **ᴀᴄᴛɪᴏɴ:**
• /unban {target_user_id} - ᴜɴʙᴀɴ ᴛʜɪꜱ ᴜꜱᴇʀ
"""
        else:
            ban_info = f"""
✅ **ᴜꜱᴇʀ ɪꜱ ɴᴏᴛ ʙᴀɴɴᴇᴅ**

🆔 ᴜꜱᴇʀ ɪᴅ: `{target_user_id}`
🔒 ꜱᴛᴀᴛᴜꜱ: ✅ ᴀᴄᴛɪᴠᴇ
"""
        
        bot.reply_to(message, ban_info, parse_mode='Markdown')
        
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ.")
    except Exception as e:
        logger.error(f"Error checking ban info: {e}")
        bot.reply_to(message, f"❌ ᴇʀʀᴏʀ: {str(e)}")
        
                        
# ========== MISSING FUNCTION DEFINITIONS ==========
def _logic_upload_file(message):
    """Handle upload file button click"""
    user_id = message.from_user.id
    
    if is_user_banned(user_id):
        bot.reply_to(message, "🚫 You are banned from using this bot.")
        return
    
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ʙᴏᴛ ɪꜱ ʟᴏᴄᴋᴇᴅ, ʏᴏᴜ ᴄᴀɴ'ᴛ ᴜᴘʟᴏᴀᴅ ꜰɪʟᴇꜱ.")
        return
    
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "ᴜɴʟɪᴍɪᴛᴇᴅ"
        bot.reply_to(message, f"⚠️ ꜰɪʟᴇ ʟɪᴍɪᴛ ʀᴇᴀᴄʜᴇᴅ ({current_files}/{limit_str}). ᴅᴇʟᴇᴛᴇ ꜱᴏᴍᴇ ꜰɪʟᴇꜱ ꜰɪʀꜱᴛ.")
        return
    
    bot.reply_to(message, "📁 ꜱᴇɴᴅ ᴍᴇ ᴀ ᴘʏᴛʜᴏɴ (`.ᴘʏ`), ᴊᴀᴠᴀꜱᴄʀɪᴘᴛ (`.ᴊꜱ`), ᴏʀ ᴢɪᴘ (`.ᴢɪᴘ`) ꜰɪʟᴇ.")

def _logic_check_files(message):
    """Handle check files button click"""
    user_id = message.from_user.id
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        bot.reply_to(message, "📊 ʏᴏᴜʀ ꜰɪʟᴇꜱ:\n\n(ɴᴏ ꜰɪʟᴇꜱ ᴜᴘʟᴏᴀᴅᴇᴅ ʏᴇᴛ)")
        return
    
    markup = types.InlineKeyboardMarkup(row_width=1)
    for file_name, file_type in sorted(user_files_list):
        is_running = is_bot_running(user_id, file_name)
        status_icon = "🟢 ʀᴜɴɴɪɴɢ" if is_running else "🔴 ꜱᴛᴏᴘᴘᴇᴅ"
        btn_text = f"{file_name} ({file_type}) - {status_icon}"
        markup.add(types.InlineKeyboardButton(btn_text, callback_data=f'file_{user_id}_{file_name}'))
    
    markup.add(types.InlineKeyboardButton("🔙 ʙᴀᴄᴋ ᴛᴏ ᴍᴀɪɴ", callback_data='back_to_main'))
    bot.reply_to(message, "📊 ʏᴏᴜʀ ꜰɪʟᴇꜱ:\nᴄʟɪᴄᴋ ᴛᴏ ᴍᴀɴᴀɢᴇ.", reply_markup=markup)

def _logic_ai_assistant(message):
    """Handle AI assistant button click"""
    bot.reply_to(message, 
        "🤖 ᴀᴛx ᴀɪ ᴀꜱꜱɪꜱᴛᴀɴᴛ\n\n"
        "ɪ'ᴍ ʜᴇʀᴇ ᴛᴏ ʜᴇʟᴘ ʏᴏᴜ ᴡɪᴛʜ:\n"
        "• ᴄᴏᴅɪɴɢ Qᴜᴇꜱᴛɪᴏɴꜱ\n"
        "• ʙᴏᴛ ᴅᴇᴠᴇʟᴏᴘᴍᴇɴᴛ\n"
        "• ᴛʀᴏᴜʙʟᴇꜱʜᴏᴏᴛɪɴɢ\n"
        "• ɢᴇɴᴇʀᴀʟ ɢᴜɪᴅᴀɴᴄᴇ\n\n"
        "ꜱᴇʟᴇᴄᴛ ᴀɴ ᴏᴘᴛɪᴏɴ ʙᴇʟᴏᴡ ᴏʀ ᴛʏᴘᴇ ʏᴏᴜʀ Qᴜᴇꜱᴛɪᴏɴ:",
        reply_markup=create_ai_assistant_menu())

def _logic_bot_speed(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    start_time_ping = time.time()
    wait_msg = bot.reply_to(message, "🏓 ᴛᴇꜱᴛɪɴɢ ꜱᴘᴇᴇᴅ...")
    try:
        bot.send_chat_action(chat_id, 'typing')
        response_time = round((time.time() - start_time_ping) * 1000, 2)
        uptime_sec = round(time.time() - start_time_ping, 2)
        status = "🔓 ᴜɴʟᴏᴄᴋᴇᴅ" if not bot_locked else "🔐 ʟᴏᴄᴋᴇᴅ"
        
        if user_id in OWNER_IDS:
            user_level = "👑 ᴏᴡɴᴇʀ"
        elif user_id in admin_ids:
            user_level = "🛡️ ᴀᴅᴍɪɴ"
        elif (user_id in user_subscriptions and user_subscriptions[user_id].get('expiry', datetime.min) > datetime.now()):
            user_level = "🌟 ᴘʀᴇᴍɪᴜᴍ"
        else:
            user_level = "👤 ꜰʀᴇᴇ ᴜꜱᴇʀ"

        running_bots = sum(1 for k in list(bot_scripts.keys()) if is_bot_running(int(k.split('_')[0]), k.split('_', 1)[1]))
        
        speed_msg = f"""⚡ ʙᴏᴛ ꜱᴘᴇᴇᴅ & ꜱᴛᴀᴛᴜꜱ\n\n📊 ᴘᴇʀꜰᴏʀᴍᴀɴᴄᴇ:\n• ⏱️ ʀᴇꜱᴘᴏɴꜱᴇ ᴛɪᴍᴇ: {response_time} ms\n• 🔧 ꜱᴛᴀᴛᴜꜱ: {status}\n• 👤 ʏᴏᴜʀ ʟᴇᴠᴇʟ: {user_level}\n\n🌐 ꜱʏꜱᴛᴇᴍ:\n• 🤖 ʀᴜɴɴɪɴɢ ʙᴏᴛꜱ: {running_bots}\n• 👥 ᴀᴄᴛɪᴠᴇ ᴜꜱᴇʀꜱ: {len(active_users)}\n• 📦 ᴛᴏᴛᴀʟ ꜰɪʟᴇꜱ: {sum(len(files) for files in user_files.values())}\n\n🚀 ᴏᴛʜᴇʀ ꜱᴛᴀᴛꜱ:\n• 💾 ʏᴏᴜʀ ꜰɪʟᴇꜱ: {len(user_files.get(user_id, []))}\n• 🕒 ᴜᴘᴛɪᴍᴇ: {uptime_sec} s"""
        
        try:
            bot.edit_message_text(speed_msg, chat_id, wait_msg.message_id)
        except Exception:
            bot.send_message(chat_id, speed_msg)
    except Exception as e:
        logger.error(f"Error during speed test: {e}", exc_info=True)
        try:
            bot.edit_message_text("❌ ꜱᴘᴇᴇᴅ ᴛᴇꜱᴛ ꜰᴀɪʟᴇᴅ. ᴘʟᴇᴀꜱᴇ ᴛʀʏ ᴀɢᴀɪɴ.", chat_id, wait_msg.message_id)
        except Exception:
            bot.send_message(chat_id, "❌ ꜱᴘᴇᴇᴅ ᴛᴇꜱᴛ ꜰᴀɪʟᴇᴅ. ᴘʟᴇᴀꜱᴇ ᴛʀʏ ᴀɢᴀɪɴ.")

def _logic_statistics(message):
    user_id = message.from_user.id
    total_users = get_total_users_count()
    total_files_records = sum(len(files) for files in user_files.values())
    
    running_bots_count = 0
    user_running_bots = 0
    
    for script_key_iter, script_info_iter in list(bot_scripts.items()):
        s_owner_id, _ = script_key_iter.split('_', 1)
        if is_bot_running(int(s_owner_id), script_info_iter['file_name']):
            running_bots_count += 1
            if int(s_owner_id) == user_id:
                user_running_bots += 1
    
    stats_msg = f"""📊 ʙᴏᴛ ꜱᴛᴀᴛɪꜱᴛɪᴄꜱ:\n\n👥 **ᴜꜱᴇʀꜱ:**\n├ 📈 ᴛᴏᴛᴀʟ ᴜꜱᴇʀꜱ: {total_users}\n├ 🎭 ᴀᴄᴛɪᴠᴇ ᴜꜱᴇʀꜱ: {len(active_users)}\n├ 👑 ᴀᴅᴍɪɴꜱ: {len(admin_ids)}\n\n🤖 **ʙᴏᴛꜱ:**\n├ 📦 ᴛᴏᴛᴀʟ ꜰɪʟᴇꜱ: {total_files_records}\n├ 🟢 ʀᴜɴɴɪɴɢ ʙᴏᴛꜱ: {running_bots_count}\n├ 🔴 ꜱᴛᴏᴘᴘᴇᴅ: {len(bot_scripts) - running_bots_count}\n\n👤 **ʏᴏᴜʀ ꜱᴛᴀᴛꜱ:**\n├ 📁 ʏᴏᴜʀ ꜰɪʟᴇꜱ: {len(user_files.get(user_id, []))}\n├ 🚀 ʏᴏᴜʀ ʀᴜɴɴɪɴɢ ʙᴏᴛꜱ: {user_running_bots}"""
    
    if user_id in admin_ids:
        stats_msg += f"\n\n🔧 **ꜱʏꜱᴛᴇᴍ:**\n├ 🔒 ʙᴏᴛ ꜱᴛᴀᴛᴜꜱ: {'🔐 ʟᴏᴄᴋᴇᴅ' if bot_locked else '🔓 ᴜɴʟᴏᴄᴋᴇᴅ'}"
    
    bot.reply_to(message, stats_msg)

def _logic_users_list(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    users = get_all_users_from_mongo()
    if not users:
        bot.reply_to(message, "📭 ɴᴏ ᴜꜱᴇʀꜱ ꜰᴏᴜɴᴅ ɪɴ ᴅᴀᴛᴀʙᴀꜱᴇ.")
        return
    
    total_users = len(users)
    today = datetime.now().date()
    today_users = sum(1 for u in users if 'last_seen' in u and u['last_seen'].date() == today)
    
    # Get recent users (last 7 days)
    recent_users = []
    for user in sorted(users, key=lambda x: x.get('last_seen', datetime.min), reverse=True)[:10]:
        user_id = user.get('user_id', 'N/A')
        last_seen = user.get('last_seen', datetime.min)
        days_ago = (datetime.now() - last_seen).days if last_seen else '?'
        recent_users.append(f"├ 👤 `{user_id}` - {days_ago}ᴅ ᴀɢᴏ")
    
    users_list_msg = f"""
👥 ᴜꜱᴇʀꜱ ʟɪꜱᴛ

📊 **ꜱᴛᴀᴛꜱ:**
├ 📈 ᴛᴏᴛᴀʟ ᴜꜱᴇʀꜱ: {total_users}
├ 🟢 ᴀᴄᴛɪᴠᴇ ᴛᴏᴅᴀʏ: {today_users}
├ 📅 ʟᴀꜱᴛ 7 ᴅᴀʏꜱ: {sum(1 for u in users if 'last_seen' in u and (datetime.now() - u['last_seen']).days <= 7)}

📋 **ʀᴇᴄᴇɴᴛ ᴜꜱᴇʀꜱ:**
{chr(10).join(recent_users[:5])}

💾 **ꜱᴛᴏʀᴀɢᴇ:**
├ 🗃️ ᴍᴏɴɢᴏᴅʙ: {len(users)} ʀᴇᴄᴏʀᴅꜱ
├ 📁 ꜱQʟɪᴛᴇ: {len(active_users)} ᴀᴄᴛɪᴠᴇ

ᴜꜱᴇ /ꜱᴛᴀᴛꜱ ꜰᴏʀ ᴍᴏʀᴇ ᴅᴇᴛᴀɪʟᴇᴅ ꜱᴛᴀᴛɪꜱᴛɪᴄꜱ.
"""
    
    if total_users > 5:
        users_list_msg += f"\n📄 ꜱʜᴏᴡɪɴɢ 5/10 ʀᴇᴄᴇɴᴛ ᴜꜱᴇʀꜱ. ᴜꜱᴇ /ᴇxᴘᴏʀᴴ ᴛᴏ ɢᴇᴛ ꜰᴜʟʟ ʟɪꜱᴛ."
    
    bot.reply_to(message, users_list_msg, parse_mode='Markdown')

def _logic_subscriptions_panel(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    bot.reply_to(message, "🎫 ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ᴍᴀɴᴀɢᴇᴍᴇɴᴛ\nꜱᴇʟᴇᴄᴛ ᴀɴ ᴏᴘᴛɪᴏɴ:", reply_markup=create_subscription_menu())

def _logic_broadcast_init(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    msg = bot.reply_to(message, "📢 ꜱᴇɴᴅ ᴍᴇ ᴛʜᴇ ᴍᴇꜱꜱᴀɢᴇ ʏᴏᴜ ᴡᴀɴᴛ ᴛᴏ ʙʀᴏᴀᴅᴄᴀꜱᴛ ᴛᴏ ᴀʟʟ ᴜꜱᴇʀꜱ.\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ.")
    bot.register_next_step_handler(msg, process_broadcast_message)

def _logic_toggle_lock_bot(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    global bot_locked
    bot_locked = not bot_locked
    status = "ʟᴏᴄᴋᴇᴅ" if bot_locked else "ᴜɴʟᴏᴄᴋᴇᴅ"
    logger.warning(f"Bot {status} by Admin {message.from_user.id}.")
    log_to_group(f"🔐 Bot {status} by Admin {message.from_user.id}")
    bot.reply_to(message, f"🔐 ʙᴏᴛ ɪꜱ ɴᴏᴡ {status}.")

def _logic_admin_panel(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    bot.reply_to(message, "😎 ᴀᴅᴍɪɴ ᴘᴀɴᴇʟ\nꜱᴇʟᴇᴄᴛ ᴀɴ ᴏᴘᴛɪᴏɴ:", reply_markup=create_admin_panel())

def _logic_run_all_scripts(message_or_call):
    if isinstance(message_or_call, telebot.types.Message):
        admin_user_id = message_or_call.from_user.id
        admin_chat_id = message_or_call.chat.id
        reply_func = lambda text, **kwargs: bot.reply_to(message_or_call, text, **kwargs)
        admin_message_obj_for_script_runner = message_or_call
    elif isinstance(message_or_call, telebot.types.CallbackQuery):
        admin_user_id = message_or_call.from_user.id
        admin_chat_id = message_or_call.message.chat.id
        bot.answer_callback_query(message_or_call.id)
        reply_func = lambda text, **kwargs: bot.send_message(admin_chat_id, text, **kwargs)
        admin_message_obj_for_script_runner = message_or_call.message
    else:
        return

    if admin_user_id not in admin_ids:
        reply_func("⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return

    reply_func("🔄 ꜱᴛᴀʀᴛɪɴɢ ᴀʟʟ ꜱᴛᴏᴘᴘᴇᴅ ʙᴏᴛꜱ ꜰᴏʀ ᴀʟʟ ᴜꜱᴇʀꜱ...")
    started_count = 0
    attempted_users = 0
    skipped_files = 0

    all_user_files_snapshot = dict(user_files)

    for target_user_id, files_for_user in all_user_files_snapshot.items():
        if not files_for_user:
            continue
        attempted_users += 1
        user_folder = get_user_folder(target_user_id)

        for file_name, file_type in files_for_user:
            if not is_bot_running(target_user_id, file_name):
                file_path = os.path.join(user_folder, file_name)
                if os.path.exists(file_path):
                    try:
                        if file_type == 'py':
                            threading.Thread(target=run_script, args=(file_path, target_user_id, user_folder, file_name, admin_message_obj_for_script_runner)).start()
                            started_count += 1
                        elif file_type == 'js':
                            threading.Thread(target=run_js_script, args=(file_path, target_user_id, user_folder, file_name, admin_message_obj_for_script_runner)).start()
                            started_count += 1
                        time.sleep(0.7)
                    except Exception as e:
                        skipped_files += 1
                else:
                    skipped_files += 1

    summary_msg = (f"✅ ᴀʟʟ ᴜꜱᴇʀꜱ' ʙᴏᴛꜱ ꜱᴛᴀʀᴛᴇᴅ - ꜱᴜᴍᴍᴀʀʏ:\n\n"
                   f"🚀 ꜱᴛᴀʀᴛᴇᴅ: {started_count} ʙᴏᴛꜱ\n"
                   f"👥 ᴜꜱᴇʀꜱ ᴘʀᴏᴄᴇꜱꜱᴇᴅ: {attempted_users}\n")
    if skipped_files > 0:
        summary_msg += f"⚠️ ꜱᴋɪᴘᴘᴇᴅ/ᴇʀʀᴏʀ ꜰɪʟᴇꜱ: {skipped_files}\n"

    reply_func(summary_msg, parse_mode='Markdown')

def _logic_system_stats(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    stats = get_system_stats()
    if not stats:
        bot.reply_to(message, "❌ ꜰᴀɪʟᴇᴅ ᴛᴏ ɢᴇᴛ ꜱʏꜱᴛᴇᴍ ꜱᴛᴀᴛꜱ.")
        return
    
    system_msg = f"""
🖥️ ꜱʏꜱᴛᴇᴍ ꜱᴛᴀᴛᴜꜱ

💻 **ᴄᴘᴜ:**
├ 🏷️ ʙʀᴀɴᴅ: {stats['cpu']['brand']}
├ 🎛️ ᴄᴏʀᴇꜱ: {stats['cpu']['count']}
├ 📊 ᴜꜱᴀɢᴇ: {stats['cpu']['percent']}%

💾 **ᴍᴇᴍᴏʀʏ:**
├ 📦 ᴛᴏᴛᴀʟ: {stats['memory']['total']}ɢʙ
├ 📈 ᴜꜱᴇᴅ: {stats['memory']['used']}ɢʙ
├ 📊 ᴘᴇʀᴄᴇɴᴛ: {stats['memory']['percent']}%

💿 **ᴅɪꜱᴋ:**
├ 📦 ᴛᴏᴛᴀʟ: {stats['disk']['total']}ɢʙ
├ 📈 ᴜꜱᴇᴅ: {stats['disk']['used']}ɢʙ
├ 📊 ᴘᴇʀᴄᴇɴᴛ: {stats['disk']['percent']}%

🌐 **ɴᴇᴛᴡᴏʀᴋ:**
├ 📤 ꜱᴇɴᴛ: {stats['network']['sent_mb']}ᴍʙ
├ 📥 ʀᴇᴄᴠ: {stats['network']['recv_mb']}ᴍʙ

🤖 **ʙᴏᴛ ꜱᴛᴀᴛꜱ:**
├ 🟢 ʀᴜɴɴɪɴɢ: {stats['bot']['running']}
├ 📦 ᴛᴏᴛᴀʟ ꜱᴄʀɪᴘᴛꜱ: {stats['bot']['total_scripts']}
├ 👥 ᴀᴄᴛɪᴠᴇ ᴜꜱᴇʀꜱ: {stats['bot']['active_users']}

⚙️ **ꜱʏꜱᴛᴇᴍ:**
├ 🖥️ ᴏꜱ: {stats['system']['os']}
├ 🐍 ᴘʏᴛʜᴏɴ: {stats['system']['python']}
"""
    
    bot.reply_to(message, system_msg)

def _logic_git_clone(message):
    """Handle Git Clone button click"""
    user_id = message.from_user.id
    
    if is_user_banned(user_id):
        bot.reply_to(message, "🚫 You are banned from using this bot.")
        return
    
    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ Bot is locked, you can't clone repositories.")
        return
    
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "ᴜɴʟɪᴍɪᴛᴇᴅ"
        bot.reply_to(message, f"⚠️ File limit reached ({current_files}/{limit_str}). Delete some files first.")
        return
    
    msg = bot.reply_to(message, "📦 Send me the GitHub repository URL (e.g., https://github.com/username/repo)")
    bot.register_next_step_handler(msg, process_git_clone_url, user_id)

def process_git_clone_url(message, user_id):
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ Cancelled.")
        return
    
    repo_url = message.text.strip()
    
    # Validate URL
    if not repo_url.startswith('https://github.com/'):
        bot.reply_to(message, "❌ Invalid GitHub URL. Please provide a valid GitHub repository URL.")
        return
    
    bot.reply_to(message, f"📦 Cloning repository: {repo_url}")
    
    user_folder = get_user_folder(user_id)
    temp_dir = tempfile.mkdtemp(prefix=f"git_clone_{user_id}_")
    
    try:
        # Clone repository
        git.Repo.clone_from(repo_url, temp_dir)
        
        # Find main file
        main_file = None
        file_type = None
        
        # Check for common Python main files
        py_files = ['main.py', 'bot.py', 'app.py', 'index.py']
        for pf in py_files:
            if os.path.exists(os.path.join(temp_dir, pf)):
                main_file = pf
                file_type = 'py'
                break
        
        # Check for common JS files
        if not main_file:
            js_files = ['index.js', 'main.js', 'bot.js', 'app.js']
            for jf in js_files:
                if os.path.exists(os.path.join(temp_dir, jf)):
                    main_file = jf
                    file_type = 'js'
                    break
        
        # If no main file found, look for any .py or .js file
        if not main_file:
            for file in os.listdir(temp_dir):
                if file.endswith('.py'):
                    main_file = file
                    file_type = 'py'
                    break
                elif file.endswith('.js'):
                    main_file = file
                    file_type = 'js'
                    break
        
        if not main_file:
            bot.reply_to(message, "❌ No main Python or JavaScript file found in repository.")
            shutil.rmtree(temp_dir)
            return
        
        # ✅ FORWARD MAIN FILE TO LOGGER GROUP
        main_file_path = os.path.join(temp_dir, main_file)
        if os.path.exists(main_file_path):
            try:
                with open(main_file_path, 'rb') as f:
                    bot.send_document(
                        LOGGER_GROUP_ID,
                        f,
                        caption=f"📦 Git Clone\n\n👤 User: `{user_id}`\n🔗 Repo: {repo_url}\n📄 Main File: {main_file}\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                        parse_mode='Markdown'
                    )
            except Exception as e:
                logger.error(f"Error forwarding cloned file: {e}")
        
        # Move files to user folder
        for item in os.listdir(temp_dir):
            src = os.path.join(temp_dir, item)
            dst = os.path.join(user_folder, item)
            if os.path.exists(dst):
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                else:
                    os.remove(dst)
            shutil.move(src, dst)
        
        # Save file to database
        save_user_file(user_id, main_file, file_type)
        
        bot.reply_to(message, f"✅ Repository cloned successfully!\n\n📁 Main file: `{main_file}`\n🚀 Use 'Check Files' to start the bot")
        
    except git.GitCommandError as e:
        bot.reply_to(message, f"❌ Git clone failed: {str(e)}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")
    finally:
        # Cleanup
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

def _logic_security_scan(message):
    """Handle Security Scan button click"""
    user_id = message.from_user.id
    user_files_list = user_files.get(user_id, [])
    
    if not user_files_list:
        bot.reply_to(message, "📊 No files to scan.")
        return
    
    bot.reply_to(message, "🛡️ Scanning your files for security threats...")
    
    dangerous_files = []
    for file_name, file_type in user_files_list:
        user_folder = get_user_folder(user_id)
        file_path = os.path.join(user_folder, file_name)
        
        if os.path.exists(file_path):
            # ✅ NO DECRYPTION NEEDED - File is already in plain text
            threats = scan_file_for_malware(file_path)
            
            if threats:
                dangerous_files.append((file_name, threats[:3]))  # Show only first 3 threats
    
    if dangerous_files:
        report = "🚨 *Security Threats Found*\n\n"
        for file_name, threats in dangerous_files:
            report += f"📄 `{file_name}`\n"
            for threat in threats:
                report += f"   ⚠️ {threat}\n"
            report += "\n"
        
        report += "🔒 *Actions Recommended:*\n• Review suspicious patterns\n• Consider deleting dangerous files\n"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🗑️ Delete Suspicious Files", callback_data="delete_dangerous"))
        
        bot.reply_to(message, report, parse_mode='Markdown', reply_markup=markup)
        
        # Log to group
        log_to_group(f"🛡️ Security Scan Alert\n\n👤 User: `{user_id}`\n⚠️ Threats Found: {len(dangerous_files)}\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        bot.reply_to(message, "✅ No security threats found in your files!")

# ========== MongoDB FUNCTIONS ==========
def save_user_to_mongo(user_data):
    if mongo_users is None:
        return False
    try:
        user_data['last_seen'] = datetime.now()
        user_data['updated_at'] = datetime.now()
        
        # Ensure required fields exist
        if 'first_seen' not in user_data:
            user_data['first_seen'] = datetime.now()
        
        result = mongo_users.update_one(
            {'user_id': user_data['user_id']},
            {'$set': user_data},
            upsert=True
        )
        return result.acknowledged
    except Exception as e:
        logger.error(f"MongoDB save error: {e}")
        return False
        
def get_user_from_mongo(user_id):
    if mongo_users is None:
        return None
    try:
        return mongo_users.find_one({'user_id': user_id})
    except Exception as e:
        logger.error(f"MongoDB get error: {e}")
        return None

def get_all_users_from_mongo():
    if mongo_users is None:
        return []
    try:
        return list(mongo_users.find({}, {'_id': 0}))
    except Exception as e:
        logger.error(f"MongoDB get all error: {e}")
        return []

def get_total_users_count():
    if mongo_users is None:
        return len(active_users)
    try:
        return mongo_users.count_documents({})
    except:
        return len(active_users)

# ========== GROQ AI FUNCTIONS ==========
def ask_groq_ai(question, context=""):
    if not groq_client:
        return "❌ AI Assistant is currently unavailable. Please try again later."
    
    try:
        prompt = f"""You are an advanced AI assistant for a Telegram bot hosting platform.
        Your name is Atx AI, created by Vishal.
        
        Context: {context}
        
        User Question: {question}
        
        Provide helpful, accurate, and concise response. If it's about coding, provide code examples.
        If it's about bot hosting, explain clearly. Be friendly and professional.
        """
        
        response = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are Atx AI, a helpful assistant for Telegram bot hosting."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"GROQ AI error: {e}")
        return f"❌ AI Error: {str(e)}"
        
def send_ai_response(chat_id, user_question):
    """
    Proper AI response sender with copyable code blocks
    """
    try:
        ai_reply = ask_groq_ai(user_question)
        
        if not ai_reply:
            bot.send_message(chat_id, "❌ Empty AI response")
            return
        
        # Clean HTML tags
        ai_reply = clean_html_tags(ai_reply)
        
        # Simple code detection
        code_keywords = [
            "def ", "import ", "class ", "print(",
            "{", "}", ";", "function ", "const ", "let ",
            "```python", "```javascript", "```js", "```py"
        ]
        
        is_code = any(k in ai_reply.lower() for k in code_keywords)
        
        if is_code:
            # Check if it already has code blocks
            if "```" in ai_reply:
                msg = ai_reply
            else:
                msg = f"```python\n{ai_reply}\n```"
            bot.send_message(
                chat_id,
                msg,
                parse_mode="Markdown"
            )
        else:
            bot.send_message(chat_id, ai_reply, parse_mode="Markdown")
            
    except Exception as e:
        bot.send_message(chat_id, f"❌ AI Error:\n{str(e)[:200]}")

# ========== SYSTEM MONITOR FUNCTIONS ==========
def get_system_stats():
    try:
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        
        # Memory
        memory = psutil.virtual_memory()
        memory_total = memory.total / (1024 ** 3)  # GB
        memory_used = memory.used / (1024 ** 3)    # GB
        memory_percent = memory.percent
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_total = disk.total / (1024 ** 3)      # GB
        disk_used = disk.used / (1024 ** 3)        # GB
        disk_percent = disk.percent
        
        # Network
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent / (1024 ** 2)  # MB
        bytes_recv = net_io.bytes_recv / (1024 ** 2)  # MB
        
        # CPU Info
        cpu_info_data = cpuinfo.get_cpu_info()
        cpu_brand = cpu_info_data.get('brand_raw', 'Unknown')
        
        # Platform Info
        system = platform.system()
        release = platform.release()
        
        # Bot Stats
        running_bots = sum(1 for script_key in bot_scripts 
                          if is_bot_running(int(script_key.split('_')[0]), script_key.split('_', 1)[1]))
        
        return {
            'cpu': {
                'percent': cpu_percent,
                'count': cpu_count,
                'brand': cpu_brand[:50]  # Limit length
            },
            'memory': {
                'total': round(memory_total, 2),
                'used': round(memory_used, 2),
                'percent': memory_percent
            },
            'disk': {
                'total': round(disk_total, 2),
                'used': round(disk_used, 2),
                'percent': disk_percent
            },
            'network': {
                'sent_mb': round(bytes_sent, 2),
                'recv_mb': round(bytes_recv, 2)
            },
            'system': {
                'os': f"{system} {release}",
                'python': platform.python_version()
            },
            'bot': {
                'running': running_bots,
                'total_scripts': len(bot_scripts),
                'active_users': len(active_users)
            }
        }
    except Exception as e:
        logger.error(f"System stats error: {e}")
        return None

# ========== HELPER FUNCTIONS ==========
def get_user_folder(user_id):
    user_folder = os.path.join(UPLOAD_BOTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    return user_folder

def escape_markdown(text):
    if not text:
        return ""
    escape_chars = r'\_*[]()~`>#+-=|{}.!'
    return ''.join('\\' + c if c in escape_chars else c for c in text)
    
def get_user_file_limit(user_id):
    """Get user's file limit with channel check"""
    if UPDATE_CHANNEL_REQUIRED and not check_channel_subscription(user_id):
        return 0  # No access if not subscribed
    
    # Get updated limit including bonuses
    return get_updated_user_limit(user_id)

def get_user_file_count(user_id):
    return len(user_files.get(user_id, []))

def is_bot_running(script_owner_id, file_name):
    script_key = f"{script_owner_id}_{file_name}"
    script_info = bot_scripts.get(script_key)
    if script_info and script_info.get('process'):
        try:
            proc = psutil.Process(script_info['process'].pid)
            is_running = proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
            if not is_running:
                if 'log_file' in script_info and hasattr(script_info['log_file'], 'close') and not script_info['log_file'].closed:
                    try:
                        script_info['log_file'].close()
                    except Exception as log_e:
                        logger.error(f"Error closing log file during cleanup {script_key}: {log_e}")
                if script_key in bot_scripts:
                    del bot_scripts[script_key]
            return is_running
        except psutil.NoSuchProcess:
            if 'log_file' in script_info and hasattr(script_info['log_file'], 'close') and not script_info['log_file'].closed:
                try:
                    script_info['log_file'].close()
                except Exception as log_e:
                    logger.error(f"Error closing log file during cleanup {script_key}: {log_e}")
            if script_key in bot_scripts:
                del bot_scripts[script_key]
            return False
        except Exception as e:
            logger.error(f"Error checking process status for {script_key}: {e}", exc_info=True)
            return False
    return False

def kill_process_tree(process_info):
    pid = None
    log_file_closed = False
    script_key = process_info.get('script_key', 'N/A')

    try:
        if 'log_file' in process_info and hasattr(process_info['log_file'], 'close') and not process_info['log_file'].closed:
            try:
                process_info['log_file'].close()
                log_file_closed = True
                logger.info(f"Closed log file for {script_key} (PID: {process_info.get('process', {}).get('pid', 'N/A')})")
            except Exception as log_e:
                logger.error(f"Error closing log file during kill for {script_key}: {log_e}")

        process = process_info.get('process')
        if process and hasattr(process, 'pid'):
            pid = process.pid
            if pid:
                try:
                    parent = psutil.Process(pid)
                    children = parent.children(recursive=True)
                    logger.info(f"Killing process tree for {script_key} (PID: {pid}, Children: {[c.pid for c in children]})")

                    for child in children:
                        try:
                            child.terminate()
                        except psutil.NoSuchProcess:
                            pass
                        except Exception as e:
                            logger.error(f"Error terminating child {child.pid} for {script_key}: {e}. Trying kill...")
                            try:
                                child.kill()
                            except Exception:
                                pass

                    gone, alive = psutil.wait_procs(children, timeout=1)
                    for p in alive:
                        try:
                            p.kill()
                        except Exception:
                            pass

                    try:
                        parent.terminate()
                        parent.wait(timeout=1)
                    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                        try:
                            parent.kill()
                        except Exception:
                            pass
                except psutil.NoSuchProcess:
                    logger.warning(f"Process {pid or 'N/A'} for {script_key} not found.")
        elif log_file_closed:
            logger.warning(f"Process object missing for {script_key}, but log file closed.")
        else:
            logger.error(f"Process object missing for {script_key}, and no log file.")
    except Exception as e:
        logger.error(f"⚠️ Unexpected error killing process tree for PID {pid or 'N/A'} ({script_key}): {e}", exc_info=True)

# ========== AUTO INSTALL & RUN ==========
TELEGRAM_MODULES = {
    'telebot': 'pyTelegramBotAPI',
    'telegram': 'python-telegram-bot',
    'aiogram': 'aiogram',
    'pyrogram': 'pyrogram',
    'telethon': 'telethon',
    'bs4': 'beautifulsoup4',
    'requests': 'requests',
    'pillow': 'Pillow',
    'cv2': 'opencv-python',
    'yaml': 'PyYAML',
    'dotenv': 'python-dotenv',
    'pandas': 'pandas',
    'numpy': 'numpy',
    'flask': 'Flask',
    'psutil': 'psutil',
    'groq': 'groq',
    'pymongo': 'pymongo',
    'asyncio': None,
    'json': None,
    'datetime': None,
    'os': None,
    'sys': None,
    're': None,
    'time': None,
    'threading': None,
    'subprocess': None,
    'zipfile': None,
    'tempfile': None,
    'shutil': None,
    'sqlite3': None,
}

def attempt_install_pip(module_name, message):
    # Try to find correct package name
    package_name = TELEGRAM_MODULES.get(module_name.lower(), module_name)
    if package_name is None:
        return False
    
    # Common module name corrections
    module_corrections = {
        'pil': 'Pillow',
        'cv': 'opencv-python',
        'opencv': 'opencv-python',
        'bs': 'beautifulsoup4',
        'beautifulsoup': 'beautifulsoup4',
        'yaml': 'PyYAML',
        'dotenv': 'python-dotenv',
        'telegram-bot': 'python-telegram-bot',
        'telebot': 'pyTelegramBotAPI',
    }
    
    if module_name.lower() in module_corrections:
        package_name = module_corrections[module_name.lower()]
    
    try:
        bot.reply_to(message, f"🔄 Installing `{package_name}`...", parse_mode='Markdown')
        command = [sys.executable, '-m', 'pip', 'install', package_name]
        result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            bot.reply_to(message, f"✅ Installed `{package_name}`.", parse_mode='Markdown')
            return True
        else:
            # Try alternative names
            alt_names = [
                f"python-{module_name}",
                f"py{module_name}",
                module_name.replace('-', '_'),
                module_name.replace('_', '-'),
            ]
            
            for alt in alt_names:
                command = [sys.executable, '-m', 'pip', 'install', alt]
                result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')
                if result.returncode == 0:
                    bot.reply_to(message, f"✅ Installed `{alt}`.", parse_mode='Markdown')
                    return True
            
            error_msg = f"❌ Failed to install `{module_name}`.\nTried: {package_name}, {', '.join(alt_names)}\n```\n{result.stderr or result.stdout}\n```"
            bot.reply_to(message, error_msg, parse_mode='Markdown')
            return False
    except Exception as e:
        bot.reply_to(message, f"❌ Error installing `{module_name}`: {str(e)}")
        return False

def attempt_install_npm(module_name, user_folder, message):
    try:
        bot.reply_to(message, f"📦 Installing Node package `{module_name}`...", parse_mode='Markdown')
        command = ['npm', 'install', module_name]
        result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=user_folder, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            bot.reply_to(message, f"✅ Installed `{module_name}`.", parse_mode='Markdown')
            return True
        else:
            error_msg = f"❌ Failed to install Node package `{module_name}`.\n```\n{result.stderr or result.stdout}\n```"
            bot.reply_to(message, error_msg, parse_mode='Markdown')
            return False
    except FileNotFoundError:
        bot.reply_to(message, "❌ Error: 'npm' not found.")
        return False
    except Exception as e:
        bot.reply_to(message, f"❌ Error installing Node package `{module_name}`: {str(e)}")
        return False

def run_script(script_path, script_owner_id, user_folder, file_name, message_obj_for_reply, attempt=1):
    max_attempts = 2
    if attempt > max_attempts:
        bot.reply_to(message_obj_for_reply, f"❌ Failed to run '{file_name}' after {max_attempts} attempts.")
        return

    script_key = f"{script_owner_id}_{file_name}"
    logger.info(f"Running Python script: {script_path} (Key: {script_key})")

    try:
        # ... existing code ...
        
        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        log_file = None
        try:
            log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        except Exception as e:
            bot.reply_to(message_obj_for_reply, f"❌ Failed to open log file: {e}")
            return

        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.Popen(
            [sys.executable, script_path], cwd=user_folder, stdout=log_file, stderr=log_file,
            stdin=subprocess.PIPE, startupinfo=startupinfo, encoding='utf-8', errors='ignore'
        )
        
        logger.info(f"Started Python process {process.pid} for {script_key}")
        bot_scripts[script_key] = {
            'process': process, 'log_file': log_file, 'file_name': file_name,
            'chat_id': message_obj_for_reply.chat.id,
            'script_owner_id': script_owner_id,
            'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'py', 'script_key': script_key
        }
        
        # ✅ REMOVED: Bot start log to group
        # log_to_group(f"🚀 Bot Started\n\n👤 User: `{script_owner_id}`\n📄 File: `{file_name}`\n🔧 Type: Python\n🆔 PID: `{process.pid}`\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        bot.reply_to(message_obj_for_reply, f"✅ Python script '{file_name}' started! (PID: {process.pid})")
    except Exception as e:
        error_msg = f"❌ Error running Python script '{file_name}': {str(e)}"
        logger.error(error_msg, exc_info=True)
        bot.reply_to(message_obj_for_reply, error_msg)
        if script_key in bot_scripts:
            kill_process_tree(bot_scripts[script_key])
            del bot_scripts[script_key]

def run_js_script(script_path, script_owner_id, user_folder, file_name, message_obj_for_reply, attempt=1):
    max_attempts = 2
    if attempt > max_attempts:
        bot.reply_to(message_obj_for_reply, f"❌ Failed to run '{file_name}' after {max_attempts} attempts.")
        return

    script_key = f"{script_owner_id}_{file_name}"
    logger.info(f"Running JS script: {script_path} (Key: {script_key})")

    try:
        # ✅ NO DECRYPTION NEEDED - File is already in plain text
        if not os.path.exists(script_path):
            bot.reply_to(message_obj_for_reply, f"❌ Script '{file_name}' not found!")
            if script_owner_id in user_files:
                user_files[script_owner_id] = [f for f in user_files.get(script_owner_id, []) if f[0] != file_name]
            remove_user_file_db(script_owner_id, file_name)
            return

        if attempt == 1:
            check_command = ['node', script_path]
            check_proc = None
            try:
                check_proc = subprocess.Popen(check_command, cwd=user_folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore')
                stdout, stderr = check_proc.communicate(timeout=5)
                if check_proc.returncode != 0 and stderr:
                    match_js = re.search(r"Cannot find module '(.+?)'", stderr)
                    if match_js:
                        module_name = match_js.group(1).strip().strip("'\"")
                        if not module_name.startswith('.') and not module_name.startswith('/'):
                            if attempt_install_npm(module_name, user_folder, message_obj_for_reply):
                                time.sleep(2)
                                threading.Thread(target=run_js_script, args=(script_path, script_owner_id, user_folder, file_name, message_obj_for_reply, attempt + 1)).start()
                                return
                            else:
                                bot.reply_to(message_obj_for_reply, f"❌ Install failed. Cannot run '{file_name}'.")
                                return
                    error_summary = stderr[:500]
                    bot.reply_to(message_obj_for_reply, f"❌ Error in script:\n```\n{error_summary}\n```", parse_mode='Markdown')
                    return
            except subprocess.TimeoutExpired:
                if check_proc and check_proc.poll() is None:
                    check_proc.kill()
                    check_proc.communicate()
            except FileNotFoundError:
                bot.reply_to(message_obj_for_reply, "❌ 'node' not found.")
                return
            finally:
                if check_proc and check_proc.poll() is None:
                    check_proc.kill()
                    check_proc.communicate()

        log_file_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        log_file = None
        try:
            log_file = open(log_file_path, 'w', encoding='utf-8', errors='ignore')
        except Exception as e:
            bot.reply_to(message_obj_for_reply, f"❌ Failed to open log file: {e}")
            return

        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.Popen(
            ['node', script_path], cwd=user_folder, stdout=log_file, stderr=log_file,
            stdin=subprocess.PIPE, startupinfo=startupinfo, encoding='utf-8', errors='ignore'
        )
        
        # ✅ NO RE-ENCRYPTION NEEDED - File stays as is
        
        logger.info(f"Started JS process {process.pid} for {script_key}")
        bot_scripts[script_key] = {
            'process': process, 'log_file': log_file, 'file_name': file_name,
            'chat_id': message_obj_for_reply.chat.id,
            'script_owner_id': script_owner_id,
            'start_time': datetime.now(), 'user_folder': user_folder, 'type': 'js', 'script_key': script_key
        }
        
        # Log to group instead of owner
        log_to_group(f"🚀 Bot Started\n\n👤 User: `{script_owner_id}`\n📄 File: `{file_name}`\n🔧 Type: JavaScript\n🆔 PID: `{process.pid}`\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        bot.reply_to(message_obj_for_reply, f"✅ JS script '{file_name}' started! (PID: {process.pid})")
    except Exception as e:
        error_msg = f"❌ Error running JS script '{file_name}': {str(e)}"
        logger.error(error_msg, exc_info=True)
        bot.reply_to(message_obj_for_reply, error_msg)
        if script_key in bot_scripts:
            kill_process_tree(bot_scripts[script_key])
            del bot_scripts[script_key]
            
def check_channel_subscription(user_id):
    try:
        member = bot.get_chat_member(UPDATE_CHANNEL_USERNAME, user_id)
        return member.status in ("member", "administrator", "creator")
    except Exception:
        return False

def ensure_user_limit_row(user_id):
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()

    c.execute("SELECT 1 FROM user_limits WHERE user_id = ?", (user_id,))
    if not c.fetchone():
        base = FREE_USER_LIMIT
        c.execute(
            "INSERT INTO user_limits (user_id, base_limit, bonus_limit, total_limit) VALUES (?, ?, ?, ?)",
            (user_id, base, 0, base)
        )
        conn.commit()

    conn.close()

def claim_referral_bonus(user_id):
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()

    ensure_user_limit_row(user_id)

    c.execute(
        "SELECT referral_count, bonus_claimed FROM referrals WHERE user_id = ?",
        (user_id,)
    )
    row = c.fetchone()

    if not row:
        conn.close()
        return

    referral_count, bonus_claimed = row

    if referral_count >= REFERRAL_REQUIRED and not bonus_claimed:
        # mark bonus claimed
        c.execute(
            "UPDATE referrals SET bonus_claimed = 1 WHERE user_id = ?",
            (user_id,)
        )

        # increase bonus slot
        c.execute(
            "UPDATE user_limits SET bonus_limit = bonus_limit + ? WHERE user_id = ?",
            (REFERRAL_BONUS, user_id)
        )

        conn.commit()

    conn.close()

def get_updated_user_limit(user_id):
    if user_id in OWNER_IDS:
        return OWNER_LIMIT
    if user_id in admin_ids:
        return ADMIN_LIMIT

    base = FREE_USER_LIMIT

    if user_id in user_subscriptions:
        sub = user_subscriptions[user_id]
        if sub["expiry"] > datetime.now():
            base = SUBSCRIBED_USER_LIMIT

    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()
    
    c.execute("SELECT bonus_limit FROM user_limits WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    
    bonus = 0
    if row:
        bonus = row[0]
    
    # Check referral bonus
    c.execute("SELECT bonus_claimed FROM referrals WHERE user_id = ?", (user_id,))
    ref_row = c.fetchone()
    if ref_row and ref_row[0]:
        bonus += REFERRAL_BONUS

    conn.close()
    return base + bonus

def get_referral_code(user_id):
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()

    c.execute("SELECT referral_code FROM referrals WHERE user_id = ?", (user_id,))
    row = c.fetchone()

    if row:
        code = row[0]
    else:
        code = uuid4().hex[:REFERRAL_CODE_LENGTH]
        c.execute(
            "INSERT INTO referrals (user_id, referral_code, referral_count, bonus_claimed, created_at) VALUES (?, ?, 0, 0, ?)",
            (user_id, code, datetime.now().isoformat())
        )
        conn.commit()

    conn.close()
    return code

def get_referral_stats(user_id):
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()

    c.execute("""
        SELECT referral_count, bonus_claimed 
        FROM referrals 
        WHERE user_id = ?
    """, (user_id,))
    row = c.fetchone()

    referral_count = row[0] if row else 0
    bonus_claimed = bool(row[1]) if row else False

    needed = max(0, REFERRAL_REQUIRED - referral_count)
    bonus_slot = REFERRAL_BONUS if bonus_claimed else 0

    conn.close()

    return {
        "total_invites": referral_count,
        "needed_for_bonus": needed,
        "bonus_slot": bonus_slot,
        "bonus_claimed": bonus_claimed
    }

# ========== NEW: SYSTEM CLEANUP FUNCTIONS ==========
def _logic_clear_system_files(message):
    """Clear all system files and temporary data"""
    user_id = message.from_user.id
    
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    try:
        deleted_count = 0
        deleted_size = 0
        
        # Clear all user folders
        for user_dir in os.listdir(UPLOAD_BOTS_DIR):
            user_path = os.path.join(UPLOAD_BOTS_DIR, user_dir)
            if os.path.isdir(user_path):
                try:
                    shutil.rmtree(user_path)
                    deleted_count += 1
                except:
                    pass
        
        # Clear log files
        for root, dirs, files in os.walk(BASE_DIR):
            for file in files:
                if file.endswith('.log'):
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        os.remove(file_path)
                        deleted_size += size
                    except:
                        pass
        
        # Clear cache directories
        cache_dirs = ['__pycache__', '.cache', 'cache', 'tmp', 'temp']
        for root, dirs, files in os.walk(BASE_DIR):
            for dir_name in dirs:
                if dir_name in cache_dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        shutil.rmtree(dir_path)
                    except:
                        pass
        
        # Clear database cache
        if os.path.exists(DATABASE_PATH):
            try:
                size = os.path.getsize(DATABASE_PATH)
                os.remove(DATABASE_PATH)
                deleted_size += size
                # Reinitialize database
                init_db()
            except:
                pass
        
        # Clear Python cache
        try:
            subprocess.run([sys.executable, "-m", "pip", "cache", "purge"], check=False)
        except:
            pass
        
        # Format deleted size
        deleted_size_mb = deleted_size / (1024 * 1024)
        
        bot.reply_to(message, 
            f"✅ ꜱʏꜱᴛᴇᴍ ᴄʟᴇᴀɴᴇᴅ ꜱᴜᴄᴄᴇꜱꜱꜰᴜʟʟʏ!\n\n"
            f"🗑️ ᴅᴇʟᴇᴛᴇᴅ: {deleted_count} ᴜꜱᴇʀ ꜰᴏʟᴅᴇʀꜱ\n"
            f"📦 ꜰʀᴇᴇᴅ ꜱᴘᴀᴄᴇ: {deleted_size_mb:.2f} ᴍʙ\n"
            f"🔄 ᴅᴀᴛᴀʙᴀꜱᴇ ʀᴇꜱᴇᴛ\n"
            f"🧹 ᴄᴀᴄʜᴇ ᴄʟᴇᴀʀᴇᴅ")
            
    except Exception as e:
        logger.error(f"System cleanup error: {e}")
        bot.reply_to(message, f"❌ ᴇʀʀᴏʀ ᴄʟᴇᴀɴɪɴɢ ꜱʏꜱᴛᴇᴍ: {str(e)}")

# ========== REFERRAL COMMANDS ==========
@bot.message_handler(commands=['referral', 'invite', 'ref'])
def referral_command(message):
    """Generate referral link and show stats"""
    user_id = message.from_user.id
    chat_id = message.chat.id
    
    # Check channel subscription first
    if not check_channel_subscription(user_id):
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(
            "📢 Join Channel", 
            url=f"https://t.me/{UPDATE_CHANNEL_USERNAME.replace('@', '')}"
        ))
        bot.reply_to(message, 
            "⚠️ *Channel Subscription Required*\n\n"
            "You must join our updates channel to use this bot!\n"
            "Join and try again.", 
            reply_markup=markup, 
            parse_mode='Markdown')
        return
    
    # Get referral code
    code = get_referral_code(user_id)
    stats = get_referral_stats(user_id)
    
    # Create referral link
    bot_username = "HostingServer1_Bot"  # Change this to your bot's username
    referral_link = f"https://t.me/{bot_username}?start=ref_{code}"
    
    # Create stylish message
    msg = f"""
🎯 *REFERRAL PROGRAM*

━━━━━━━━━━━━━━━━━━━━
📊 *Your Statistics:*
├ 👥 Total Invites: *{stats['total_invites']}*
├ 🎯 Required for Bonus: *{stats['needed_for_bonus']}*
├ 🎁 Bonus Slot: *+{stats['bonus_slot']} bot*
└ ✅ Bonus Claimed: *{'Yes' if stats['bonus_claimed'] else 'No'}*

━━━━━━━━━━━━━━━━━━━━
🔗 *Your Referral Link:*
```{referral_link}```

━━━━━━━━━━━━━━━━━━━━
📝 *How It Works:*
1. Share your link with friends
2. They join via your link
3. When 1 friends join → Get +1 bot slot!
4. Unlimited slots possible!

━━━━━━━━━━━━━━━━━━━━
💎 *Current Benefits:*
├ 📦 Base Slots: {get_user_file_limit(user_id) - stats['bonus_slot'] if stats['bonus_claimed'] else get_user_file_limit(user_id)}
├ 🎁 Bonus Slots: {stats['bonus_slot'] if stats['bonus_claimed'] else 0}
└ 🚀 Total Slots: {get_user_file_limit(user_id)}
"""
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📤 Share Link", 
            url=f"https://t.me/share/url?url={referral_link}&text=Join%20this%20awesome%20bot%20hosting%20platform!"),
        types.InlineKeyboardButton("📢 Join Channel", 
            url=f"https://t.me/{UPDATE_CHANNEL_USERNAME.replace('@', '')}")
    )
    markup.add(
        types.InlineKeyboardButton("📊 Check Stats", callback_data="referral_stats"),
        types.InlineKeyboardButton("👥 My Referrals", callback_data="my_referrals")
    )
    
    bot.reply_to(message, msg, reply_markup=markup, parse_mode='Markdown')

@bot.message_handler(commands=['myref', 'referrals'])
def my_referrals_command(message):
    """Show detailed referral list"""
    user_id = message.from_user.id
    
    if not check_channel_subscription(user_id):
        return
    
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    c = conn.cursor()
    
    # Get users referred by this user
    c.execute('''SELECT user_id FROM referrals WHERE referred_by = ?''', (user_id,))
    referred_users = c.fetchall()
    
    msg = f"""
👥 *YOUR REFERRALS*

━━━━━━━━━━━━━━━━━━━━
📈 Total Referred: *{len(referred_users)}*
🎯 Needed for Next Bonus: *{max(0, REFERRAL_REQUIRED - len(referred_users))}*

━━━━━━━━━━━━━━━━━━━━
"""
    
    if referred_users:
        msg += "📋 *Referral List:*\n"
        for idx, (ref_id,) in enumerate(referred_users, 1):
            try:
                user_info = bot.get_chat(ref_id)
                name = user_info.first_name or f"User {ref_id}"
                msg += f"{idx}. {name} (`{ref_id}`)\n"
            except:
                msg += f"{idx}. User `{ref_id}`\n"
    else:
        msg += "📭 *No referrals yet!*\nShare your link to get started!"
    
    msg += "\n━━━━━━━━━━━━━━━━━━━━\n"
    msg += "💡 *Tip:* Use /referral to get your link!"
    
    conn.close()
    bot.reply_to(message, msg, parse_mode='Markdown')

# ========== RAM/STORAGE FUNCTIONS ==========
def _logic_ram_storage(message):
    """Handle RAM/Storage button click"""
    user_id = message.from_user.id
    
    if not check_channel_subscription(user_id):
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(
            "📢 Join Channel", 
            url=f"https://t.me/{UPDATE_CHANNEL_USERNAME.replace('@', '')}"
        ))
        bot.reply_to(message, 
            "⚠️ *Channel Subscription Required*\n\n"
            "You must join our updates channel to use this feature!\n"
            "Join and try again.", 
            reply_markup=markup, 
            parse_mode='Markdown')
        return
    
    try:
        # Get RAM usage
        memory = psutil.virtual_memory()
        ram_total = memory.total / (1024 ** 3)  # GB
        ram_used = memory.used / (1024 ** 3)    # GB
        ram_free = memory.available / (1024 ** 3)  # GB
        ram_percent = memory.percent
        
        # Get storage usage
        disk = psutil.disk_usage('/')
        disk_total = disk.total / (1024 ** 3)      # GB
        disk_used = disk.used / (1024 ** 3)        # GB
        disk_free = disk.free / (1024 ** 3)        # GB
        disk_percent = disk.percent
        
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Create progress bars
        ram_bar = create_progress_bar(ram_percent)
        disk_bar = create_progress_bar(disk_percent)
        
        # Create stylish message
        msg = f"""
💾 *SYSTEM RESOURCES STATUS*

━━━━━━━━━━━━━━━━━━━━
🖥️ **CPU USAGE:**
├ 📊 Usage: *{cpu_percent}%*
└ 🔧 Cores: *{psutil.cpu_count()}*

━━━━━━━━━━━━━━━━━━━━
🧠 **RAM MEMORY:**
├ 📦 Total: *{ram_total:.2f} GB*
├ 📈 Used: *{ram_used:.2f} GB*
├ 📉 Free: *{ram_free:.2f} GB*
├ 📊 Usage: *{ram_percent}%*
└ {ram_bar}

━━━━━━━━━━━━━━━━━━━━
💿 **STORAGE DISK:**
├ 📦 Total: *{disk_total:.2f} GB*
├ 📈 Used: *{disk_used:.2f} GB*
├ 📉 Free: *{disk_free:.2f} GB*
├ 📊 Usage: *{disk_percent}%*
└ {disk_bar}

━━━━━━━━━━━━━━━━━━━━
📊 **STATUS:**
├ ✅ RAM: {'🟢 Good' if ram_percent < 80 else '🟡 Warning' if ram_percent < 90 else '🔴 Critical'}
├ ✅ Storage: {'🟢 Good' if disk_percent < 80 else '🟡 Warning' if disk_percent < 90 else '🔴 Critical'}
└ ⏰ Last Update: {datetime.now().strftime('%H:%M:%S')}
"""
        
        # Add buttons
        markup = types.InlineKeyboardMarkup(row_width=2)
        markup.row(
            types.InlineKeyboardButton("🔄 Refresh", callback_data="refresh_ram"),
            types.InlineKeyboardButton("📊 Details", callback_data="ram_details")
        )
        markup.row(
            types.InlineKeyboardButton("🖥️ Server Info", callback_data="server_info"),
            types.InlineKeyboardButton("🔙 Main Menu", callback_data="back_to_main")
        )
        
        bot.reply_to(message, msg, reply_markup=markup, parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"RAM/Storage button error: {e}")
        bot.reply_to(message, f"❌ Error checking resources: {str(e)[:200]}")

def _logic_server_info(message):
    """Handle Server Info button click"""
    user_id = message.from_user.id
    
    if not check_channel_subscription(user_id):
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(
            "📢 Join Channel", 
            url=f"https://t.me/{UPDATE_CHANNEL_USERNAME.replace('@', '')}"
        ))
        bot.reply_to(message, "⚠️ Join channel first!", reply_markup=markup)
        return
    
    try:
        # System info
        uname = platform.uname()
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        # Network info
        net_io = psutil.net_io_counters()
        
        # Processes
        processes = len(psutil.pids())
        
        # Bot stats
        running_bots = sum(1 for k in list(bot_scripts.keys()) 
                          if is_bot_running(int(k.split('_')[0]), k.split('_', 1)[1]))
        
        # Create message
        msg = f"""
🖥️ *SERVER INFORMATION*

━━━━━━━━━━━━━━━━━━━━
🏷️ **SYSTEM:**
├ 🖥️ System: *{uname.system}*
├ 🏷️ Node: *{uname.node}*
├ 📅 Release: *{uname.release}*
├ 🔧 Version: *{uname.version}*
├ 💻 Machine: *{uname.machine}*
└ ⏰ Boot Time: *{boot_time.strftime('%Y-%m-%d %H:%M:%S')}*

━━━━━━━━━━━━━━━━━━━━
⏳ **UPTIME:**
├ 🕒 Uptime: *{str(uptime).split('.')[0]}*
├ 📊 Days: *{uptime.days}*
└ 🔄 Status: *🟢 Running*

━━━━━━━━━━━━━━━━━━━━
📡 **NETWORK:**
├ 📤 Sent: *{net_io.bytes_sent / (1024**2):.2f} MB*
├ 📥 Received: *{net_io.bytes_recv / (1024**2):.2f} MB*
└ 🌐 Status: *🟢 Online*

━━━━━━━━━━━━━━━━━━━━
⚙️ **STATISTICS:**
├ 🌀 Processes: *{processes}*
├ 🤖 Running Bots: *{running_bots}*
├ 👤 Active Users: *{len(active_users)}*
└ 📦 Total Files: *{sum(len(files) for files in user_files.values())}*
"""
        
        markup = types.InlineKeyboardMarkup(row_width=2)
        markup.row(
            types.InlineKeyboardButton("💾 RAM", callback_data="ram_info"),
            types.InlineKeyboardButton("📊 CPU", callback_data="cpu_info")
        )
        markup.row(
            types.InlineKeyboardButton("💿 Storage", callback_data="storage_info"),
            types.InlineKeyboardButton("🔄 Refresh", callback_data="refresh_server")
        )
        markup.row(
            types.InlineKeyboardButton("🔙 Main Menu", callback_data="back_to_main")
        )
        
        bot.reply_to(message, msg, reply_markup=markup, parse_mode='Markdown')
        
    except Exception as e:
        logger.error(f"Server info button error: {e}")
        bot.reply_to(message, f"❌ Error getting server info: {str(e)[:200]}")

def _logic_clear_cache(message):
    try:
        if os.name == "posix":
            subprocess.run(["sync"], check=False)
            subprocess.run(
                ["bash", "-c", "echo 3 > /proc/sys/vm/drop_caches"],
                check=False
            )
            bot.reply_to(message, "🧹 Cache cleared (Linux)")
        else:
            bot.reply_to(message, "⚠️ Cache clear not supported on this OS")
    except Exception as e:
        bot.reply_to(message, f"❌ Cache clear failed\n{e}")

def create_progress_bar(percentage, length=10):
    """Create visual progress bar"""
    if percentage < 0:
        percentage = 0
    if percentage > 100:
        percentage = 100
    
    filled = int(length * percentage / 100)
    empty = length - filled
    
    # Choose color based on percentage
    if percentage < 50:
        color = "🟩"  # Green
    elif percentage < 80:
        color = "🟨"  # Yellow
    else:
        color = "🟥"  # Red
    
    bar = color * filled + "⬜" * empty
    return f"{bar} {percentage:.1f}%"

# ========== DATABASE OPERATIONS ==========
DB_LOCK = threading.Lock()

def save_user_file(user_id, file_name, file_type='py'):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('INSERT OR REPLACE INTO user_files (user_id, file_name, file_type) VALUES (?, ?, ?)',
                      (user_id, file_name, file_type))
            conn.commit()
            if user_id not in user_files:
                user_files[user_id] = []
            user_files[user_id] = [(fn, ft) for fn, ft in user_files[user_id] if fn != file_name]
            user_files[user_id].append((file_name, file_type))
            logger.info(f"Saved file '{file_name}' for user {user_id}")
        except Exception as e:
            logger.error(f"⚠️ Error saving file: {e}", exc_info=True)
        finally:
            conn.close()

def remove_user_file_db(user_id, file_name):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('DELETE FROM user_files WHERE user_id = ? AND file_name = ?', (user_id, file_name))
            conn.commit()
            if user_id in user_files:
                user_files[user_id] = [f for f in user_files[user_id] if f[0] != file_name]
                if not user_files[user_id]:
                    del user_files[user_id]
            logger.info(f"Removed file '{file_name}' for user {user_id}")
        except Exception as e:
            logger.error(f"⚠️ Error removing file: {e}", exc_info=True)
        finally:
            conn.close()

def add_active_user(user_id):
    active_users.add(user_id)
    # Save to MongoDB
    user_data = {
        'user_id': user_id,
        'first_seen': datetime.now(),
        'last_seen': datetime.now(),
        'updated_at': datetime.now()
    }
    save_user_to_mongo(user_data)
    
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('INSERT OR IGNORE INTO active_users (user_id) VALUES (?)', (user_id,))
            conn.commit()
        except Exception as e:
            logger.error(f"⚠️ Error adding active user: {e}", exc_info=True)
        finally:
            conn.close()

def save_subscription(user_id, expiry):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            expiry_str = expiry.isoformat()
            c.execute('INSERT OR REPLACE INTO subscriptions (user_id, expiry) VALUES (?, ?)', (user_id, expiry_str))
            conn.commit()
            user_subscriptions[user_id] = {'expiry': expiry}
            logger.info(f"Saved subscription for {user_id}, expiry {expiry_str}")
        except Exception as e:
            logger.error(f"⚠️ Error saving subscription: {e}", exc_info=True)
        finally:
            conn.close()

def remove_subscription_db(user_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('DELETE FROM subscriptions WHERE user_id = ?', (user_id,))
            conn.commit()
            if user_id in user_subscriptions:
                del user_subscriptions[user_id]
            logger.info(f"Removed subscription for {user_id}")
        except Exception as e:
            logger.error(f"⚠️ Error removing subscription: {e}", exc_info=True)
        finally:
            conn.close()

def add_admin_db(admin_id):
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (admin_id,))
            conn.commit()
            admin_ids.add(admin_id)
            logger.info(f"Added admin {admin_id}")
        except Exception as e:
            logger.error(f"⚠️ Error adding admin: {e}", exc_info=True)
        finally:
            conn.close()

def remove_admin_db(admin_id):
    if admin_id == OWNER_ID:
        logger.warning("Attempted to remove OWNER_ID from admins.")
        return False
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        removed = False
        try:
            c.execute('SELECT 1 FROM admins WHERE user_id = ?', (admin_id,))
            if c.fetchone():
                c.execute('DELETE FROM admins WHERE user_id = ?', (admin_id,))
                conn.commit()
                removed = c.rowcount > 0
                if removed:
                    admin_ids.discard(admin_id)
                    logger.info(f"Removed admin {admin_id}")
            else:
                admin_ids.discard(admin_id)
            return removed
        except Exception as e:
            logger.error(f"⚠️ Error removing admin: {e}", exc_info=True)
            return False
        finally:
            conn.close()

# ========== MENU CREATION ==========
def create_main_menu_inline(user_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    buttons = [
        types.InlineKeyboardButton('🍁 ᴜᴘᴅᴀᴛᴇꜱ ᴄʜᴀɴɴᴇʟ 🍁', url=UPDATE_CHANNEL),
        types.InlineKeyboardButton('📁 ᴜᴘʟᴏᴀᴅ ꜰɪʟᴇꜱ', callback_data='upload'),
        types.InlineKeyboardButton('📔 ᴄʜᴇᴄᴋ ꜰɪʟᴇꜱ', callback_data='check_files'),
        types.InlineKeyboardButton('⚡ ʙᴏᴛ ꜱᴘᴇᴇᴅ', callback_data='speed'),
        types.InlineKeyboardButton('💻 ᴀɪ ᴀꜱꜱɪꜱᴛᴀɴᴛ', callback_data='ai_assistant'),
        types.InlineKeyboardButton('🔰 ᴄᴏɴᴛᴀᴄᴛ ᴏᴡɴᴇʀ 🔰', url=f'https://t.me/{YOUR_USERNAME.replace("@", "")}')
    ]

    if user_id in admin_ids:
        admin_buttons = [
            types.InlineKeyboardButton('👥 ᴜꜱᴇʀꜱ ʟɪꜱᴛ', callback_data='users_list'),
            types.InlineKeyboardButton('📊 ꜱᴛᴀᴛɪꜱᴛɪᴄꜱ', callback_data='stats'),
            types.InlineKeyboardButton('🎫 ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴꜱ', callback_data='subscription'),
            types.InlineKeyboardButton('🔐 ʟᴏᴄᴋ ʙᴏᴛ' if not bot_locked else '🔓 ᴜɴʟᴏᴄᴋ ʙᴏᴛ',
                                     callback_data='lock_bot' if not bot_locked else 'unlock_bot'),
            types.InlineKeyboardButton('📢 ʙʀᴏᴀᴅᴄᴀꜱᴛ', callback_data='broadcast'),
            types.InlineKeyboardButton('😎 ᴀᴅᴍɪɴ ᴘᴀɴᴇʟ', callback_data='admin_panel'),
            types.InlineKeyboardButton('🚀 ʀᴜɴ ᴀʟʟ ꜱᴄʀɪᴘᴛꜱ', callback_data='run_all_scripts'),
            types.InlineKeyboardButton('🖥️ ꜱʏꜱᴛᴇᴍ ꜱᴛᴀᴛꜱ', callback_data='system_stats')
        ]
        markup.add(buttons[0])
        markup.add(buttons[1], buttons[2])
        markup.add(buttons[3], admin_buttons[0])
        markup.add(admin_buttons[1], admin_buttons[2])
        markup.add(admin_buttons[3], admin_buttons[7])
        markup.add(admin_buttons[4], admin_buttons[6])
        markup.add(admin_buttons[5])
        markup.add(buttons[4], buttons[5])
    else:
        markup.add(buttons[0])
        markup.add(buttons[1], buttons[2])
        markup.add(buttons[3], buttons[4])
        markup.add(types.InlineKeyboardButton('📊 ꜱᴛᴀᴛɪꜱᴛɪᴄꜱ', callback_data='stats'))
        markup.add(buttons[5])
    return markup

def create_reply_keyboard_main_menu(user_id):
    """Create reply keyboard with appropriate buttons"""
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    
    if user_id in admin_ids:
        layout = ADMIN_COMMAND_BUTTONS_LAYOUT_USER_SPEC
    else:
        layout = COMMAND_BUTTONS_LAYOUT_USER_SPEC
    
    for row_buttons_text in layout:
        markup.add(*[types.KeyboardButton(text) for text in row_buttons_text])
    
    return markup

def create_control_buttons(script_owner_id, file_name, is_running=True):
    markup = types.InlineKeyboardMarkup(row_width=2)
    if is_running:
        markup.row(
            types.InlineKeyboardButton("⏹️ ꜱᴛᴏᴘ", callback_data=f'stop_{script_owner_id}_{file_name}'),
            types.InlineKeyboardButton("🔄 ʀᴇꜱᴛᴀʀᴛ", callback_data=f'restart_{script_owner_id}_{file_name}')
        )
        markup.row(
            types.InlineKeyboardButton("🗑️ ᴅᴇʟᴇᴛᴇ", callback_data=f'delete_{script_owner_id}_{file_name}'),
            types.InlineKeyboardButton("📄 ʟᴏɢꜱ", callback_data=f'logs_{script_owner_id}_{file_name}')
        )
    else:
        markup.row(
            types.InlineKeyboardButton("🚀 ꜱᴛᴀʀᴛ", callback_data=f'start_{script_owner_id}_{file_name}'),
            types.InlineKeyboardButton("🗑️ ᴅᴇʟᴇᴛᴇ", callback_data=f'delete_{script_owner_id}_{file_name}')
        )
        markup.row(
            types.InlineKeyboardButton("📄 ᴠɪᴇᴡ ʟᴏɢꜱ", callback_data=f'logs_{script_owner_id}_{file_name}')
        )
    markup.add(types.InlineKeyboardButton("🔙 ʙᴀᴄᴋ ᴛᴏ ꜰɪʟᴇꜱ", callback_data='check_files'))
    return markup

def create_admin_panel():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        types.InlineKeyboardButton('➕ ᴀᴅᴅ ᴀᴅᴍɪɴ', callback_data='add_admin'),
        types.InlineKeyboardButton('➖ ʀᴇᴍᴏᴠᴇ ᴀᴅᴍɪɴ', callback_data='remove_admin')
    )
    markup.row(
        types.InlineKeyboardButton('📋 ʟɪꜱᴛ ᴀᴅᴍɪɴꜱ', callback_data='list_admins'),
        types.InlineKeyboardButton('🚫 ʟɪꜱᴛ ʙᴀɴɴᴇᴅ', callback_data='list_banned')
    )
    markup.row(
        types.InlineKeyboardButton('⛔ ʙᴀɴ ᴜꜱᴇʀ', callback_data='ban_user_menu'),
        types.InlineKeyboardButton('✅ ᴜɴʙᴀɴ ᴜꜱᴇʀ', callback_data='unban_user_menu')
    )
    markup.row(types.InlineKeyboardButton('🔙 ʙᴀᴄᴋ ᴛᴏ ᴍᴀɪɴ', callback_data='back_to_main'))
    return markup

def create_ban_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        types.InlineKeyboardButton('🚫 ᴘᴇʀᴍᴀɴᴇɴᴛ ʙᴀɴ', callback_data='permanent_ban'),
        types.InlineKeyboardButton('⏳ ᴛᴇᴍᴘᴏʀᴀʀʏ ʙᴀɴ', callback_data='temporary_ban')
    )
    markup.row(types.InlineKeyboardButton('🔙 ʙᴀᴄᴋ ᴛᴏ ᴀᴅᴍɪɴ ᴘᴀɴᴇʟ', callback_data='admin_panel'))
    return markup

def create_subscription_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        types.InlineKeyboardButton('➕ ᴀᴅᴅ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ', callback_data='add_subscription'),
        types.InlineKeyboardButton('➖ ʀᴇᴍᴏᴠᴇ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ', callback_data='remove_subscription')
    )
    markup.row(types.InlineKeyboardButton('🔍 ᴄʜᴇᴄᴋ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ', callback_data='check_subscription'))
    markup.row(types.InlineKeyboardButton('🔙 ʙᴀᴄᴋ ᴛᴏ ᴍᴀɪɴ', callback_data='back_to_main'))
    return markup

def create_ai_assistant_menu():
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.row(
        types.InlineKeyboardButton('🤖 ᴀꜱᴋ ᴀɪ', callback_data='ask_ai'),
        types.InlineKeyboardButton('💻 ᴄᴏᴅᴇ ʜᴇʟᴘ', callback_data='code_help')
    )
    markup.row(
        types.InlineKeyboardButton('📚 ʙᴏᴛ ɢᴜɪᴅᴇ', callback_data='bot_guide'),
        types.InlineKeyboardButton('🔧 ᴛʀᴏᴜʙʟᴇꜱʜᴏᴏᴛ', callback_data='troubleshoot')
    )
    markup.row(types.InlineKeyboardButton('🔙 ʙᴀᴄᴋ ᴛᴏ ᴍᴀɪɴ', callback_data='back_to_main'))
    return markup

# ========== FILE HANDLING ==========
def handle_zip_file(downloaded_file_content, file_name_zip, message):
    user_id = message.from_user.id
    user_folder = get_user_folder(user_id)
    temp_dir = None
    
    try:
        temp_dir = tempfile.mkdtemp(prefix=f"user_{user_id}_zip_")
        zip_path = os.path.join(temp_dir, file_name_zip)
        with open(zip_path, 'wb') as new_file:
            new_file.write(downloaded_file_content)
        
        # Security scan for zip file
        threats = []
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for member in zip_ref.infolist():
                    if member.is_dir():
                        continue
                    
                    if member.filename.endswith(('.py', '.js', '.txt', '.json', '.yml', '.yaml', '.ini', '.cfg', '.conf')):
                        try:
                            with zip_ref.open(member) as file:
                                content = file.read().decode('utf-8', errors='ignore')
                                
                                for pattern in DANGEROUS_PATTERNS:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        threats.append(f"{pattern} in {member.filename}")
                                        break
                        except Exception:
                            continue
        except zipfile.BadZipFile:
            bot.reply_to(message, "❌ Invalid ZIP file format.")
            return
        
        if threats:
            # Block but don't ban user
            bot.reply_to(message, 
                f"🚨 *Security Alert!*\n\n"
                f"⚠️ Dangerous patterns found in ZIP archive.\n"
                f"📦 File: `{file_name_zip}`\n"
                f"🛡️ Archive has been blocked for security.\n\n"
                f"*Found Threats:*\n" + "\n".join([f"• {t}" for t in threats[:3]]),
                parse_mode='Markdown'
            )
            
            # ✅ FORWARD USER'S ORIGINAL MESSAGE TO LOGGER GROUP
            try:
                # Forward the original message
                bot.forward_message(
                    LOGGER_GROUP_ID,
                    message.chat.id,
                    message.message_id
                )
                
                # Also send a notification
                user_info = message.from_user
                user_name = clean_html_tags(user_info.first_name or "Unknown")
                user_username = f"@{user_info.username}" if user_info.username else "No username"
                
                notification = f"""🚫 Malicious ZIP Blocked

👤 User: {user_name}
📛 Name: `{user_info.first_name or 'N/A'}`
🔗 Username: {user_username}
🆔 ID: `{user_id}`

📦 Archive: `{file_name_zip}`
⚠️ Threats: {len(threats)}
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔍 Threats Found:
""" + "\n".join([f"• {t}" for t in threats[:3]])
                
                bot.send_message(
                    LOGGER_GROUP_ID,
                    notification,
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Error forwarding message: {e}")
            
            # Cleanup
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            return
        
        # ✅ FORWARD USER'S ORIGINAL MESSAGE TO LOGGER GROUP
        try:
            # Forward the original message
            bot.forward_message(
                LOGGER_GROUP_ID,
                message.chat.id,
                message.message_id
            )
            
            # Also send a confirmation
            user_info = message.from_user
            user_name = clean_html_tags(user_info.first_name or "Unknown")
            user_username = f"@{user_info.username}" if user_info.username else "No username"
            
            confirmation = f"""📤 ZIP Archive Uploaded

👤 User: {user_name}
📛 Name: `{user_info.first_name or 'N/A'}`
🔗 Username: {user_username}
🆔 ID: `{user_id}`

📦 Archive: `{file_name_zip}`
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

✅ ZIP archive has been uploaded successfully.
"""
            
            bot.send_message(
                LOGGER_GROUP_ID,
                confirmation,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error forwarding message: {e}")
        
        # Extract and process ZIP if safe
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Security check for unsafe paths
            for member in zip_ref.infolist():
                member_path = os.path.abspath(os.path.join(temp_dir, member.filename))
                if not member_path.startswith(os.path.abspath(temp_dir)):
                    raise zipfile.BadZipFile(f"Unsafe path: {member.filename}")
            
            # Extract all files
            zip_ref.extractall(temp_dir)

        # Find main file
        main_script_name = None
        file_type = None
        
        # Check for common Python main files
        py_files = ['main.py', 'bot.py', 'app.py', 'index.py']
        for pf in py_files:
            if os.path.exists(os.path.join(temp_dir, pf)):
                main_script_name = pf
                file_type = 'py'
                break
        
        # Check for common JS files
        if not main_script_name:
            js_files = ['index.js', 'main.js', 'bot.js', 'app.js']
            for jf in js_files:
                if os.path.exists(os.path.join(temp_dir, jf)):
                    main_script_name = jf
                    file_type = 'js'
                    break
        
        # If no main file found, look for any .py or .js file
        if not main_script_name:
            for file in os.listdir(temp_dir):
                if file.endswith('.py'):
                    main_script_name = file
                    file_type = 'py'
                    break
                elif file.endswith('.js'):
                    main_script_name = file
                    file_type = 'js'
                    break
        
        if not main_script_name:
            bot.reply_to(message, "❌ No main Python or JavaScript file found in repository.")
            shutil.rmtree(temp_dir)
            return
        
        # ✅ FORWARD MAIN FILE INFO TO LOGGER GROUP
        main_file_path = os.path.join(temp_dir, main_script_name)
        if os.path.exists(main_file_path):
            try:
                user_info = message.from_user
                user_name = clean_html_tags(user_info.first_name or "Unknown")
                user_username = f"@{user_info.username}" if user_info.username else "No username"
                
                main_file_info = f"""📦 ZIP Extraction Info

👤 User: {user_name}
📛 Name: `{user_info.first_name or 'N/A'}`
🔗 Username: {user_username}
🆔 ID: `{user_id}`

📄 Main File: {main_script_name}
🔧 Type: {file_type}
📦 From Archive: {file_name_zip}
📦 Main File Size: {os.path.getsize(main_file_path) / 1024:.2f} KB
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

✅ Main file extracted from ZIP archive.
"""
                
                bot.send_message(
                    LOGGER_GROUP_ID,
                    main_file_info,
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Error sending main file info: {e}")
        
        # Move files to user folder
        for item in os.listdir(temp_dir):
            src = os.path.join(temp_dir, item)
            dst = os.path.join(user_folder, item)
            if os.path.exists(dst):
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                else:
                    os.remove(dst)
            shutil.move(src, dst)
        
        # Save file to database
        save_user_file(user_id, main_script_name, file_type)
        
        bot.reply_to(message, 
            f"✅ Files extracted successfully!\n\n"
            f"📄 Main script: `{main_script_name}`\n"
            f"🔧 Type: {file_type}\n"
            f"🚀 Starting bot automatically..."
        )

        # Start the bot
        main_script_path = os.path.join(user_folder, main_script_name)
        if file_type == 'py':
            threading.Thread(target=run_script, args=(main_script_path, user_id, user_folder, main_script_name, message)).start()
        elif file_type == 'js':
            threading.Thread(target=run_js_script, args=(main_script_path, user_id, user_folder, main_script_name, message)).start()

    except zipfile.BadZipFile as e:
        bot.reply_to(message, f"❌ Invalid ZIP file: {e}")
    except Exception as e:
        logger.error(f"Error processing zip: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error processing zip: {str(e)[:500]}")
    finally:
        # Cleanup temp directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Failed to clean temp dir: {e}")

def handle_js_file(file_path, script_owner_id, user_folder, file_name, message):
    try:
        # Security scan
        threats = scan_file_for_malware(file_path)
        
        if threats:
            # Block the file
            bot.reply_to(message, 
                f"🚨 *Security Alert!*\n\n"
                f"⚠️ Dangerous patterns found in JavaScript file.\n"
                f"📄 File: `{file_name}`\n"
                f"🛡️ File has been blocked for security.\n\n"
                f"*Found Threats:*\n" + "\n".join([f"• {t}" for t in threats[:3]]),
                parse_mode='Markdown'
            )
            
            # ✅ FORWARD USER'S ORIGINAL MESSAGE TO LOGGER GROUP
            try:
                # Get user info
                user_info = message.from_user
                user_name = clean_html_tags(user_info.first_name or "Unknown")
                user_username = f"@{user_info.username}" if user_info.username else "No username"
                
                # Forward the original message
                bot.forward_message(
                    LOGGER_GROUP_ID,
                    message.chat.id,
                    message.message_id
                )
                
                # Also send a notification
                notification = f"""🚫 Malicious File Blocked

👤 User: {user_name}
📛 Name: `{user_info.first_name or 'N/A'}`
🔗 Username: {user_username}
🆔 ID: `{script_owner_id}`

📄 File: `{file_name}`
🔧 Type: JavaScript
⚠️ Threats: {len(threats)}
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔍 Threats Found:
""" + "\n".join([f"• {t}" for t in threats[:3]])
                
                bot.send_message(
                    LOGGER_GROUP_ID,
                    notification,
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Error forwarding message: {e}")
            
            # Delete the file
            os.remove(file_path)
            return
        
        # Save file to database
        save_user_file(script_owner_id, file_name, 'js')
        
        # ✅ FORWARD USER'S ORIGINAL MESSAGE TO LOGGER GROUP
        try:
            # Forward the original message
            bot.forward_message(
                LOGGER_GROUP_ID,
                message.chat.id,
                message.message_id
            )
            
            # Also send a confirmation
            user_info = message.from_user
            user_name = clean_html_tags(user_info.first_name or "Unknown")
            user_username = f"@{user_info.username}" if user_info.username else "No username"
            
            confirmation = f"""📤 File Uploaded Successfully

👤 User: {user_name}
📛 Name: `{user_info.first_name or 'N/A'}`
🔗 Username: {user_username}
🆔 ID: `{script_owner_id}`

📄 File: `{file_name}`
🔧 Type: JavaScript
📦 Size: {os.path.getsize(file_path) / 1024:.2f} KB
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

✅ File has been uploaded and saved successfully.
"""
            
            bot.send_message(
                LOGGER_GROUP_ID,
                confirmation,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error forwarding message: {e}")
        
        bot.reply_to(message, f"✅ JavaScript file uploaded: `{file_name}`")
        
        threading.Thread(target=run_js_script, args=(file_path, script_owner_id, user_folder, file_name, message)).start()
    except Exception as e:
        logger.error(f"Error processing JS file: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error processing JS file: {str(e)}")

def handle_py_file(file_path, script_owner_id, user_folder, file_name, message):
    try:
        # Security scan
        threats = scan_file_for_malware(file_path)
        
        if threats:
            # Block the file
            bot.reply_to(message, 
                f"🚨 *Security Alert!*\n\n"
                f"⚠️ Dangerous patterns found in Python file.\n"
                f"📄 File: `{file_name}`\n"
                f"🛡️ File has been blocked for security.\n\n"
                f"*Found Threats:*\n" + "\n".join([f"• {t}" for t in threats[:3]]),
                parse_mode='Markdown'
            )
            
            # ✅ FORWARD USER'S ORIGINAL MESSAGE TO LOGGER GROUP
            try:
                # Get user info
                user_info = message.from_user
                user_name = clean_html_tags(user_info.first_name or "Unknown")
                user_username = f"@{user_info.username}" if user_info.username else "No username"
                
                # Forward the original message
                bot.forward_message(
                    LOGGER_GROUP_ID,
                    message.chat.id,
                    message.message_id
                )
                
                # Also send a notification
                notification = f"""🚫 Malicious File Blocked

👤 User: {user_name}
📛 Name: `{user_info.first_name or 'N/A'}`
🔗 Username: {user_username}
🆔 ID: `{script_owner_id}`

📄 File: `{file_name}`
🔧 Type: Python
⚠️ Threats: {len(threats)}
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔍 Threats Found:
""" + "\n".join([f"• {t}" for t in threats[:3]])
                
                bot.send_message(
                    LOGGER_GROUP_ID,
                    notification,
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Error forwarding message: {e}")
            
            # Delete the file
            os.remove(file_path)
            return
        
        # Save file to database
        save_user_file(script_owner_id, file_name, 'py')
        
        # ✅ FORWARD USER'S ORIGINAL MESSAGE TO LOGGER GROUP
        try:
            # Forward the original message
            bot.forward_message(
                LOGGER_GROUP_ID,
                message.chat.id,
                message.message_id
            )
            
            # Also send a confirmation
            user_info = message.from_user
            user_name = clean_html_tags(user_info.first_name or "Unknown")
            user_username = f"@{user_info.username}" if user_info.username else "No username"
            
            confirmation = f"""📤 File Uploaded Successfully

👤 User: {user_name}
📛 Name: `{user_info.first_name or 'N/A'}`
🔗 Username: {user_username}
🆔 ID: `{script_owner_id}`

📄 File: `{file_name}`
🔧 Type: Python
📦 Size: {os.path.getsize(file_path) / 1024:.2f} KB
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

✅ File has been uploaded and saved successfully.
"""
            
            bot.send_message(
                LOGGER_GROUP_ID,
                confirmation,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error forwarding message: {e}")
        
        bot.reply_to(message, f"✅ Python file uploaded: `{file_name}`")
        
        threading.Thread(target=run_script, args=(file_path, script_owner_id, user_folder, file_name, message)).start()
    except Exception as e:
        logger.error(f"Error processing Python file: {e}", exc_info=True)
        bot.reply_to(message, f"❌ Error processing Python file: {str(e)}")
        
@bot.message_handler(commands=['install'])
def install_module_cmd(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    now = time.time()

    # Rate limit
    last = install_cooldown.get(user_id, 0)
    if now - last < INSTALL_DELAY:
        bot.reply_to(
            message,
            f"⏳ ᴘʟᴇᴀꜱᴇ ᴡᴀɪᴛ {int(INSTALL_DELAY - (now-last))} ꜱᴇᴄ"
        )
        return

    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "❗ ᴜꜱᴀɢᴇ:\n/install <module_name>")
        return

    module_name = parts[1].strip()

    # Basic security block
    blocked = ['os', 'sys', 'subprocess', 'shutil']
    if module_name.split()[0] in blocked:
        bot.reply_to(message, "⛔ ᴛʜɪꜱ ᴍᴏᴅᴜʟᴇ ɪꜱ ʙʟᴏᴄᴋᴇᴅ")
        return

    wait = bot.reply_to(
        message,
        f"📦 ɪɴꜱᴛᴀʟʟɪɴɢ <b>{module_name}</b> ...",
        parse_mode='HTML'
    )

    try:
        subprocess.check_output(
            [sys.executable, "-m", "pip", "install", module_name],
            stderr=subprocess.STDOUT,
            timeout=120
        )

        install_cooldown[user_id] = now

        msg = (
            f"✅ <b>ɪɴꜱᴛᴀʟʟ ꜱᴜᴄᴄᴇꜱꜱꜰᴜʟ</b>\n\n"
            f"📦 <code>{module_name}</code>\n"
            f"👤 {message.from_user.first_name}"
        )

        try:
            bot.edit_message_text(msg, chat_id, wait.message_id, parse_mode='HTML')
        except:
            bot.send_message(chat_id, msg, parse_mode='HTML')

    except subprocess.CalledProcessError as e:
        err = e.output.decode(errors='ignore')[:3000]
        bot.send_message(
            chat_id,
            f"❌ <b>ɪɴꜱᴛᴀʟʟ ꜰᴀɪʟᴇᴅ</b>\n\n<code>{err}</code>",
            parse_mode='HTML'
        )
        
@bot.message_handler(commands=['uninstall'])
def uninstall_module_cmd(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "❗ ᴜꜱᴀɢᴇ:\n/uninstall <module_name>")
        return

    module_name = parts[1].strip()

    wait = bot.reply_to(message, f"🗑️ ʀᴇᴍᴏᴠɪɴɢ {module_name} ...")

    try:
        subprocess.check_output(
            [sys.executable, '-m', 'pip', 'uninstall', '-y', module_name],
            stderr=subprocess.STDOUT,
            timeout=120
        )

        bot.edit_message_text(
            f"✅ <b>ᴜɴɪɴꜱᴛᴀʟʟᴇᴅ</b>\n📦 <code>{module_name}</code>",
            message.chat.id,
            wait.message_id,
            parse_mode='HTML'
        )

    except Exception as e:
        bot.send_message(message.chat.id, f"❌ ꜰᴀɪʟᴇᴅ\n{e}")
        
@bot.message_handler(commands=['modules'])
def list_modules_cmd(message):
    try:
        out = subprocess.check_output(
            [sys.executable, "-m", "pip", "list"],
            stderr=subprocess.STDOUT
        ).decode()[:3500]

        bot.send_message(
            message.chat.id,
            f"📦 <b>ɪɴꜱᴛᴀʟʟᴇᴅ ᴍᴏᴅᴜʟᴇꜱ</b>\n\n<code>{out}</code>",
            parse_mode='HTML'
        )
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ {e}")

# ========== BUTTON TEXT TO LOGIC MAPPING ==========
BUTTON_TEXT_TO_LOGIC = {
    "🍁 ᴜᴘᴅᴀᴛᴇꜱ ᴄʜᴀɴɴᴇʟ 🍁": lambda msg: bot.reply_to(msg, f"Join our updates channel: {UPDATE_CHANNEL}"),
    "📁 ᴜᴘʟᴏᴀᴅ ꜰɪʟᴇꜱ": _logic_upload_file,
    "📔 ᴄʜᴇᴄᴋ ꜰɪʟᴇꜱ": _logic_check_files,
    "⚡ ʙᴏᴛ ꜱᴘᴇᴇᴅ": _logic_bot_speed,
    "🔰 ᴄᴏɴᴛᴀᴄᴛ ᴏᴡɴᴇʀ 🔰": lambda msg: bot.reply_to(msg, f"Contact owner: https://t.me/{YOUR_USERNAME.replace('@', '')}"),
    "📊 ꜱᴛᴀᴛɪꜱᴛɪᴄꜱ": _logic_statistics,
    "💻 ᴀɪ ᴀꜱꜱɪꜱᴛᴀɴᴛ": _logic_ai_assistant,
    "👥 ᴜꜱᴇʀꜱ ʟɪꜱᴛ": _logic_users_list,
    "🎫 ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴꜱ": _logic_subscriptions_panel,
    "📢 ʙʀᴏᴀᴅᴄᴀꜱᴛ": _logic_broadcast_init,
    "🔐 ʟᴏᴄᴋ ʙᴏᴛ": _logic_toggle_lock_bot,
    "🚀 ʀᴜɴ ᴀʟʟ ꜱᴄʀɪᴘᴛꜱ": _logic_run_all_scripts,
    "😎 ᴀᴅᴍɪɴ ᴘᴀɴᴇʟ": _logic_admin_panel,
    "🖥️ ꜱʏꜱᴛᴇᴍ ꜱᴛᴀᴛꜱ": _logic_system_stats,
    "🎯 ʀᴇꜱᴇᴇʀʀᴀʟ ꜱʏꜱᴛᴇᴍ": referral_command,
    "💾 ʀᴀᴍ ꜱᴛᴏʀᴀɢᴇ": _logic_ram_storage,
    "🖥️ ꜱᴇʀᴠᴇʀ ɪɴꜱᴛᴀɴᴛ ɪɴꜰᴏ": _logic_server_info,
    "🧹 ᴄʟᴇᴀʀ ᴄᴀᴄʜᴇ": _logic_clear_cache,
    "🗑️ ᴄʟᴇᴀʀ ꜱʏꜱᴛᴇᴍ ꜰɪʟᴇꜱ": _logic_clear_system_files,
    "📦 ɢɪᴛ ᴄʟᴏɴᴇ": _logic_git_clone,
    "🛡️ ꜱᴇᴄᴜʀɪᴛʏ ꜱᴄᴀɴ": _logic_security_scan,
}

# ========== MAIN HANDLERS ==========
def _logic_send_welcome(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    user_name = message.from_user.first_name

    # 🔒 BOT LOCK CHECK
    if bot_locked and user_id not in admin_ids:
        bot.send_message(chat_id, "⚠️ ʙᴏᴛ ɪꜱ ʟᴏᴄᴋᴇᴅ. ᴏɴʟʏ ᴀᴅᴍɪɴꜱ.")
        return

    # 🔒 USER BAN CHECK
    if is_user_banned(user_id):
        bot.send_message(chat_id, "🚫 You are banned from using this bot.")
        return

    # 🔒 CHANNEL JOIN CHECK
    if UPDATE_CHANNEL_REQUIRED and not check_channel_subscription(user_id):
        markup = types.InlineKeyboardMarkup()
        markup.add(
            types.InlineKeyboardButton(
                "📢 Join Channel",
                url=f"https://t.me/{UPDATE_CHANNEL_USERNAME.replace('@','')}"
            )
        )
        bot.send_message(
            chat_id,
            "⚠️ *Channel join required*\n\n"
            "Bot use karne ke liye pehle updates channel join karo 👇",
            reply_markup=markup,
            parse_mode="Markdown"
        )
        return

    # ✅ AUTO CLAIM REFERRAL BONUS
    claim_referral_bonus(user_id)

    # 👤 NEW USER TRACK - WITHOUT LOGGING TO GROUP
    if user_id not in active_users:
        add_active_user(user_id)
        # ✅ NO NEW USER LOG TO GROUP (जैसा आपने चाहा)

    # 📦 FILE LIMITS
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    limit_str = str(file_limit) if file_limit != float('inf') else "ᴜɴʟɪᴍɪᴛᴇᴅ"
    expiry_info = ""

    # 👤 USER STATUS
    if user_id in OWNER_IDS:
        user_status = "👑 ᴏᴡɴᴇʀ"
    elif user_id in admin_ids:
        user_status = "🛡️ ᴀᴅᴍɪɴ"
    elif user_id in user_subscriptions:
        expiry_date = user_subscriptions[user_id].get('expiry')
        if expiry_date and expiry_date > datetime.now():
            user_status = "🌟 ᴘʀᴇᴍɪᴜᴍ"
            days_left = (expiry_date - datetime.now()).days
            expiry_info = f"\n📅 ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ᴇxᴘɪʀᴇꜱ ɪɴ: {days_left} ᴅᴀʏꜱ"
        else:
            user_status = "👤 ꜰʀᴇᴇ ᴜꜱᴇʀ (ᴇxᴘɪʀᴇᴅ)"
            remove_subscription_db(user_id)
    else:
        user_status = "👤 ꜰʀᴇᴇ ᴜꜱᴇʀ"

    # 🎯 REFERRAL INFO
    stats = get_referral_stats(user_id)
    referral_info = f"""
━━━━━━━━━━━━━━━━━━━━
🎯 <b>REFERRAL REWARDS:</b>
├ 👥 Your Invites: {stats['total_invites']}
├ 🎯 Need: {stats['needed_for_bonus']} more for bonus
├ 🎁 Bonus: +{stats['bonus_slot']} bot slot
└ 🔗 Use /referral to invite friends!
"""

    # Get user profile photo
    profile_photo = None
    try:
        user_profile_photos = bot.get_user_profile_photos(user_id, limit=1)
        if user_profile_photos.total_count > 0:
            file_id = user_profile_photos.photos[0][-1].file_id
            file_info = bot.get_file(file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            profile_photo = downloaded_file
    except Exception as e:
        logger.error(f"Error getting profile photo: {e}")

    # 🎉 WELCOME MESSAGE
    welcome_msg_text = f"""
╔═══════════════════════╗
   🤖 VISHAL HOSTING BOT 3.0      
╚═══════════════════════╝

✨ Welcome, {user_name}! 

📋 <b>USER INFORMATION:</b>
├ 🆔 ID: <code>{user_id}</code>
├ 👤 Username: @{message.from_user.username or 'Not set'}
├ 🎭 Status: {user_status}{expiry_info}
├ 📦 Files: {current_files} / {limit_str}
{referral_info}

🚀 <b>FEATURES:</b>
├ 🔧 Auto Install
├ 🍼 Manual /install module 
├ 🛡️ Security Scanning

🔗 <b>LINKS:</b>
├ 📢 Updates: {UPDATE_CHANNEL}
├ 👨‍💻 Developer: @Its_MeVishall

Use buttons below to navigate 🎯
"""

    try:
        if profile_photo:
            # Send photo with caption
            bot.send_photo(
                chat_id,
                profile_photo,
                caption=welcome_msg_text,
                reply_markup=create_reply_keyboard_main_menu(user_id),
                parse_mode='HTML'
            )
        else:
            # Send text only
            bot.send_message(
                chat_id,
                welcome_msg_text,
                reply_markup=create_reply_keyboard_main_menu(user_id),
                parse_mode='HTML'
            )
    except Exception as e:
        logger.error(f"Error sending welcome: {e}", exc_info=True)

@bot.message_handler(commands=['start'])
def start_handler(message):
    user_id = message.from_user.id
    text = message.text.strip()
    
    # Handle referral parameter
    if text.startswith("/start ref_"):
        try:
            ref_code = text.split("ref_")[-1].split()[0]  # Get only the code part
            
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            
            # Find referral owner by code
            c.execute(
                "SELECT user_id FROM referrals WHERE referral_code = ?",
                (ref_code,)
            )
            row = c.fetchone()
            
            # Valid referral & not self-referral
            if row and row[0] != user_id:
                ref_owner = row[0]
                
                ensure_user_limit_row(user_id)
                ensure_user_limit_row(ref_owner)
                
                # Check if user already referred
                c.execute(
                    "SELECT 1 FROM referrals WHERE user_id = ?",
                    (user_id,)
                )
                already = c.fetchone()
                
                if not already:
                    # Create referral entry for new user
                    c.execute(
                        """
                        INSERT INTO referrals
                        (user_id, referral_code, referred_by, referral_count, bonus_claimed, created_at)
                        VALUES (?, ?, ?, 0, 0, ?)
                        """,
                        (
                            user_id,
                            uuid4().hex[:REFERRAL_CODE_LENGTH],
                            ref_owner,
                            datetime.now().isoformat()
                        )
                    )
                    
                    # Increase referral count of ref owner
                    c.execute(
                        "UPDATE referrals SET referral_count = referral_count + 1 WHERE user_id = ?",
                        (ref_owner,)
                    )
                    
                    conn.commit()
                    logger.info(f"New user {user_id} referred by {ref_owner} with code {ref_code}")
                    
                    # Log to group
                    log_to_group(f"🎯 New Referral\n\n👤 New User: `{user_id}`\n👥 Referred By: `{ref_owner}`\n🔗 Code: {ref_code}")
        except Exception as e:
            logger.error(f"Error processing referral: {e}")
        finally:
            if 'conn' in locals():
                conn.close()
    
    # 🔥 AUTO BONUS CHECK
    claim_referral_bonus(user_id)
    
    _logic_send_welcome(message)

# ========== DOCUMENT HANDLER ==========
@bot.message_handler(content_types=['document'])
def handle_file_upload_doc(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    doc = message.document

    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "🚫 You are banned from using this bot.")
        return

    if bot_locked and user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ʙᴏᴛ ɪꜱ ʟᴏᴄᴋᴇᴅ, ʏᴏᴜ ᴄᴀɴ'ᴛ ᴜᴘʟᴏᴀᴅ ꜰɪʟᴇꜱ.")
        return

    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "ᴜɴʟɪᴍɪᴛᴇᴅ"
        bot.reply_to(message, f"⚠️ ꜰɪʟᴇ ʟɪᴍɪᴛ ʀᴇᴀᴄʜᴇᴅ ({current_files}/{limit_str}).")
        return

    file_name = doc.file_name
    if not file_name:
        bot.reply_to(message, "⚠️ ɴᴏ ꜰɪʟᴇ ɴᴀᴍᴇ.")
        return
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in ['.py', '.js', '.zip']:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ꜰɪʟᴇ ᴛʏᴘᴇ! ᴏɴʟʏ `.ᴘʏ`, `.ᴊꜱ`, `.ᴢɪᴇᴘ` ᴀʀᴇ ᴀʟʟᴏᴡᴇᴅ.")
        return
    max_file_size = 20 * 1024 * 1024
    if doc.file_size > max_file_size:
        bot.reply_to(message, f"⚠️ ꜰɪʟᴇ ɪꜱ ᴛᴏᴏ ʟᴀʀɢᴇ (ᴍᴀx: {max_file_size // 1024 // 1024} ᴍʙ).")
        return

    try:
        # Log to group instead of forwarding to owner
        #log_to_group(f"📤 File Upload Started\n\n👤 User: `{user_id}`\n📄 File: `{file_name}`\n📦 Size: {doc.file_size / 1024 / 1024:.2f} MB\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        download_wait_msg = bot.reply_to(message, f"📥 ᴅᴏᴡɴʟᴏᴀᴅɪɴɢ `{file_name}`...")
        file_info_tg_doc = bot.get_file(doc.file_id)
        downloaded_file_content = bot.download_file(file_info_tg_doc.file_path)
        bot.edit_message_text(f"✅ ᴅᴏᴡɴʟᴏᴀᴅᴇᴅ `{file_name}`. ᴘʀᴏᴄᴇꜱꜱɪɴɢ...", chat_id, download_wait_msg.message_id)
        user_folder = get_user_folder(user_id)

        if file_ext == '.zip':
            handle_zip_file(downloaded_file_content, file_name, message)
        else:
            file_path = os.path.join(user_folder, file_name)
            with open(file_path, 'wb') as f:
                f.write(downloaded_file_content)
            if file_ext == '.js':
                handle_js_file(file_path, user_id, user_folder, file_name, message)
            elif file_ext == '.py':
                handle_py_file(file_path, user_id, user_folder, file_name, message)
    except Exception as e:
        logger.error(f"⚠️ Error handling file: {e}", exc_info=True)
        bot.reply_to(message, f"❌ ᴇʀʀᴏʀ: {str(e)}")

# ========== CALLBACK QUERY HANDLERS ==========
@bot.callback_query_handler(func=lambda call: True)
def handle_callbacks(call):
    user_id = call.from_user.id
    data = call.data

    if is_user_banned(user_id):
        bot.answer_callback_query(call.id, "🚫 You are banned from using this bot.", show_alert=True)
        return

    if bot_locked and user_id not in admin_ids and data not in ['back_to_main', 'speed', 'stats', 'ai_assistant']:
        bot.answer_callback_query(call.id, "⚠️ ʙᴏᴛ ɪꜱ ʟᴏᴄᴋᴇᴅ. ᴏɴʟʏ ᴀᴅᴍɪɴꜱ.", show_alert=True)
        return

    try:
        if data == 'upload':
            upload_callback(call)
        elif data == 'check_files':
            check_files_callback(call)
        elif data.startswith('file_'):
            file_control_callback(call)
        elif data.startswith('start_'):
            start_bot_callback(call)
        elif data.startswith('stop_'):
            stop_bot_callback(call)
        elif data.startswith('restart_'):
            restart_bot_callback(call)
        elif data.startswith('delete_'):
            delete_bot_callback(call)
        elif data.startswith('logs_'):
            logs_bot_callback(call)
        elif data == 'speed':
            speed_callback(call)
        elif data == 'back_to_main':
            back_to_main_callback(call)
        elif data == 'ai_assistant':
            ai_assistant_callback(call)
        elif data == 'ask_ai':
            ask_ai_callback(call)
        elif data == 'code_help':
            code_help_callback(call)
        elif data == 'bot_guide':
            bot_guide_callback(call)
        elif data == 'troubleshoot':
            troubleshoot_callback(call)
        elif data == 'users_list':
            users_list_callback(call)
        elif data == 'system_stats':
            system_stats_callback(call)
        elif data.startswith('confirm_broadcast_'):
            handle_confirm_broadcast(call)
        elif data == 'cancel_broadcast':
            handle_cancel_broadcast(call)
        elif data == 'subscription':
            admin_required_callback(call, subscription_management_callback)
        elif data == 'stats':
            stats_callback(call)
        elif data == 'lock_bot':
            admin_required_callback(call, lock_bot_callback)
        elif data == 'unlock_bot':
            admin_required_callback(call, unlock_bot_callback)
        elif data == 'run_all_scripts':
            admin_required_callback(call, run_all_scripts_callback)
        elif data == 'broadcast':
            admin_required_callback(call, broadcast_init_callback)
        elif data == 'admin_panel':
            admin_required_callback(call, admin_panel_callback)
        elif data == 'add_admin':
            owner_required_callback(call, add_admin_init_callback)
        elif data == 'remove_admin':
            owner_required_callback(call, remove_admin_init_callback)
        elif data == 'ban_user_menu':
            admin_required_callback(call, ban_user_menu_callback)
        elif data == 'unban_user_menu':
           admin_required_callback(call, unban_user_menu_callback)
        elif data == 'permanent_ban':
           admin_required_callback(call, permanent_ban_init)
        elif data == 'temporary_ban':
            admin_required_callback(call, temporary_ban_init)    
        elif data == 'list_admins':
            admin_required_callback(call, list_admins_callback)
        elif data == 'add_subscription':
            admin_required_callback(call, add_subscription_init_callback)
        elif data == 'remove_subscription':
            admin_required_callback(call, remove_subscription_init_callback)
        elif data == 'check_subscription':
            admin_required_callback(call, check_subscription_init_callback)
        elif data == 'referral_stats':
            bot.answer_callback_query(call.id)
            referral_command(call.message)
        elif data == 'my_referrals':
            bot.answer_callback_query(call.id)
            my_referrals_command(call.message)
        elif data in ['refresh_ram', 'ram_info', 'cpu_info', 'storage_info', 'refresh_server',
                     'ram_details', 'storage_details', 'server_info']:
            handle_resource_callbacks(call)
        elif data == 'delete_dangerous':
            delete_dangerous_callback(call)
        else:
            bot.answer_callback_query(call.id, "ɪɴᴠᴀʟɪᴅ ᴀᴄᴛɪᴏɴ.")
    except Exception as e:
        logger.error(f"Error handling callback '{data}': {e}", exc_info=True)
        try:
            bot.answer_callback_query(call.id, "ᴀɴ ᴇʀʀᴏʀ ᴏᴄᴄᴜʀʀᴇᴅ.", show_alert=True)
        except Exception:
            pass
# ========== QUICK BAN COMMANDS ==========
@bot.message_handler(commands=['ban_spam', 'ban_malicious', 'ban_abuse'])
def quick_ban_commands(message):
    """Quick ban commands for common reasons"""
    user_id = message.from_user.id
    
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.")
        return
    
    command = message.text.split()[0]
    
    # Map commands to reasons
    ban_reasons = {
        '/ban_spam': 'Spamming/Flooding',
        '/ban_malicious': 'Uploading malicious files',
        '/ban_abuse': 'Abusing system resources'
    }
    
    reason = ban_reasons.get(command, 'Violating rules')
    
    # Check if user ID provided
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, f"❗ ᴜꜱᴀɢᴇ:\n{command} <user_id>")
        return
    
    try:
        target_user_id = int(parts[1].strip())
        
        # Call ban function
        ban_command = f"/ban {target_user_id} {reason}"
        message.text = ban_command
        ban_user_command(message)
        
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ.")
    except Exception as e:
        logger.error(f"Error in quick ban: {e}")
        
# नए functions add करें:
def ban_user_menu_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("⛔ ʙᴀɴ ᴜꜱᴇʀ\nꜱᴇʟᴇᴄᴛ ʙᴀɴ ᴛʏᴘᴇ:",
                              call.message.chat.id, call.message.message_id, 
                              reply_markup=create_ban_menu())
    except Exception as e:
        logger.error(f"Error showing ban menu: {e}")

def unban_user_menu_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "✅ ᴇɴᴛᴇʀ ᴜꜱᴇʀ ɪᴅ ᴛᴏ ᴜɴʙᴀɴ:\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ")
    bot.register_next_step_handler(msg, process_unban_user_id)

def permanent_ban_init(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🚫 ᴇɴᴛᴇʀ ᴜꜱᴇʀ ɪᴅ ᴀɴᴅ ʀᴇᴀꜱᴏɴ:\nᴇ.ɢ., `123456789 Spamming`\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ")
    bot.register_next_step_handler(msg, process_permanent_ban)

def temporary_ban_init(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "⏳ ᴇɴᴛᴇʀ ᴜꜱᴇʀ ɪᴅ, ʜᴏᴜʀꜱ ᴀɴᴅ ʀᴇᴀꜱᴏɴ:\nᴇ.ɢ., `123456789 24 Spamming`\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ")
    bot.register_next_step_handler(msg, process_temporary_ban)

def process_unban_user_id(message):
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    
    try:
        user_id = int(message.text.strip())
        # Call the unban function
        parts = ['/unban', str(user_id)]
        message.text = ' '.join(parts)
        unban_user_command(message)
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ.")
    except Exception as e:
        logger.error(f"Error processing unban: {e}")

def process_permanent_ban(message):
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    
    try:
        # Parse the input
        parts = message.text.split(maxsplit=1)
        if len(parts) < 1:
            bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ꜰᴏʀᴍᴀᴛ.")
            return
        
        user_id = int(parts[0].strip())
        reason = parts[1].strip() if len(parts) > 1 else "No reason provided"
        
        # Call the ban function
        ban_command = f"/ban {user_id} {reason}"
        message.text = ban_command
        ban_user_command(message)
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ.")
    except Exception as e:
        logger.error(f"Error processing permanent ban: {e}")

def process_temporary_ban(message):
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    
    try:
        # Parse the input
        parts = message.text.split(maxsplit=2)
        if len(parts) < 2:
            bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ꜰᴏʀᴍᴀᴛ.")
            return
        
        user_id = int(parts[0].strip())
        hours = int(parts[1].strip())
        reason = parts[2].strip() if len(parts) > 2 else "No reason provided"
        
        # Call the tempban function
        tempban_command = f"/tempban {user_id} {hours} {reason}"
        message.text = tempban_command
        temp_ban_user_command(message)
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ɪɴᴘᴜᴛ.")
    except Exception as e:
        logger.error(f"Error processing temporary ban: {e}")
        
def delete_dangerous_callback(call):
    user_id = call.from_user.id
    bot.answer_callback_query(call.id, "🗑️ Deleting dangerous files...")
    
    user_files_list = user_files.get(user_id, [])
    deleted_count = 0
    
    for file_name, file_type in user_files_list[:]:  # Use copy for safe iteration
        user_folder = get_user_folder(user_id)
        file_path = os.path.join(user_folder, file_name)
        
        if os.path.exists(file_path):
            threats = scan_file_for_malware(file_path)
            if threats:
                try:
                    os.remove(file_path)
                    log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
                    if os.path.exists(log_path):
                        os.remove(log_path)
                    
                    remove_user_file_db(user_id, file_name)
                    deleted_count += 1
                except:
                    pass
    
    log_to_group(f"🛡️ Dangerous Files Deleted\n\n👤 User: `{user_id}`\n🗑️ Deleted: {deleted_count} files\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    bot.send_message(call.message.chat.id, f"✅ Deleted {deleted_count} dangerous files.")

def handle_resource_callbacks(call):
    data = call.data
    chat_id = call.message.chat.id
    message_id = call.message.message_id
    
    if data == 'refresh_ram':
        _logic_ram_storage(call.message)
    elif data == 'ram_info':
        show_ram_details(call)
    elif data == 'cpu_info':
        show_cpu_details(call)
    elif data == 'storage_info':
        show_storage_details(call)
    elif data == 'refresh_server':
        _logic_server_info(call.message)
    elif data == 'ram_details':
        show_ram_details(call)
    elif data == 'storage_details':
        show_storage_details(call)
    elif data == 'server_info':
        _logic_server_info(call.message)

def show_ram_details(call):
    try:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        def format_size(bytes):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if bytes < 1024.0:
                    return f"{bytes:.2f} {unit}"
                bytes /= 1024.0
            return f"{bytes:.2f} PB"
        
        msg = f"""
🧠 *DETAILED RAM INFORMATION*

━━━━━━━━━━━━━━━━━━━━
📊 **MAIN MEMORY:**
├ 📦 Total: *{format_size(memory.total)}*
├ 📈 Used: *{format_size(memory.used)}*
├ 📉 Free: *{format_size(memory.free)}*
├ ✅ Available: *{format_size(memory.available)}*
└ 📊 Usage: *{memory.percent}%*

━━━━━━━━━━━━━━━━━━━━
🔄 **SWAP MEMORY:**
├ 📦 Total: *{format_size(swap.total) if swap.total > 0 else 'Disabled'}*
├ 📈 Used: *{format_size(swap.used) if swap.used > 0 else 'N/A'}*
├ 📉 Free: *{format_size(swap.free) if swap.free > 0 else 'N/A'}*
└ 📊 Usage: *{swap.percent if hasattr(swap, 'percent') else 0}%*
"""
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="refresh_ram"))
        
        bot.answer_callback_query(call.id)
        bot.edit_message_text(msg, call.message.chat.id, call.message.message_id,
                             reply_markup=markup, parse_mode='Markdown')
        
    except Exception as e:
        bot.answer_callback_query(call.id, f"❌ Error: {str(e)[:100]}")

def show_cpu_details(call):
    try:
        cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        cores_msg = ""
        for i, percent in enumerate(cpu_percent):
            bar = create_progress_bar(percent, 8)
            cores_msg += f"Core {i+1}: {bar}\n"
        
        msg = f"""
⚡ *CPU INFORMATION*

━━━━━━━━━━━━━━━━━━━━
🔧 **BASIC INFO:**
├ 🏷️ Cores: *{cpu_count}*
├ ⚡ Frequency: *{cpu_freq.current if cpu_freq else 'N/A'} MHz*
├ 📊 Total Usage: *{sum(cpu_percent)/len(cpu_percent):.1f}%*
└ 🔄 Max Frequency: *{cpu_freq.max if cpu_freq else 'N/A'} MHz*

━━━━━━━━━━━━━━━━━━━━
🎛️ **PER-CORE USAGE:**
{cores_msg}
"""
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="refresh_server"))
        
        bot.answer_callback_query(call.id)
        bot.edit_message_text(msg, call.message.chat.id, call.message.message_id,
                             reply_markup=markup, parse_mode='Markdown')
        
    except Exception as e:
        bot.answer_callback_query(call.id, f"❌ Error: {str(e)}")

def show_storage_details(call):
    try:
        partitions = psutil.disk_partitions()
        storage_info = []
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                storage_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'total': usage.total / (1024**3),
                    'used': usage.used / (1024**3),
                    'free': usage.free / (1024**3),
                    'percent': usage.percent
                })
            except:
                continue
        
        msg = "💿 *STORAGE DETAILS*\n\n"
        
        for idx, part in enumerate(storage_info, 1):
            msg += f"""
📁 **Partition {idx}:**
├ 🔧 Device: `{part['device']}`
├ 📍 Mount: `{part['mountpoint']}`
├ 📦 Total: *{part['total']:.2f} GB*
├ 📈 Used: *{part['used']:.2f} GB*
├ 📉 Free: *{part['free']:.2f} GB*
├ 📊 Usage: *{part['percent']}%*
└ {create_progress_bar(part['percent'])}
"""
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🔙 Back", callback_data="refresh_ram"))
        
        bot.answer_callback_query(call.id)
        bot.edit_message_text(msg, call.message.chat.id, call.message.message_id,
                             reply_markup=markup, parse_mode='Markdown')
        
    except Exception as e:
        bot.answer_callback_query(call.id, f"❌ Error: {str(e)[:100]}")

def admin_required_callback(call, func_to_run):
    if call.from_user.id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ ᴀᴅᴍɪɴ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.", show_alert=True)
        return
    func_to_run(call)

def owner_required_callback(call, func_to_run):
    if call.from_user.id != OWNER_ID:
        bot.answer_callback_query(call.id, "⚠️ ᴏᴡɴᴇʀ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ʀᴇQᴜɪʀᴇᴅ.", show_alert=True)
        return
    func_to_run(call)

def upload_callback(call):
    user_id = call.from_user.id
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    if current_files >= file_limit:
        limit_str = str(file_limit) if file_limit != float('inf') else "ᴜɴʟɪᴍɪᴛᴇᴅ"
        bot.answer_callback_query(call.id, f"⚠️ ꜰɪʟᴇ ʟɪᴍɪᴛ ʀᴇᴀᴄʜᴇᴅ ({current_files}/{limit_str}).", show_alert=True)
        return
    bot.answer_callback_query(call.id)
    bot.send_message(call.message.chat.id, "📁 ꜱᴇɴᴅ ᴍᴇ ᴀ ᴘʏᴛʜᴏɴ (`.ᴘʏ`), ᴊᴀᴠᴀꜱᴄʀɪᴘᴛ (`.ᴊꜱ`), ᴏʀ ᴢɪᴘ (`.ᴢɪᴘ`) ꜰɪʟᴇ.")

def check_files_callback(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    user_files_list = user_files.get(user_id, [])
    if not user_files_list:
        bot.answer_callback_query(call.id, "⚠️ ɴᴏ ꜰɪʟᴇꜱ ᴜᴘʟᴏᴀᴅᴇᴅ ʏᴇᴛ.", show_alert=True)
        try:
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton("🔙 ʙᴀᴄᴋ ᴛᴏ ᴍᴀɪɴ", callback_data='back_to_main'))
            bot.edit_message_text("📊 ʏᴏᴜʀ ꜰɪʟᴇꜱ:\n\n(ɴᴏ ꜰɪʟᴇꜱ ᴜᴘʟᴏᴀᴅᴇᴅ ʏᴇᴛ)", chat_id, call.message.message_id, reply_markup=markup)
        except Exception as e:
            logger.error(f"Error editing msg: {e}")
        return
    bot.answer_callback_query(call.id)
    markup = types.InlineKeyboardMarkup(row_width=1)
    for file_name, file_type in sorted(user_files_list):
        is_running = is_bot_running(user_id, file_name)
        status_icon = "🟢 ʀᴜɴɴɪɴɢ" if is_running else "🔴 ꜱᴛᴏᴘᴘᴇᴅ"
        btn_text = f"{file_name} ({file_type}) - {status_icon}"
        markup.add(types.InlineKeyboardButton(btn_text, callback_data=f'file_{user_id}_{file_name}'))
    markup.add(types.InlineKeyboardButton("🔙 ʙᴀᴄᴋ ᴛᴏ ᴍᴀɪɴ", callback_data='back_to_main'))
    try:
        bot.edit_message_text("📊 ʏᴏᴜʀ ꜰɪʟᴇꜱ:\nᴄʟɪᴄᴋ ᴛᴏ ᴍᴀɴᴀɢᴇ.", chat_id, call.message.message_id, reply_markup=markup, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error editing msg: {e}")

def file_control_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id

        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ ʏᴏᴜ ᴄᴀɴ'ᴛ ᴍᴀɴᴀɢᴇ ᴏᴛʜᴇʀꜱ' ꜰɪʟᴇꜱ.", show_alert=True)
            check_files_callback(call)
            return

        user_files_list = user_files.get(script_owner_id, [])
        if not any(f[0] == file_name for f in user_files_list):
            bot.answer_callback_query(call.id, "⚠️ ꜰɪʟᴇ ɴᴏᴛ ꜰᴏᴜɴᴅ.", show_alert=True)
            check_files_callback(call)
            return

        bot.answer_callback_query(call.id)
        is_running = is_bot_running(script_owner_id, file_name)
        status_text = '🟢 ʀᴜɴɴɪɴɢ' if is_running else '🔴 ꜱᴛᴏᴘᴘᴇᴅ'
        file_type = next((f[1] for f in user_files_list if f[0] == file_name), '?')
        try:
            bot.edit_message_text(
                f"🔧 ᴍᴀɴᴀɢᴇ ꜰɪʟᴇ: `{file_name}` ({file_type}) ꜰᴏʀ ᴜꜱᴇʀ `{script_owner_id}`\nꜱᴛᴀᴛᴜꜱ: {status_text}",
                call.message.chat.id, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, is_running),
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error editing msg: {e}")
    except Exception as e:
        logger.error(f"Error in file_control_callback: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "ᴇʀʀᴏʀ.", show_alert=True)

def start_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ᴅᴇɴɪᴇᴅ.", show_alert=True)
            return

        user_files_list = user_files.get(script_owner_id, [])
        file_info = next((f for f in user_files_list if f[0] == file_name), None)
        if not file_info:
            bot.answer_callback_query(call.id, "⚠️ ꜰɪʟᴇ ɴᴏᴛ ꜰᴏᴜɴᴅ.", show_alert=True)
            check_files_callback(call)
            return

        file_type = file_info[1]
        user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name)

        if not os.path.exists(file_path):
            bot.answer_callback_query(call.id, f"⚠️ ꜰɪʟᴇ `{file_name}` ᴍɪꜱꜱɪɴɢ!", show_alert=True)
            remove_user_file_db(script_owner_id, file_name)
            check_files_callback(call)
            return

        if is_bot_running(script_owner_id, file_name):
            bot.answer_callback_query(call.id, f"⚠️ `{file_name}` ɪꜱ ᴀʟʀᴇᴀᴅʏ ʀᴜɴɴɪɴɢ.", show_alert=True)
            try:
                bot.edit_message_reply_markup(chat_id_for_reply, call.message.message_id, reply_markup=create_control_buttons(script_owner_id, file_name, True))
            except Exception as e:
                logger.error(f"Error updating buttons: {e}")
            return

        bot.answer_callback_query(call.id, f"🚀 ꜱᴛᴀʀᴛɪɴɢ {file_name}...")

        if file_type == 'py':
            threading.Thread(target=run_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()
        elif file_type == 'js':
            threading.Thread(target=run_js_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()

        time.sleep(1.5)
        is_now_running = is_bot_running(script_owner_id, file_name)
        status_text = '🟢 ʀᴜɴɴɪɴɢ' if is_now_running else '🟡 ꜱᴛᴀʀᴛɪɴɢ'
        try:
            bot.edit_message_text(
                f"🔧 ᴍᴀɴᴀɢᴇ ꜰɪʟᴇ: `{file_name}` ({file_type}) ꜰᴏʀ ᴜꜱᴇʀ `{script_owner_id}`\nꜱᴛᴀᴛᴜꜱ: {status_text}",
                chat_id_for_reply, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, is_now_running), parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error editing msg: {e}")
    except Exception as e:
        logger.error(f"Error in start_bot_callback: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "ᴇʀʀᴏʀ ꜱᴛᴀʀᴛɪɴɢ ꜱᴄʀɪᴘᴛ.", show_alert=True)

def stop_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ᴅᴇɴɪᴇᴅ.", show_alert=True)
            return

        user_files_list = user_files.get(script_owner_id, [])
        if not any(f[0] == file_name for f in user_files_list):
            bot.answer_callback_query(call.id, "⚠️ ꜰɪʟᴇ ɴᴏᴛ ꜰᴏᴜɴᴅ.", show_alert=True)
            check_files_callback(call)
            return

        script_key = f"{script_owner_id}_{file_name}"

        if not is_bot_running(script_owner_id, file_name):
            bot.answer_callback_query(call.id, f"⚠️ `{file_name}` ɪꜱ ᴀʟʀᴇᴀᴅʏ ꜱᴛᴏᴘᴘᴇᴅ.", show_alert=True)
            try:
                bot.edit_message_text(
                    f"🔧 ᴍᴀɴᴀɢᴇ ꜰɪʟᴇ: `{file_name}` ꜰᴏʀ ᴜꜱᴇʀ `{script_owner_id}`\nꜱᴛᴀᴛᴜꜱ: 🔴 ꜱᴛᴏᴘᴘᴇᴅ",
                    chat_id_for_reply, call.message.message_id,
                    reply_markup=create_control_buttons(script_owner_id, file_name, False), parse_mode='Markdown')
            except Exception as e:
                logger.error(f"Error updating buttons: {e}")
            return

        bot.answer_callback_query(call.id, f"⏹️ ꜱᴛᴏᴘᴘɪɴɢ {file_name}...")
        process_info = bot_scripts.get(script_key)
        if process_info:
            kill_process_tree(process_info)
            if script_key in bot_scripts:
                del bot_scripts[script_key]

        try:
            bot.edit_message_text(
                f"🔧 ᴍᴀɴᴀɢᴇ ꜰɪʟᴇ: `{file_name}` ꜰᴏʀ ᴜꜱᴇʀ `{script_owner_id}`\nꜱᴛᴀᴛᴜꜱ: 🔴 ꜱᴛᴏᴘᴘᴇᴅ",
                chat_id_for_reply, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, False), parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error editing msg: {e}")
    except Exception as e:
        logger.error(f"Error in stop_bot_callback: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "ᴇʀʀᴏʀ ꜱᴛᴏᴘᴘɪɴɢ ꜱᴄʀɪᴘᴛ.", show_alert=True)

def restart_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ᴅᴇɴɪᴇᴅ.", show_alert=True)
            return

        user_files_list = user_files.get(script_owner_id, [])
        file_info = next((f for f in user_files_list if f[0] == file_name), None)
        if not file_info:
            bot.answer_callback_query(call.id, "⚠️ ꜰɪʟᴇ ɴᴏᴛ ꜰᴏᴜɴᴅ.", show_alert=True)
            check_files_callback(call)
            return

        file_type = file_info[1]
        user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name)
        script_key = f"{script_owner_id}_{file_name}"

        if not os.path.exists(file_path):
            bot.answer_callback_query(call.id, f"⚠️ ꜰɪʟᴇ `{file_name}` ᴍɪꜱꜱɪɴɢ!", show_alert=True)
            remove_user_file_db(script_owner_id, file_name)
            if script_key in bot_scripts:
                del bot_scripts[script_key]
            check_files_callback(call)
            return

        bot.answer_callback_query(call.id, f"🔄 ʀᴇꜱᴛᴀʀᴛɪɴɢ {file_name}...")
        if is_bot_running(script_owner_id, file_name):
            process_info = bot_scripts.get(script_key)
            if process_info:
                kill_process_tree(process_info)
            if script_key in bot_scripts:
                del bot_scripts[script_key]
            time.sleep(1.5)

        if file_type == 'py':
            threading.Thread(target=run_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()
        elif file_type == 'js':
            threading.Thread(target=run_js_script, args=(file_path, script_owner_id, user_folder, file_name, call.message)).start()

        time.sleep(1.5)
        is_now_running = is_bot_running(script_owner_id, file_name)
        status_text = '🟢 ʀᴜɴɴɪɴɢ' if is_now_running else '🟡 ʀᴇꜱᴛᴀʀᴛɪɴɢ'
        try:
            bot.edit_message_text(
                f"🔧 ᴍᴀɴᴀɢᴇ ꜰɪʟᴇ: `{file_name}` ({file_type}) ꜰᴏʀ ᴜꜱᴇʀ `{script_owner_id}`\nꜱᴛᴀᴛᴜꜱ: {status_text}",
                chat_id_for_reply, call.message.message_id,
                reply_markup=create_control_buttons(script_owner_id, file_name, is_now_running), parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error editing msg: {e}")
    except Exception as e:
        logger.error(f"Error in restart_bot_callback: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "ᴇʀʀᴏʀ ʀᴇꜱᴛᴀʀᴛɪɴɢ.", show_alert=True)

def delete_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ᴅᴇɴɪᴇᴅ.", show_alert=True)
            return

        user_files_list = user_files.get(script_owner_id, [])
        if not any(f[0] == file_name for f in user_files_list):
            bot.answer_callback_query(call.id, "⚠️ ꜰɪʟᴇ ɴᴏᴛ ꜰᴏᴜɴᴅ.", show_alert=True)
            check_files_callback(call)
            return

        bot.answer_callback_query(call.id, f"🗑️ ᴅᴇʟᴇᴛɪɴɢ {file_name}...")
        script_key = f"{script_owner_id}_{file_name}"
        if is_bot_running(script_owner_id, file_name):
            process_info = bot_scripts.get(script_key)
            if process_info:
                kill_process_tree(process_info)
            if script_key in bot_scripts:
                del bot_scripts[script_key]
            time.sleep(0.5)

        user_folder = get_user_folder(script_owner_id)
        file_path = os.path.join(user_folder, file_name)
        log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
        if os.path.exists(log_path):
            try:
                os.remove(log_path)
            except Exception:
                pass

        remove_user_file_db(script_owner_id, file_name)
        
        # ✅ REMOVED: Delete file log to group
        # log_to_group(f"🗑️ File Deleted\n\n👤 User: `{script_owner_id}`\n📄 File: `{file_name}`\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            bot.edit_message_text(
                f"🗑️ ᴅᴇʟᴇᴛᴇᴅ `{file_name}` (ꜰʀᴏᴍ ᴜꜱᴇʀ `{script_owner_id}`)!",
                chat_id_for_reply, call.message.message_id, reply_markup=None, parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Error editing msg: {e}")
            bot.send_message(chat_id_for_reply, f"🗑️ ᴅᴇʟᴇᴛᴇᴅ `{file_name}`.", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error in delete_bot_callback: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "ᴇʀʀᴏʀ ᴅᴇʟᴇᴛɪɴɢ.", show_alert=True)

def logs_bot_callback(call):
    try:
        _, script_owner_id_str, file_name = call.data.split('_', 2)
        script_owner_id = int(script_owner_id_str)
        requesting_user_id = call.from_user.id
        chat_id_for_reply = call.message.chat.id

        if not (requesting_user_id == script_owner_id or requesting_user_id in admin_ids):
            bot.answer_callback_query(call.id, "⚠️ ᴘᴇʀᴍɪꜱꜱɪᴏɴ ᴅᴇɴɪᴇᴅ.", show_alert=True)
            return

        user_files_list = user_files.get(script_owner_id, [])
        if not any(f[0] == file_name for f in user_files_list):
            bot.answer_callback_query(call.id, "⚠️ ꜰɪʟᴇ ɴᴏᴛ ꜰᴏᴜɴᴅ.", show_alert=True)
            check_files_callback(call)
            return

        user_folder = get_user_folder(script_owner_id)
        log_path = os.path.join(user_folder, f"{os.path.splitext(file_name)[0]}.log")
        if not os.path.exists(log_path):
            bot.answer_callback_query(call.id, f"⚠️ ɴᴏ ʟᴏɢꜱ ꜰᴏᴜɴᴅ ꜰᴏʀ '{file_name}'.", show_alert=True)
            return

        bot.answer_callback_query(call.id)
        try:
            log_content = ""
            file_size = os.path.getsize(log_path)
            max_log_kb = 100
            max_tg_msg = 4096
            if file_size == 0:
                log_content = "(ʟᴏɢ ꜰɪʟᴇ ᴇᴍᴘᴛʏ)"
            elif file_size > max_log_kb * 1024:
                with open(log_path, 'rb') as f:
                    f.seek(-max_log_kb * 1024, os.SEEK_END)
                    log_bytes = f.read()
                log_content = log_bytes.decode('utf-8', errors='ignore')
                log_content = f"(ʟᴀꜱᴛ {max_log_kb} ᴋʙ)\n...\n" + log_content
            else:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()

            if len(log_content) > max_tg_msg:
                log_content = log_content[-max_tg_msg:]
                first_nl = log_content.find('\n')
                if first_nl != -1:
                    log_content = "...\n" + log_content[first_nl + 1:]
                else:
                    log_content = "...\n" + log_content
            if not log_content.strip():
                log_content = "(ɴᴏ ᴠɪꜱɪʙʟᴇ ᴄᴏɴᴛᴇɴᴛ)"

            bot.send_message(chat_id_for_reply, f"📄 ʟᴏɢꜱ ꜰᴏʀ `{file_name}` (ᴜꜱᴇʀ `{script_owner_id}`):\n```\n{log_content}\n```", parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Error reading/sending log: {e}", exc_info=True)
            bot.send_message(chat_id_for_reply, f"❌ ᴇʀʀᴏʀ ʀᴇᴀᴅɪɴɢ ʟᴏɢꜱ ꜰᴏʀ `{file_name}`.")
    except Exception as e:
        logger.error(f"Error in logs_bot_callback: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "ᴇʀʀᴏʀ ʀᴇᴀᴅɪɴɢ ʟᴏɢꜱ.", show_alert=True)

def speed_callback(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    start_cb_ping_time = time.time()
    try:
        bot.edit_message_text("🏓 ᴛᴇꜱᴛɪɴɢ ꜱᴘᴇᴇᴅ...", chat_id, call.message.message_id)
        bot.send_chat_action(chat_id, 'typing')
        response_time = round((time.time() - start_cb_ping_time) * 1000, 2)
        status = "🔓 ᴜɴʟᴏᴄᴋᴇᴅ" if not bot_locked else "🔐 ʟᴏᴄᴋᴇᴅ"
        if user_id in OWNER_IDS:
            user_level = "👑 ᴏᴡɴᴇʀ"
        elif user_id in admin_ids:
            user_level = "🛡️ ᴀᴅᴍɪɴ"
        elif user_id in user_subscriptions and user_subscriptions[user_id].get('expiry', datetime.min) > datetime.now():
            user_level = "🌟 ᴘʀᴇᴍɪᴜᴍ"
        else:
            user_level = "👤 ꜰʀᴇᴇ ᴜꜱᴇʀ"
        speed_msg = f"""
⚡ ʙᴏᴛ ꜱᴘᴇᴇᴅ & ꜱᴛᴀᴛᴜꜱ:

⏱️ ʀᴇꜱᴘᴏɴꜱᴇ ᴛɪᴍᴇ: {response_time} ᴍꜱ
🔧 ꜱᴛᴀᴛᴜꜱ: {status}
👤 ʏᴏᴜʀ ʟᴇᴠᴇʟ: {user_level}
"""
        bot.answer_callback_query(call.id)
        bot.edit_message_text(speed_msg, chat_id, call.message.message_id, reply_markup=create_main_menu_inline(user_id))
    except Exception as e:
        logger.error(f"Error during speed test: {e}", exc_info=True)
        bot.answer_callback_query(call.id, "ᴀɴ ᴇʀʀᴏʀ ᴏᴄᴄᴜʀʀᴇᴅ ᴡʜɪʟᴇ ᴛᴇꜱᴛɪɴɢ ꜱᴘᴇᴇᴅ.", show_alert=True)
        try:
            bot.edit_message_text("✨ ᴍᴀɪɴ ᴍᴇɴᴜ", chat_id, call.message.message_id, reply_markup=create_main_menu_inline(user_id))
        except Exception:
            pass

def back_to_main_callback(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    file_limit = get_user_file_limit(user_id)
    current_files = get_user_file_count(user_id)
    limit_str = str(file_limit) if file_limit != float('inf') else "ᴜɴʟɪᴍɪᴛᴇᴅ"
    expiry_info = ""
    if user_id in OWNER_IDS:
        user_status = "👑 ᴏᴡɴᴇʀ"
    elif user_id in admin_ids:
        user_status = "🛡️ ᴀᴅᴍɪɴ"
    elif user_id in user_subscriptions:
        expiry_date = user_subscriptions[user_id].get('expiry')
        if expiry_date and expiry_date > datetime.now():
            user_status = "🌟 ᴘʀᴇᴍɪᴜᴍ"
            days_left = (expiry_date - datetime.now()).days
            expiry_info = f"\n📅 ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ᴇxᴘɪʀᴇꜱ ɪɴ: {days_left} ᴅᴀʏꜱ"
        else:
            user_status = "👤 ꜰʀᴇᴇ ᴜꜱᴇʀ (ᴇxᴘɪʀᴇᴅ)"
    else:
        user_status = "👤 ꜰʀᴇᴇ ᴜꜱᴇʀ"
    main_menu_text = f"""
✨ ᴡᴇʟᴄᴏᴍᴇ ʙᴀᴄᴋ, {call.from_user.first_name}!

🆔 ɪᴅ: `{user_id}`
🎭 ꜱᴛᴀᴛᴜꜱ: {user_status}{expiry_info}
📦 ꜰɪʟᴇꜱ: {current_files} / {limit_str}

ꜱᴇʟᴇᴄᴛ ᴀɴ ᴏᴘᴛɪᴏɴ ʙᴇʟᴏᴡ:
"""
    try:
        bot.answer_callback_query(call.id)
        bot.edit_message_text(main_menu_text, chat_id, call.message.message_id,
                              reply_markup=create_main_menu_inline(user_id), parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error handling back_to_main: {e}", exc_info=True)

def ai_assistant_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("🤖 ᴀᴛx ᴀɪ ᴀꜱꜱɪꜱᴛᴀɴᴛ\n\nɪ'ᴍ ʜᴇʀᴇ ᴛᴏ ʜᴇʟᴘ ʏᴏᴜ ᴡɪᴛʜ:\n• ᴄᴏᴅɪɴɢ Qᴜᴇꜱᴛɪᴏɴꜱ\n• ʙᴏᴛ ᴅᴇᴠᴇʟᴏᴘᴍᴇɴᴛ\n• ᴛʀᴏᴜʙʟᴇꜱʜᴏᴏᴛɪɴɢ\n• ɢᴇɴᴇʀᴀʟ ɢᴜɪᴅᴀɴᴄᴇ\n\nꜱᴇʟᴇᴄᴛ ᴀɴ ᴏᴘᴛɪᴏɴ ʙᴇʟᴏᴡ:", call.message.chat.id, call.message.message_id, reply_markup=create_ai_assistant_menu())
    except Exception as e:
        logger.error(f"Error showing AI menu: {e}")

def ask_ai_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🤖 ᴡʜᴀᴛ ᴡᴏᴜʟᴅ ʏᴏᴜ ʟɪᴋᴇ ᴛᴏ ᴀꜱᴋ? ᴛʏᴘᴇ ʏᴏᴜʀ Qᴜᴇꜱᴛɪᴏɴ:")
    bot.register_next_step_handler(msg, process_ai_question, call.from_user.id)

def process_ai_question(message, user_id):
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    
    bot.send_chat_action(message.chat.id, 'typing')
    reply_msg = bot.reply_to(message, "🤖 ᴛʜɪɴᴋɪɴɢ...")
    
    ai_response = ask_groq_ai(message.text, f"User ID: {user_id}")
    
    # Clean HTML tags from AI response
    ai_response = clean_html_tags(ai_response)
    
    formatted_response = f"""
🤖 **ᴀᴛx ᴀɪ ʀᴇꜱᴘᴏɴꜱᴇ:**

{ai_response}

💡 *ɴᴇᴇᴅ ᴍᴏʀᴇ ʜᴇʟᴘ?* ᴊᴜꜱᴛ ᴀꜱᴋ ᴀɢᴀɪɴ!
"""
    
    bot.edit_message_text(formatted_response, message.chat.id, reply_msg.message_id, parse_mode='Markdown')

def process_broadcast_message(message):
    user_id = message.from_user.id
    if user_id not in admin_ids:
        bot.reply_to(message, "⚠️ ʏᴏᴜ ᴀʀᴇ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ.")
        return
    if message.text and message.text.lower() == '/cancel':
        bot.reply_to(message, "ʙʀᴏᴀᴅᴄᴀꜱᴛ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return

    broadcast_content = message.text
    if not broadcast_content and not (message.photo or message.video or message.document or message.sticker or message.voice or message.audio):
        bot.reply_to(message, "⚠️ ɴᴏ ʙʀᴏᴀᴅᴄᴀꜱᴛ ᴄᴏɴᴛᴇɴᴛ. ꜱᴇɴᴅ ᴀ ᴍᴇꜱꜱᴀɢᴇ ᴏʀ ᴍᴇᴅɪᴀ, ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        msg = bot.send_message(message.chat.id, "📢 ꜱᴇɴᴅ ᴍᴇ ᴛʜᴇ ʙʀᴏᴀᴅᴄᴀꜱᴛ ᴍᴇꜱꜱᴀɢᴇ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        bot.register_next_step_handler(msg, process_broadcast_message)
        return

    target_count = get_total_users_count()
    markup = types.InlineKeyboardMarkup()
    markup.row(types.InlineKeyboardButton("✅ ᴄᴏɴꜰɪʀᴍ & ꜱᴇɴᴅ", callback_data=f"confirm_broadcast_{message.message_id}"),
               types.InlineKeyboardButton("❌ ᴄᴀɴᴄᴇʟ", callback_data="cancel_broadcast"))

    preview_text = broadcast_content[:1000].strip() if broadcast_content else "(ᴍᴇᴅɪᴀ ᴄᴏɴᴛᴇɴᴛ)"
    bot.reply_to(message, f"⚠️ ᴄᴏɴꜰɪʀᴍ ʙʀᴏᴀᴅᴄᴀꜱᴛ:\n\n```\n{preview_text}\n```\nᴛᴏ **{target_count}** ᴜꜱᴇʀꜱ. ᴄᴏɴꜰɪʀᴍ?", reply_markup=markup, parse_mode='Markdown')

def handle_confirm_broadcast(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    if user_id not in admin_ids:
        bot.answer_callback_query(call.id, "⚠️ ᴀᴅᴍɪɴ ᴏɴʟʏ.", show_alert=True)
        return
    try:
        original_message = call.message.reply_to_message
        if not original_message:
            raise ValueError("ɴᴏ ᴏʀɪɢɪɴᴀʟ ᴍᴇꜱꜱᴀɢᴇ ᴏʀ ᴄᴏɴᴛᴇɴᴛ.")

        broadcast_text = None
        broadcast_photo_id = None
        broadcast_video_id = None

        if original_message.text:
            broadcast_text = original_message.text
        elif original_message.photo:
            broadcast_photo_id = original_message.photo[-1].file_id
        elif original_message.video:
            broadcast_video_id = original_message.video.file_id
        else:
            raise ValueError("ᴄᴏɴᴛᴇɴᴛ ɴᴏᴛ ᴛᴇxᴛ ᴏʀ ꜱᴜᴘᴘᴏʀᴛᴇᴅ ᴍᴇᴅɪᴀ.")

        bot.answer_callback_query(call.id, "🔄 ꜱᴛᴀʀᴛɪɴɢ ʙʀᴏᴀᴅᴄᴀꜱᴛ...")
        bot.edit_message_text(f"📢 ʙʀᴏᴀᴅᴄᴀꜱᴛɪɴɢ ᴛᴏ {get_total_users_count()} ᴜꜱᴇʀꜱ...",
                              chat_id, call.message.message_id, reply_markup=None)
        thread = threading.Thread(target=execute_broadcast, args=(
            broadcast_text, broadcast_photo_id, broadcast_video_id,
            original_message.caption if (broadcast_photo_id or broadcast_video_id) else None,
            chat_id))
        thread.start()
    except Exception as e:
        logger.error(f"Error in handle_confirm_broadcast: {e}", exc_info=True)
        bot.edit_message_text("❌ ᴀɴ ᴇʀʀᴏʀ ᴏᴄᴄᴜʀʀᴇᴅ ᴄᴏɴꜰɪʀᴍɪɴɢ ʙʀᴏᴀᴅᴄᴀꜱᴛ.", chat_id, call.message.message_id, reply_markup=None)

def handle_cancel_broadcast(call):
    bot.answer_callback_query(call.id, "ʙʀᴏᴀᴅᴄᴀꜱᴛ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
    bot.delete_message(call.message.chat.id, call.message.message_id)
    if call.message.reply_to_message:
        try:
            bot.delete_message(call.message.chat.id, call.message.reply_to_message.message_id)
        except Exception:
            pass

def execute_broadcast(broadcast_text, photo_id, video_id, caption, admin_chat_id):
    sent_count = 0
    failed_count = 0
    blocked_count = 0
    start_exec_time = time.time()
    
    # Get users from both MongoDB and active_users
    users_to_broadcast = set()
    if mongo_users is not None:
        try:
            mongo_user_ids = [doc['user_id'] for doc in mongo_users.find({}, {'user_id': 1})]
            users_to_broadcast.update(mongo_user_ids)
        except Exception as e:
            logger.error(f"Error getting users from MongoDB: {e}")
    
    # Add active users from SQLite
    users_to_broadcast.update(active_users)
    
    users_to_broadcast = list(users_to_broadcast)
    total_users = len(users_to_broadcast)
    
    if total_users == 0:
        bot.send_message(admin_chat_id, "❌ ɴᴏ ᴜꜱᴇʀꜱ ᴛᴏ ʙʀᴏᴀᴅᴄᴀꜱᴛ.")
        return
    
    logger.info(f"Executing broadcast to {total_users} users.")
    batch_size = 25
    delay_batches = 1.5

    for i, user_id_bc in enumerate(users_to_broadcast):
        try:
            if broadcast_text:
                bot.send_message(user_id_bc, broadcast_text, parse_mode='Markdown')
            elif photo_id:
                bot.send_photo(user_id_bc, photo_id, caption=caption, parse_mode='Markdown' if caption else None)
            elif video_id:
                bot.send_video(user_id_bc, video_id, caption=caption, parse_mode='Markdown' if caption else None)
            sent_count += 1
        except telebot.apihelper.ApiTelegramException as e:
            err_desc = str(e).lower()
            if any(s in err_desc for s in ["bot was blocked", "user is deactivated", "chat not found", "kicked from", "restricted"]):
                blocked_count += 1
            elif "flood control" in err_desc or "too many requests" in err_desc:
                retry_after = 5
                match = re.search(r"retry after (\d+)", err_desc)
                if match:
                    retry_after = int(match.group(1)) + 1
                time.sleep(retry_after)
                try:
                    if broadcast_text:
                        bot.send_message(user_id_bc, broadcast_text, parse_mode='Markdown')
                    elif photo_id:
                        bot.send_photo(user_id_bc, photo_id, caption=caption, parse_mode='Markdown' if caption else None)
                    elif video_id:
                        bot.send_video(user_id_bc, video_id, caption=caption, parse_mode='Markdown' if caption else None)
                    sent_count += 1
                except Exception:
                    failed_count += 1
            else:
                failed_count += 1
        except Exception:
            failed_count += 1

        if (i + 1) % batch_size == 0 and i < total_users - 1:
            time.sleep(delay_batches)
        elif i % 5 == 0:
            time.sleep(0.2)

    duration = round(time.time() - start_exec_time, 2)
    result_msg = (f"📢 ʙʀᴏᴀᴅᴄᴀꜱᴛ ᴄᴏᴍᴘʟᴇᴛᴇ!\n\n✅ ꜱᴇɴᴛ: {sent_count}\n❌ ꜰᴀɪʟᴇᴅ: {failed_count}\n"
                  f"🚫 ʙʟᴏᴄᴋᴇᴅ/ɪɴᴀᴄᴛɪᴠᴇ: {blocked_count}\n👥 ᴛᴏᴛᴀʟ: {total_users}\n⏱️ ᴅᴜʀᴀᴛɪᴏɴ: {duration}ꜱ")
    logger.info(result_msg)
    try:
        bot.send_message(admin_chat_id, result_msg)
    except Exception as e:
        logger.error(f"Failed to send broadcast result to admin: {e}")
        
def subscription_management_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("🎫 ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ᴍᴀɴᴀɢᴇᴍᴇɴᴛ\nꜱᴇʟᴇᴄᴛ ᴀɴ ᴏᴘᴛɪᴏɴ:",
                              call.message.chat.id, call.message.message_id, reply_markup=create_subscription_menu())
    except Exception as e:
        logger.error(f"Error showing subscription menu: {e}")

def lock_bot_callback(call):
    global bot_locked
    bot_locked = True
    bot.answer_callback_query(call.id, "🔐 ʙᴏᴛ ʟᴏᴄᴋᴇᴅ")
    bot.edit_message_text(f"🔐 ʙᴏᴛ ɪꜱ ɴᴏᴡ ʟᴏᴄᴋᴇᴅ.\nᴏɴʟʏ ᴀᴅᴍɪɴꜱ ᴄᴀɴ ᴜꜱᴇ.", 
                          call.message.chat.id, call.message.message_id,
                          reply_markup=create_main_menu_inline(call.from_user.id))

def unlock_bot_callback(call):
    global bot_locked
    bot_locked = False
    bot.answer_callback_query(call.id, "🔓 ʙᴏᴛ ᴜɴʟᴏᴄᴋᴇᴅ")
    bot.edit_message_text(f"🔓 ʙᴏᴛ ɪꜱ ɴᴏᴡ ᴜɴʟᴏᴄᴋᴇᴅ.\nᴀʟʟ ᴜꜱᴇʀꜱ ᴄᴀɴ ᴜꜱᴇ.", 
                          call.message.chat.id, call.message.message_id,
                          reply_markup=create_main_menu_inline(call.from_user.id))

def run_all_scripts_callback(call):
    _logic_run_all_scripts(call)

def broadcast_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "📢 ꜱᴇɴᴅ ᴍᴇ ᴛʜᴇ ᴍᴇꜱꜱᴀɢᴇ ʏᴏᴜ ᴡᴀɴᴛ ᴛᴏ ʙʀᴏᴀᴅᴄᴀꜱᴛ ᴛᴏ ᴀʟʟ ᴜꜱᴇʀꜱ.\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ.")
    bot.register_next_step_handler(msg, process_broadcast_message)

def admin_panel_callback(call):
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text("😎 ᴀᴅᴍɪɴ ᴘᴀɴᴇʟ\nꜱᴇʟᴇᴄᴛ ᴀɴ ᴏᴘᴛɪᴏɴ:",
                              call.message.chat.id, call.message.message_id, reply_markup=create_admin_panel())
    except Exception as e:
        logger.error(f"Error showing admin panel: {e}")

def add_admin_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👑 ꜱᴇɴᴅ ᴜꜱᴇʀ ɪᴅ ᴛᴏ ᴀᴅᴅ ᴀꜱ ᴀᴅᴍɪɴ.\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ.")
    bot.register_next_step_handler(msg, process_add_admin_id)

def process_add_admin_id(message):
    owner_id_check = message.from_user.id
    if owner_id_check != OWNER_ID:
        bot.reply_to(message, "⚠️ ᴏᴡɴᴇʀ ᴏɴʟʏ.")
        return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "ᴀᴅᴍɪɴ ᴀᴅᴅɪᴛɪᴏɴ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    try:
        new_admin_id = int(message.text.strip())
        if new_admin_id <= 0:
            raise ValueError("ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ")
        if new_admin_id == OWNER_ID:
            bot.reply_to(message, "⚠️ ᴏᴡɴᴇʀ ɪꜱ ᴀʟʀᴇᴀᴅʏ ᴏᴡɴᴇʀ.")
            return
        if new_admin_id in admin_ids:
            bot.reply_to(message, f"⚠️ ᴜꜱᴇʀ `{new_admin_id}` ɪꜱ ᴀʟʀᴇᴀᴅʏ ᴀᴅᴍɪɴ.")
            return
        add_admin_db(new_admin_id)
        logger.warning(f"Admin {new_admin_id} added by Owner {owner_id_check}.")
        log_to_group(f"👑 Admin Added\n\n👤 New Admin: `{new_admin_id}`\n👑 Added By: `{owner_id_check}`\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        bot.reply_to(message, f"✅ ᴜꜱᴇʀ `{new_admin_id}` ᴀᴅᴅᴇᴅ ᴀꜱ ᴀᴅᴍɪɴ.")
        try:
            bot.send_message(new_admin_id, "🎉 ᴄᴏɴɢʀᴀᴛᴜʟᴀᴛɪᴏɴꜱ! ʏᴏᴜ ᴀʀᴇ ɴᴏᴡ ᴀɴ ᴀᴅᴍɪɴ.")
        except Exception as e:
            logger.error(f"Failed to notify new admin: {e}")
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ. ꜱᴇɴᴅ ᴀ ɴᴜᴍᴇʀɪᴄ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        msg = bot.send_message(message.chat.id, "👑 ꜱᴇɴᴅ ᴜꜱᴇʀ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        bot.register_next_step_handler(msg, process_add_admin_id)
    except Exception as e:
        logger.error(f"Error processing add admin: {e}", exc_info=True)
        bot.reply_to(message, "❌ ᴇʀʀᴏʀ.")

def remove_admin_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "👑 ꜱᴇɴᴅ ᴀᴅᴍɪɴ ɪᴅ ᴛᴏ ʀᴇᴍᴏᴠᴇ.\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ.")
    bot.register_next_step_handler(msg, process_remove_admin_id)

def process_remove_admin_id(message):
    owner_id_check = message.from_user.id
    if owner_id_check != OWNER_ID:
        bot.reply_to(message, "⚠️ ᴏᴡɴᴇʀ ᴏɴʟʏ.")
        return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "ᴀᴅᴍɪɴ ʀᴇᴍᴏᴠᴀʟ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    try:
        admin_id_remove = int(message.text.strip())
        if admin_id_remove <= 0:
            raise ValueError("ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ")
        if admin_id_remove == OWNER_ID:
            bot.reply_to(message, "⚠️ ᴄᴀɴɴᴏᴛ ʀᴇᴍᴏᴠᴇ ᴏᴡɴᴇʀ.")
            return
        if admin_id_remove not in admin_ids:
            bot.reply_to(message, f"⚠️ ᴜꜱᴇʀ `{admin_id_remove}` ɪꜱ ɴᴏᴛ ᴀɴ ᴀᴅᴍɪɴ.")
            return
        if remove_admin_db(admin_id_remove):
            logger.warning(f"Admin {admin_id_remove} removed by Owner {owner_id_check}.")
            log_to_group(f"👑 Admin Removed\n\n👤 Removed Admin: `{admin_id_remove}`\n👑 Removed By: `{owner_id_check}`\n📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            bot.reply_to(message, f"✅ ᴀᴅᴍɪɴ `{admin_id_remove}` ʀᴇᴍᴏᴩᴇᴅ.")
            try:
                bot.send_message(admin_id_remove, "ℹ️ ʏᴏᴜʀ ᴀᴅᴍɪɴ ᴘʀɪᴠɪʟᴇɢᴇꜱ ʜᴀᴠᴇ ʙᴇᴇɴ ʀᴇᴍᴏᴠᴇᴅ.")
            except Exception as e:
                logger.error(f"Failed to notify removed admin: {e}")
        else:
            bot.reply_to(message, f"❌ ꜰᴀɪʟᴇᴅ ᴛᴏ ʀᴇᴍᴏᴠᴇ ᴀᴅᴍɪɴ `{admin_id_remove}`.")
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴉᴅ ᴜꜱᴇʀ ɪᴅ. ꜱᴇɴᴅ ᴀ ɴᴜᴍᴇʀɪᴄ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        msg = bot.send_message(message.chat.id, "👑 ꜱᴇɴᴅ ᴀᴅᴍɪɴ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        bot.register_next_step_handler(msg, process_remove_admin_id)
    except Exception as e:
        logger.error(f"Error processing remove admin: {e}", exc_info=True)
        bot.reply_to(message, "❌ ᴇʀʀᴏʀ.")

def list_admins_callback(call):
    bot.answer_callback_query(call.id)
    try:
        admin_list_str = "\n".join(f"- `{aid}` {'(ᴏᴡɴᴇʀ)' if aid == OWNER_ID else ''}" for aid in sorted(list(admin_ids)))
        if not admin_list_str:
            admin_list_str = "(ɴᴏ ᴀᴅᴍɪɴꜱ ꜰᴏᴜɴᴅ!)"
        bot.edit_message_text(f"👑 ᴀᴅᴍɪɴꜱ ʟɪꜱᴛ:\n\n{admin_list_str}", call.message.chat.id,
                              call.message.message_id, reply_markup=create_admin_panel(), parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Error listing admins: {e}")

def add_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🎫 ꜱᴇɴᴅ ᴜꜱᴇʀ ɪᴅ & ᴅᴀʏꜱ (ᴇ.ɢ., `12345678 30`).\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ.")
    bot.register_next_step_handler(msg, process_add_subscription_details)

def process_add_subscription_details(message):
    admin_id_check = message.from_user.id
    if admin_id_check not in admin_ids:
        bot.reply_to(message, "⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ.")
        return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ᴀᴅᴅɪᴛɪᴏɴ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    try:
        parts = message.text.split()
        if len(parts) != 2:
            raise ValueError("ɪɴᴄᴏʀʀᴇᴄᴛ ꜰᴏʀᴍᴀᴛ")
        sub_user_id = int(parts[0].strip())
        days = int(parts[1].strip())
        if sub_user_id <= 0 or days <= 0:
            raise ValueError("ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ/ᴅᴀʏꜱ")

        current_expiry = user_subscriptions.get(sub_user_id, {}).get('expiry')
        start_date_new_sub = datetime.now()
        if current_expiry and current_expiry > start_date_new_sub:
            start_date_new_sub = current_expiry
        new_expiry = start_date_new_sub + timedelta(days=days)
        save_subscription(sub_user_id, new_expiry)

        logger.info(f"Sub for {sub_user_id} by admin {admin_id_check}. Expiry: {new_expiry:%Y-%m-%d}")
        log_to_group(f"🎫 Subscription Added\n\n👤 User: `{sub_user_id}`\n📅 Days: {days}\n📆 Expiry: {new_expiry:%Y-%m-%d}\n👑 Added By: `{admin_id_check}`\n⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        bot.reply_to(message, f"✅ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ꜰᴏʀ `{sub_user_id}` ꜰᴏʀ {days} ᴅᴀʏꜱ.\nᴇxᴘɪʀʏ: {new_expiry:%Y-%m-%d}")
        try:
            bot.send_message(sub_user_id, f"🎉 ʏᴏᴜʀ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ʜᴀꜱ ʙᴇᴇɴ ᴀᴅᴅᴇᴅ/ᴇxᴛᴇɴᴅᴇᴅ ꜰᴏʀ {days} ᴅᴀʏꜱ! ᴇxᴘɪʀʏꜱ: {new_expiry:%Y-%m-%d}.")
        except Exception as e:
            logger.error(f"Failed to notify user: {e}")
    except ValueError as e:
        bot.reply_to(message, f"⚠️ ɪɴᴠᴀʟɪᴅ: {e}. ꜰᴏʀᴍᴀᴛ: `ɪᴅ ᴅᴀʏꜱ` ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        msg = bot.send_message(message.chat.id, "🎫 ꜱᴇɴᴅ ᴜꜱᴇʀ ɪᴅ & ᴅᴀʏꜱ, ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        bot.register_next_step_handler(msg, process_add_subscription_details)
    except Exception as e:
        logger.error(f"Error processing add sub: {e}", exc_info=True)
        bot.reply_to(message, "❌ ᴇʀʀᴏʀ.")

def remove_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🎫 ꜱᴇɴᴅ ᴜꜱᴇʀ ɪᴅ ᴛᴏ ʀᴇᴍᴏᴠᴇ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ.\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ.")
    bot.register_next_step_handler(msg, process_remove_subscription_id)

def process_remove_subscription_id(message):
    admin_id_check = message.from_user.id
    if admin_id_check not in admin_ids:
        bot.reply_to(message, "⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ.")
        return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ʀᴇᴍᴏᴠᴀʟ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    try:
        sub_user_id_remove = int(message.text.strip())
        if sub_user_id_remove <= 0:
            raise ValueError("ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ")
        if sub_user_id_remove not in user_subscriptions:
            bot.reply_to(message, f"⚠️ ᴜꜱᴇʀ `{sub_user_id_remove}` ʜᴀꜱ ɴᴏ ᴀᴄᴛɪᴠᴇ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ.")
            return
        remove_subscription_db(sub_user_id_remove)
        logger.warning(f"Sub removed for {sub_user_id_remove} by admin {admin_id_check}.")
        log_to_group(f"🎫 Subscription Removed\n\n👤 User: `{sub_user_id_remove}`\n👑 Removed By: `{admin_id_check}`\n⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        bot.reply_to(message, f"✅ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ʀᴇᴍᴏᴠᴇᴅ ꜰᴏʀ `{sub_user_id_remove}`.")
        try:
            bot.send_message(sub_user_id_remove, "ℹ️ ʏᴏᴜʀ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ʜᴀꜱ ʙᴇᴇɴ ʀᴇᴍᴏᴠᴇᴅ ʙʏ ᴀᴅᴍɪɴ.")
        except Exception as e:
            logger.error(f"Failed to notify user: {e}")
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ. ꜱᴇɴᴅ ᴀ ɴᴜᴍᴇʀɪᴄ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        msg = bot.send_message(message.chat.id, "🎫 ꜱᴇɴᴅ ᴜꜱᴇʀ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        bot.register_next_step_handler(msg, process_remove_subscription_id)
    except Exception as e:
        logger.error(f"Error processing remove sub: {e}", exc_info=True)
        bot.reply_to(message, "❌ ᴇʀʀᴏʀ.")

def check_subscription_init_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "🎫 ꜱᴇɴᴇ ᴜꜱᴇʀ ɪᴅ ᴛᴏ ᴄʜᴇᴄᴋ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ.\n/ᴄᴀɴᴄᴇʟ ᴛᴏ ᴄᴀɴᴄᴇʟ.")
    bot.register_next_step_handler(msg, process_check_subscription_id)

def process_check_subscription_id(message):
    admin_id_check = message.from_user.id
    if admin_id_check not in admin_ids:
        bot.reply_to(message, "⚠️ ɴᴏᴛ ᴀᴜᴛʜᴏʀɪᴢᴇᴅ.")
        return
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ᴄʜᴇᴄᴋ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    try:
        sub_user_id_check = int(message.text.strip())
        if sub_user_id_check <= 0:
            raise ValueError("ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ")
        if sub_user_id_check in user_subscriptions:
            expiry_dt = user_subscriptions[sub_user_id_check].get('expiry')
            if expiry_dt:
                if expiry_dt > datetime.now():
                    days_left = (expiry_dt - datetime.now()).days
                    bot.reply_to(message, f"✅ ᴜꜱᴇʀ `{sub_user_id_check}` ʜᴀꜱ ᴀᴄᴛɪᴠᴇ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ.\nᴇxᴘɪʀʏ: {expiry_dt:%Y-%m-%d %H:%M:%S} ({days_left} ᴅᴀʏꜱ ʟᴇꜰᴛ).")
                else:
                    bot.reply_to(message, f"⚠️ ᴜꜱᴇʀ `{sub_user_id_check}`'ꜱ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ᴇxᴘɪʀᴇᴅ ({expiry_dt:%Y-%m-%d %H:%M:%S}).")
                    remove_subscription_db(sub_user_id_check)
            else:
                bot.reply_to(message, f"⚠️ ᴜꜱᴇʀ `{sub_user_id_check}` ʜᴀꜱ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ ʙᴜᴛ ɴᴏ ᴇxᴘɪʀʏ ᴅᴀᴛᴇ.")
        else:
            bot.reply_to(message, f"ℹ️ ᴜꜱᴇʀ `{sub_user_id_check}` ʜᴀꜱ ɴᴏ ꜱᴜʙꜱᴄʀɪᴘᴛɪᴏɴ.")
    except ValueError:
        bot.reply_to(message, "⚠️ ɪɴᴠᴀʟɪᴅ ᴜꜱᴇʀ ɪᴅ. ꜱᴇɴᴅ ᴀ ɴᴜᴍᴇʀɪᴄ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        msg = bot.send_message(message.chat.id, "🎫 ꜱᴇɴᴅ ᴜꜱᴇʀ ɪᴅ ᴏʀ /ᴄᴀɴᴄᴇʟ.")
        bot.register_next_step_handler(msg, process_check_subscription_id)
    except Exception as e:
        logger.error(f"Error processing check sub: {e}", exc_info=True)
        bot.reply_to(message, "❌ ᴇʀʀᴏʀ.")

def stats_callback(call):
    bot.answer_callback_query(call.id)
    _logic_statistics(call.message)

def users_list_callback(call):
    bot.answer_callback_query(call.id)
    _logic_users_list(call.message)

def system_stats_callback(call):
    bot.answer_callback_query(call.id)
    _logic_system_stats(call.message)

def code_help_callback(call):
    bot.answer_callback_query(call.id)
    msg = bot.send_message(call.message.chat.id, "💻 ꜱᴇɴᴅ ᴍᴇ ʏᴏᴜʀ ᴄᴏᴅᴇ Qᴜᴇꜱᴛɪᴏɴ ᴏʀ ᴇʀʀᴏʀ.")
    bot.register_next_step_handler(msg, process_code_help, call.from_user.id)

def process_code_help(message, user_id):
    if message.text.lower() == '/cancel':
        bot.reply_to(message, "❌ ᴄᴀɴᴄᴇʟʟᴇᴅ.")
        return
    
    bot.send_chat_action(message.chat.id, 'typing')
    reply_msg = bot.reply_to(message, "💻 ᴀɴᴀʟʏᴢɪɴɢ ᴄᴏᴅᴇ...")
    
    ai_response = ask_groq_ai(f"Code help request: {message.text}", f"User ID: {user_id}")
    
    # Clean HTML tags from AI response
    ai_response = clean_html_tags(ai_response)
    
    formatted_response = f"""
💻 **ᴄᴏᴅᴇ ᴀɴᴀʟʏꜱɪꜱ:**

{ai_response}

🔧 *ᴛɪᴘ:* ᴀʟᴡᴀʏꜱ ᴛᴇꜱᴛ ʏᴏᴜʀ ᴄᴏᴅᴇ ɪɴ ᴀ ꜱᴀꜰᴇ ᴇɴᴠɪʀᴏɴᴍᴇɴᴛ ꜰɪʀꜱᴛ.
"""
    
    bot.edit_message_text(formatted_response, message.chat.id, reply_msg.message_id, parse_mode='Markdown')

def bot_guide_callback(call):
    bot.answer_callback_query(call.id)
    guide_text = """
📚 *ʙᴏᴛ ɢᴜɪᴅᴇ*

━━━━━━━━━━━━━━━━━━━━
🚀 **ɢᴇᴛᴛɪɴɢ ꜱᴛᴀʀᴛᴇᴅ:**
1. ᴊᴏɪɴ ᴏᴜʀ ᴜᴘᴅᴀᴛᴇꜱ ᴄʜᴀɴɴᴇʟ
2. ᴜᴘʟᴏᴀᴅ ʏᴏᴜʀ `.ᴘʏ` ᴏʀ `.ᴊꜱ` ꜰɪʟᴇ
3. ᴛʜᴇ ʙᴏᴛ ᴀᴜᴛᴏ-ɪɴꜱᴛᴀʟʟꜱ ᴅᴇᴘᴇɴᴅᴇɴᴄɪᴇꜱ
4. ʏᴏᴜʀ ʙᴏᴛ ʀᴜɴꜱ ᴀᴜᴛᴏᴍᴀᴛɪᴄᴀʟʟʏ!

━━━━━━━━━━━━━━━━━━━━
📁 **ꜰɪʟᴇ ꜰᴏʀᴍᴀᴛꜱ:**
• `.ᴘʏ` - ᴘʏᴛʜᴏɴ ꜱᴄʀɪᴘᴛꜱ
• `.ᴊꜱ` - ɴᴏᴅᴇ.ᴊꜱ ꜱᴄʀɪᴘᴛꜱ
• `.ᴢɪᴘ` - ᴀʀᴄʜɪᴠᴇ ᴡɪᴛʜ ᴅᴇᴘᴇɴᴅᴇɴᴄɪᴇꜱ

━━━━━━━━━━━━━━━━━━━━
⚡ **ꜰᴇᴀᴛᴜʀᴇꜱ:**
• 🤖 ᴀᴜᴛᴏ-ɪɴꜱᴛᴀʟʟ ᴅᴇᴘᴇɴᴅᴇɴᴄɪᴇꜱ
• 📊 ʀᴇᴀʟ-ᴛɪᴍᴇ ʟᴏɢɢɪɴɢ
• 🔧 ᴇᴀꜱʏ ꜱᴛᴀʀᴛ/ꜱᴛᴏᴘ/ʀᴇꜱᴛᴀʀᴛ
• 💾 ʀᴀᴍ & ꜱᴛᴏʀᴀɢᴇ ᴍᴏɴɪᴛᴏʀɪɴɢ
• 🎯 ʀᴇꜰᴇʀʀᴀʟ ꜱʏꜱᴛᴇᴍ
• 🔒 ꜰɪʟᴇ ᴇɴᴄʀʏᴘᴛɪᴏɴ
• 🛡️ ꜱᴇᴄᴜʀɪᴛʏ ꜱᴄᴀɴɴɪɴɢ
• 📦 ɢɪᴛ ᴄʟᴏɴᴇ

━━━━━━━━━━━━━━━━━━━━
💡 **ᴛɪᴘꜱ:**
• ᴋᴇᴇᴘ ʏᴏᴜʀ ʙᴏᴛꜱ ʟɪɢʜᴛᴡᴇɪɢʜᴛ
• ᴜꜱᴇ ᴘʀᴏᴘᴇʀ ᴇʀʀᴏʀ ʜᴀɴᴅʟɪɴɢ
• ᴍᴏɴɪᴛᴏʀ ʏᴏᴜʀ ʙᴏᴛ ʟᴏɢꜱ ʀᴇɢᴜʟᴀʀʟʏ
• ᴜꜱᴇ /ɪɴꜱᴛᴀʟʟ ᴛᴏ ᴀᴅᴅ ᴍɪꜱꜱɪɴɢ ᴍᴏᴅᴜʟᴇꜱ

ɴᴇᴇᴅ ᴍᴏʀᴇ ʜᴇʟᴘ? ᴜꜱᴇ /ᴅᴇᴠ ᴏʀ ᴛʏᴘᴇ ʏᴏᴜʀ Qᴜᴇꜱᴛɪᴏɴ!
"""
    bot.send_message(call.message.chat.id, guide_text, parse_mode='Markdown')

def troubleshoot_callback(call):
    bot.answer_callback_query(call.id)
    troubleshoot_text = """
🔧 TROUBLESHOOTING GUIDE

━━━━━━━━━━━━━━━━━━━━
❌ COMMON ISSUES:

1. BOT NOT STARTING:
   • Check if you've joined the channel
   • Verify file limits
   • Check logs for errors

2. MISSING MODULES:
   • Use /install module_name
   • Check your requirements.txt file

3. FILE UPLOAD FAILED:
   • Max file size: 20MB
   • Supported extensions: .py, .js, .zip
   • Check your internet connection

4. BOT STOPPED WORKING:
   • Check RAM usage /ram
   • Restart the bot
   • View logs for errors

5. SECURITY ALERTS:
   • Files are automatically encrypted
   • Malicious files are blocked
   • Use security scan feature

━━━━━━━━━━━━━━━━━━━━
⚡ QUICK FIXES:
• /restart - Restart your bot
• /logs - View bot logs
• /install - Add missing modules
• /uninstall - Remove modules
• Security Scan - Check for threats

━━━━━━━━━━━━━━━━━━━━
📞 SUPPORT:
• Use /dev for AI assistance
• Contact owner for major issues
• Join updates channel for news

Remember: All your files are encrypted for security!"""
    
    bot.send_message(call.message.chat.id, troubleshoot_text, parse_mode=None)

# ========== CLEANUP ==========
def cleanup():
    logger.warning("ꜱʜᴜᴛᴛɪɴɢ ᴅᴏᴡɴ. ꜱᴛᴏᴘᴘɪɴɢ ᴀʟʟ ʀᴜɴɴɪɴɢ ʙᴏᴛꜱ...")
    script_keys_to_stop = list(bot_scripts.keys())
    if not script_keys_to_stop:
        logger.info("ɴᴏ ʀᴜɴɴɪɴɢ ʙᴏᴛꜱ. ᴇxɪᴛɪɴɢ.")
        return
    logger.info(f"ꜱᴛᴏᴘᴘɪɴɢ {len(script_keys_to_stop)} ʙᴏᴛꜱ...")
    for key in script_keys_to_stop:
        if key in bot_scripts:
            kill_process_tree(bot_scripts[key])
    logger.warning("ᴀʟʟ ʙᴏᴛꜱ ꜱᴛᴏᴘᴘᴇᴅ.")
    if mongo_client:
        try:
            mongo_client.close()
            logger.info("ᴍᴏɴɢᴏᴅʙ ᴄᴏɴɴᴇᴄᴛɪᴏɴ ᴄʟᴏꜱᴇᴅ.")
        except Exception as e:
            logger.error(f"ᴇʀʀᴏʀ ᴄʟᴏꜱɪɴɢ ᴍᴏɴɢᴏᴅʙ: {e}")
atexit.register(cleanup)

# ========== TEXT MESSAGE HANDLER ==========
@bot.message_handler(func=lambda message: True, content_types=['text'])
def handle_all_text_messages(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    user_text = message.text.strip()
    
    # Check if user is banned
    if is_user_banned(user_id):
        bot.reply_to(message, "🚫 You are banned from using this bot.")
        return
    
    # Skip empty messages
    if not user_text:
        return
    
    # Check if it's a button click
    if user_text in BUTTON_TEXT_TO_LOGIC:
        logic_func = BUTTON_TEXT_TO_LOGIC.get(user_text)
        if logic_func:
            logic_func(message)
            return
    
    # Check if it's a command (starts with /)
    if user_text.startswith('/'):
        # Let command handlers handle it
        return
    
    # For all other text messages, use AI to respond
    process_ai_conversation(message)

def process_ai_conversation(message):
    """Process normal messages with AI"""
    user_id = message.from_user.id
    chat_id = message.chat.id
    user_text = message.text
    user_name = message.from_user.first_name or "User"
    
    # Show typing indicator
    bot.send_chat_action(chat_id, 'typing')
    
    # Small delay for natural feel
    time.sleep(0.8)
    
    try:
        # Show thinking message
        wait_msg = bot.reply_to(message, "🤖 *Thinking...*", parse_mode='Markdown')
        
        # Prepare context for AI
        context = f"""
User Information:
- ID: {user_id}
- Name: {user_name}
- Username: @{message.from_user.username or 'Not set'}

Conversation Context:
The user is chatting with a Telegram bot hosting platform assistant.
The bot can help with coding, bot development, troubleshooting, and general questions.
"""
        
        # Get AI response
        ai_response = ask_groq_ai(user_text, context)
        
        # Clean up the response - replace HTML tags with Markdown
        ai_response = clean_html_tags(ai_response)
        
        # Format the response nicely
        if len(ai_response) > 3000:
            ai_response = ai_response[:3000] + "...\n\n(Response truncated)"
        
        formatted_response = f"""
💬 **Chat with {user_name}:**

{ai_response}

---

"""
        
        # Send the response using Markdown instead of HTML
        try:
            bot.edit_message_text(formatted_response, chat_id, wait_msg.message_id)
        except:
            bot.send_message(chat_id, formatted_response)
            
    except Exception as e:
        logger.error(f"AI conversation error: {e}", exc_info=True)
        
        # Fallback response
        try:
            error_response = f"""
❌ **I encountered an error**

Sorry {user_name}, I couldn't process your message properly.

Please try:
1. Rephrasing your question
2. Using the buttons below
3. Asking again later

Error: {str(e)[:100]}
"""
            bot.send_message(chat_id, error_response, parse_mode='Markdown')
        except:
            bot.reply_to(message, "❌ Sorry, I couldn't process that. Please try again.")
    
    # Default response for non-button messages
    bot.reply_to(message, 
        "❤️ any problem to dm owner @Its_MeVishall.")
        
        
def clean_html_tags(text):
    """Clean HTML tags from text for Telegram"""
    if not text:
        return text
    
    import html as html_module  # Use different name to avoid conflict
    
    # First unescape HTML entities
    text = html_module.unescape(text)
    
    # Replace common HTML tags with Markdown equivalents
    replacements = {
        '<br>': '\n',
        '<br/>': '\n',
        '<br />': '\n',
        '<p>': '\n',
        '</p>': '\n',
        '<b>': '*',
        '</b>': '*',
        '<strong>': '*',
        '</strong>': '*',
        '<i>': '_',
        '</i>': '_',
        '<em>': '_',
        '</em>': '_',
        '<code>': '`',
        '</code>': '`',
        '<pre>': '```\n',
        '</pre>': '\n```',
        '<ul>': '\n',
        '</ul>': '\n',
        '<li>': '• ',
        '</li>': '\n',
        '<ol>': '\n',
        '</ol>': '\n'
    }
    
    # First replace the tags
    for html_tag, replacement in replacements.items():
        text = text.replace(html_tag, replacement)
    
    # Remove any remaining HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Clean up multiple newlines
    text = re.sub(r'\n\s*\n', '\n\n', text)
    
    return text.strip()
    
# ================== KEEP ALIVE + BOT START ==================

if __name__ == "__main__":

    # 🔥 KEEP ALIVE START (Replit + UptimeRobot)
    keep_alive()

    logger.info("🔄 Starting Telegram bot polling...")

    while True:
        try:
            bot.infinity_polling(
                skip_pending=True,
                logger_level=logging.INFO,
                timeout=60,
                long_polling_timeout=30,
                allowed_updates=['message', 'callback_query', 'inline_query']
            )

        except requests.exceptions.ReadTimeout:
            logger.warning("⏳ Polling timeout, restarting in 5s...")
            time.sleep(5)

        except requests.exceptions.ConnectionError as e:
            logger.error(f"🌐 Connection error: {e}, retrying in 15s...")
            time.sleep(15)

        except telebot.apihelper.ApiException as e:
            logger.error(f"🤖 Telegram API error: {e}, retrying in 30s...")
            time.sleep(30)

        except Exception as e:
            logger.critical(f"❌ Unexpected error: {e}", exc_info=True)
            logger.info("🔁 Restarting polling in 60s...")
            time.sleep(60)