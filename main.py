import streamlit as st
import hashlib
import json
import os
import base64
import time
from cryptography.fernet import Fernet
import secrets

# Set page config for responsive UI
st.set_page_config(page_title="Secure Data Vault", layout="centered")

# Apply custom styles
st.markdown("""
    <style>
        .stApp {
            background-color: #f5f7fa;
            font-family: 'Segoe UI', sans-serif;
        }
        .stTextInput, .stTextArea, .stButton button {
            border-radius: 10px;
        }
        .block-container {
            padding: 2rem;
        }
        .stSidebar {
            background-color: #e8eff5;
        }
        .css-18e3th9 {
            padding-top: 2rem;
        }
        h1, h2, h3, h4, h5 {
            color: #1e3a8a;
        }
    </style>
""", unsafe_allow_html=True)

# Constants and Global Variables
KEY = Fernet.generate_key()  # In production, store this securely
cipher = Fernet(KEY)
DATA_FILE = "stored_data.json"
USERS_FILE = "users.json"
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 60  # seconds

# Session State Initialization
for key in ["failed_attempts", "lockout_time", "reauthorized", "current_user"]:
    if key not in st.session_state:
        st.session_state[key] = 0 if key == "failed_attempts" else None if key == "lockout_time" else False if key == "reauthorized" else ""

# Load data from file
stored_data = json.load(open(DATA_FILE)) if os.path.exists(DATA_FILE) else {}
users = json.load(open(USERS_FILE)) if os.path.exists(USERS_FILE) else {}

# Save data to file
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

def save_users():
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

# Generate salt for PBKDF2
def generate_salt():
    return base64.b64encode(secrets.token_bytes(16)).decode()

# Function to hash passkey with PBKDF2
def hash_passkey(passkey, salt):
    return hashlib.pbkdf2_hmac("sha256", passkey.encode(), base64.b64decode(salt.encode()), 100000).hex()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    encrypted_text = encrypted_text.strip()  # Clean whitespace
    if st.session_state.current_user not in stored_data:
        return None
    user_data = stored_data[st.session_state.current_user]
    for key, value in user_data.items():
        if key.strip() == encrypted_text:
            salt = value["salt"]
            hashed_input = hash_passkey(passkey, salt)
            if hashed_input == value["passkey"]:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.session_state.lockout_time = time.time()
    return None

# Lockout Check
if st.session_state.lockout_time:
    elapsed = time.time() - st.session_state.lockout_time
    if elapsed < LOCKOUT_DURATION:
        st.warning(f"🚫 Too many failed attempts! Please wait {int(LOCKOUT_DURATION - elapsed)} seconds.")
        st.stop()
    else:
        st.session_state.failed_attempts = 0
        st.session_state.lockout_time = None

# Navigation
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=100)
st.sidebar.title("🔐 Secure Vault")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.radio("Navigation", menu)

# Home Page
if choice == "Home":
    st.title("🏠 Welcome to Secure Data Vault")
    st.write("""
        Safely store and retrieve your sensitive information with military-grade encryption.

        🔐 Register an account
        🔐 Log in to your vault
        🔐 Store secret notes, passwords, or sensitive messages
        🔐 Retrieve them anytime with your unique passkey
    """)

# Registration Page
elif choice == "Register":
    st.title("📝 Create New Account")
    new_user = st.text_input("Choose a Username")
    new_pass = st.text_input("Choose a Password", type="password")

    if st.button("Register", use_container_width=True):
        if new_user in users:
            st.error("❌ Username already exists!")
        else:
            salt = generate_salt()
            users[new_user] = {
                "password": hash_passkey(new_pass, salt),
                "salt": salt
            }
            save_users()
            stored_data[new_user] = {}
            save_data()
            st.success("✅ Account created successfully!")

# Login Page
elif choice == "Login":
    st.title("🔑 Secure Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login", use_container_width=True):
        if username in users:
            salt = users[username]["salt"]
            hashed_input = hash_passkey(password, salt)
            if hashed_input == users[username]["password"]:
                st.session_state.current_user = username
                st.session_state.reauthorized = True
                st.success(f"✅ Welcome, {username}!")
            else:
                st.error("❌ Incorrect password!")
        else:
            st.error("❌ User not found!")

# Store Data Page
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login to store data.")
    else:
        st.title("📂 Store Your Data Securely")
        user_data = st.text_area("Enter Data You Want to Secure")
        passkey = st.text_input("Set a Passkey to Lock It", type="password")

        if st.button("🔐 Encrypt & Save", use_container_width=True):
            if user_data and passkey:
                salt = generate_salt()
                hashed_passkey = hash_passkey(passkey, salt)
                encrypted_text = encrypt_data(user_data)
                user_dict = stored_data.get(st.session_state.current_user, {})
                user_dict[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "salt": salt
                }
                stored_data[st.session_state.current_user] = user_dict
                save_data()
                st.success("✅ Data stored securely!")
                st.text_area("Encrypted Data (copy to retrieve):", encrypted_text)
            else:
                st.error("⚠️ Both fields are required!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login to retrieve data.")
    elif st.session_state.failed_attempts >= MAX_ATTEMPTS and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts! Please login again.")
    else:
        st.title("🔍 Retrieve Your Secured Data")
        encrypted_text = st.text_area("Paste Your Encrypted Data").strip()
        passkey = st.text_input("Enter Your Passkey", type="password")

        if st.button("🔓 Decrypt", use_container_width=True):
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted_text)
                else:
                    attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
            else:
                st.error("⚠️ Both fields are required!")
