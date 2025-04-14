

import streamlit as st
import hashlib
import json
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Custom CSS
st.markdown("""
    <style>
    .main {
        background-color: #f5f5f5;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
        border: none;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #45a049;
    }
    .stTextInput>div>div>input {
        border-radius: 5px;
    }
    .stTextArea>div>div>textarea {
        border-radius: 5px;
    }
    .success-message {
        color: #4CAF50;
        font-weight: bold;
    }
    .error-message {
        color: #f44336;
        font-weight: bold;
    }
    .title {
        color: #2c3e50;
        text-align: center;
        margin-bottom: 30px;
    }
    .subtitle {
        color: #34495e;
        margin-bottom: 20px;
    }
    .card {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin-bottom: 20px;
    }
    </style>
    """, unsafe_allow_html=True)

# Constants
DATA_FILE = "encrypted_data.json"
LOCKOUT_DURATION = 300  # 5 minutes in seconds

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Load or create data file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {"users": {}, "data": {}}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Initialize data
stored_data = load_data()

# Encryption key
encryption_key = Fernet.generate_key()

# Function to hash passkey using PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

# Function to encrypt data
def encrypt_data(text, key):
    cipher = Fernet(key)
    encrypted_bytes = cipher.encrypt(text.encode())
    return encrypted_bytes.decode('utf-8')

# Function to decrypt data
def decrypt_data(ciphertext, key):
    cipher = Fernet(key)
    decrypted_bytes = cipher.decrypt(ciphertext.encode('utf-8'))
    return decrypted_bytes.decode('utf-8')

# Function to handle login
def login_page():
    st.markdown("<h1 class='title'>🔐 Secure Login</h1>", unsafe_allow_html=True)
    
    # Check for lockout
    if st.session_state.lockout_time and datetime.now() < st.session_state.lockout_time:
        remaining_time = (st.session_state.lockout_time - datetime.now()).seconds
        st.error(f"🔒 Account locked. Please try again in {remaining_time} seconds.")
        return
    
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        username = st.text_input("👤 Username")
        password = st.text_input("🔑 Password", type="password")
        
        if st.button("Login", key="login_button"):
            if username in stored_data["users"]:
                user_data = stored_data["users"][username]
                key, _ = hash_passkey(password, user_data["salt"])
                if key.decode() == user_data["key"]:
                    st.session_state.is_logged_in = True
                    st.session_state.current_user = username
                    st.session_state.failed_attempts = 0
                    st.success("✅ Login successful")
                    st.rerun()
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = datetime.now() + timedelta(seconds=LOCKOUT_DURATION)
                        st.error("❌ Too many failed attempts. Account locked for 5 minutes.")
                    else:
                        st.error(f"❌ Invalid credentials. Attempts remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ User not found")
        st.markdown("</div>", unsafe_allow_html=True)

# Function to handle registration
def register_page():
    st.markdown("<h1 class='title'>📝 Register New Account</h1>", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        username = st.text_input("👤 Choose Username")
        password = st.text_input("🔑 Choose Password", type="password")
        
        if st.button("Register", key="register_button"):
            if username in stored_data["users"]:
                st.error("❌ Username already exists")
            else:
                key, salt = hash_passkey(password)
                stored_data["users"][username] = {"key": key.decode(), "salt": salt.hex()}
                stored_data["data"][username] = {}
                save_data(stored_data)
                st.success("✅ Registration successful! Please login.")
        st.markdown("</div>", unsafe_allow_html=True)

# Function to handle data storage
def store_data_page():
    st.markdown("<h1 class='title'>💾 Store Data</h1>", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        text = st.text_area("📝 Enter your text")
        passkey = st.text_input("🔑 Enter passkey", type="password")
        
        if st.button("Store Data", key="store_button"):
            if text and passkey:
                hashed_passkey, salt = hash_passkey(passkey)
                encrypted_text = encrypt_data(text, encryption_key)
                if st.session_state.current_user not in stored_data["data"]:
                    stored_data["data"][st.session_state.current_user] = {}
                stored_data["data"][st.session_state.current_user][hashed_passkey.decode()] = {
                    "encrypted_text": encrypted_text,
                    "salt": salt.hex()
                }
                save_data(stored_data)
                st.success("✅ Data stored successfully")
        st.markdown("</div>", unsafe_allow_html=True)

# Function to handle data retrieval
def retrieve_data_page():
    st.markdown("<h1 class='title'>🔍 Retrieve Data</h1>", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        passkey = st.text_input("🔑 Enter passkey", type="password")
        
        if st.button("Retrieve Data", key="retrieve_button"):
            if passkey:
                hashed_passkey, _ = hash_passkey(passkey)
                user_data = stored_data["data"].get(st.session_state.current_user, {})
                if hashed_passkey.decode() in user_data:
                    encrypted_text = user_data[hashed_passkey.decode()]["encrypted_text"]
                    decrypted_text = decrypt_data(encrypted_text, encryption_key)
                    st.success("✅ Decrypted text: " + decrypted_text)
                else:
                    st.error("❌ Invalid passkey")
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.is_logged_in = False
                        st.error("❌ Too many failed attempts. Please login again.")
                        st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

# Main app
def main():
    st.markdown("<h1 class='title'>🔒 Secure Data Storage System</h1>", unsafe_allow_html=True)
    
    if not st.session_state.is_logged_in:
        page = st.radio("Select an option", ["Login", "Register"])
        if page == "Login":
            login_page()
        else:
            register_page()
    else:
        page = st.radio("Choose a page", ["Home", "Store Data", "Retrieve Data", "Logout"])
        
        if page == "Home":
            st.markdown(f"<h2 class='subtitle'>👋 Welcome, {st.session_state.current_user}!</h2>", unsafe_allow_html=True)
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            st.write("Please select an option from the sidebar to manage your data.")
            st.markdown("</div>", unsafe_allow_html=True)
        elif page == "Store Data":
            store_data_page()
        elif page == "Retrieve Data":
            retrieve_data_page()
        elif page == "Logout":
            st.session_state.is_logged_in = False
            st.session_state.current_user = None
            st.rerun()

if __name__ == "__main__":
    main()