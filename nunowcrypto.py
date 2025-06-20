import streamlit as st
import hashlib
import sqlite3

# Database setup
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
conn.commit()

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def add_user(username, password):
    hashed = hash_password(password)
    c.execute("INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)", (username, hashed))
    conn.commit()

def get_user(username):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    return c.fetchone()

def update_password(username, new_password):
    hashed = hash_password(new_password)
    c.execute("UPDATE users SET password=? WHERE username=?", (hashed, username))
    conn.commit()

# Initialize default user
if not get_user("abdi"):
    add_user("abdi", "sir1234")  # Default password, can be changed later

# Streamlit UI
st.set_page_config(page_title="NunowCrypto", layout="centered")
st.title("🔐 NunowCrypto Login")

menu = ["Login", "Change Password"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Login":
    st.subheader("Login to your dashboard")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')

    if st.button("Login"):
        user = get_user(username)
        if user and verify_password(password, user[1]):
            st.success(f"Welcome, {username}! 👋")
            st.write("Your dashboard will show your crypto trading signals here.")
            # TODO: Add crypto signal dashboard here
        else:
            st.error("Invalid username or password")

elif choice == "Change Password":
    st.subheader("Change Your Password")
    username = st.text_input("Username")
    old_password = st.text_input("Old Password", type='password')
    new_password = st.text_input("New Password", type='password')

    if st.button("Update Password"):
        user = get_user(username)
        if user and verify_password(old_password, user[1]):
            update_password(username, new_password)
            st.success("Password updated successfully!")
        else:
            st.error("Old password incorrect or user not found")
