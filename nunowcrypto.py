import streamlit as st
import hashlib
import sqlite3
from binance.client import Client
import pandas as pd
import pandas_ta as ta
import numpy as np
import time

# --------------- User Authentication Setup ----------------
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
conn.commit()

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

if not get_user("abdi"):
    add_user("abdi", "sir1234")

# ---------------- Binance API Setup ---------------------
# Use Binance public API - no keys required for public data
client = Client()

# Timeframes supported by Binance for Klines
TIMEFRAMES = {
    '1m': '1m',
    '3m': '3m',
    '5m': '5m',
    '15m': '15m',
    '30m': '30m',
    '1h': '1h',
    '2h': '2h',
    '4h': '4h',
    '6h': '6h',
    '8h': '8h',
    '12h': '12h',
    '1d': '1d',
    '3d': '3d',
    '1w': '1w',
    '1M': '1M'
}

# ------------------ Helper functions --------------------
def fetch_symbols():
    info = client.get_exchange_info()
    symbols = [s['symbol'] for s in info['symbols'] if s['status'] == 'TRADING']
    # Filter to spot markets only (optional)
    spot_symbols = [sym for sym in symbols if sym.endswith('USDT')]
    return spot_symbols

def get_klines(symbol, interval, limit=500):
    try:
        klines = client.get_klines(symbol=symbol, interval=interval, limit=limit)
        df = pd.DataFrame(klines, columns=['open_time', 'open', 'high', 'low', 'close', 'volume',
                                           'close_time', 'quote_asset_volume', 'number_of_trades',
                                           'taker_buy_base_asset_volume', 'taker_buy_quote_asset_volume', 'ignore'])
        df['open'] = df['open'].astype(float)
        df['high'] = df['high'].astype(float)
        df['low'] = df['low'].astype(float)
        df['close'] = df['close'].astype(float)
        df['volume'] = df['volume'].astype(float)
        df['open_time'] = pd.to_datetime(df['open_time'], unit='ms')
        return df
    except Exception as e:
        st.error(f"Error fetching klines: {e}")
        return None

def calculate_indicators(df):
    df['RSI'] = ta.rsi(df['close'], length=14)
    macd = ta.macd(df['close'])
    df['MACD'] = macd['MACD_12_26_9']
    df['MACD_signal'] = macd['MACDs_12_26_9']
    df['MACD_hist'] = macd['MACDh_12_26_9']
    return df

def generate_signal(df):
    # Simple signal logic combining RSI and MACD
    if df is None or df.empty:
        return "No data"
    last_rsi = df['RSI'].iloc[-1]
    last_macd = df['MACD'].iloc[-1]
    last_macd_signal = df['MACD_signal'].iloc[-1]

    # RSI signals
    if last_rsi < 30:
        rsi_signal = "Buy"
    elif last_rsi > 70:
        rsi_signal = "Sell"
    else:
        rsi_signal = "Hold"

    # MACD signals
    if last_macd > last_macd_signal:
        macd_signal = "Buy"
    elif last_macd < last_macd_signal:
        macd_signal = "Sell"
    else:
        macd_signal = "Hold"

    # Combine signals (simple logic)
    if rsi_signal == "Buy" and macd_signal == "Buy":
        return "Strong Buy"
    elif rsi_signal == "Sell" and macd_signal == "Sell":
        return "Strong Sell"
    elif rsi_signal == "Buy" or macd_signal == "Buy":
        return "Buy"
    elif rsi_signal == "Sell" or macd_signal == "Sell":
        return "Sell"
    else:
        return "Hold"

# ---------------------- Streamlit UI ----------------------
st.set_page_config(page_title="NunowCrypto", layout="wide")
st.title("🔐 NunowCrypto - Crypto Signals Dashboard")

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

            # Dashboard content starts here
            st.header("📊 Crypto Signals")

            symbols = fetch_symbols()
            symbol = st.selectbox("Select Token (USDT pairs)", symbols, index=symbols.index("BTCUSDT") if "BTCUSDT" in symbols else 0)
            timeframe = st.selectbox("Select Timeframe", list(TIMEFRAMES.keys()), index=5)  # default 1h

            if st.button("Get Signal"):
                with st.spinner("Fetching data and calculating signal..."):
                    df = get_klines(symbol, TIMEFRAMES[timeframe])
                    if df is not None:
                        df = calculate_indicators(df)
                        signal = generate_signal(df)
                        st.write(f"### Signal for {symbol} on {timeframe} timeframe: **{signal}**")

                        st.line_chart(df[['close', 'RSI', 'MACD', 'MACD_signal']])
                    else:
                        st.error("Failed to fetch or process data.")

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
