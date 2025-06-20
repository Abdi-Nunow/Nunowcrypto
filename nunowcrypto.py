import streamlit as st
from binance.client import Client
import pandas as pd
import numpy as np
import ta
import time

# Binance API (public data, API key iyo secret uma baahnid haddii aad read-only xog raadineyso)
client = Client()

# Timeframes Binance taageerto (waxaad ku dari kartaa kuwa kale)
TIMEFRAMES = ['1m', '5m', '15m', '30m', '1h', '4h', '1d']

st.title("NunowCrypto - Crypto Signal Bot")

# Hel dhammaan symbols (tokens) ee Binance Futures (ama Spot market)
@st.cache_data(ttl=600)
def get_symbols():
    info = client.get_exchange_info()
    symbols = [s['symbol'] for s in info['symbols'] if s['status'] == 'TRADING' and s['quoteAsset'] == 'USDT']
    return symbols

symbols = get_symbols()

# User input
selected_symbol = st.selectbox("Choose symbol:", symbols)
selected_tf = st.selectbox("Choose timeframe:", TIMEFRAMES)

# Function to get historical klines data
@st.cache_data(ttl=300)
def get_klines(symbol, interval, limit=500):
    klines = client.get_klines(symbol=symbol, interval=interval, limit=limit)
    df = pd.DataFrame(klines, columns=['Open time', 'Open', 'High', 'Low', 'Close', 'Volume',
                                       'Close time', 'Quote asset volume', 'Number of trades',
                                       'Taker buy base asset volume', 'Taker buy quote asset volume', 'Ignore'])
    df['Open time'] = pd.to_datetime(df['Open time'], unit='ms')
    df['Close time'] = pd.to_datetime(df['Close time'], unit='ms')
    df[['Open', 'High', 'Low', 'Close', 'Volume']] = df[['Open', 'High', 'Low', 'Close', 'Volume']].astype(float)
    return df

# Calculate indicators (RSI and MACD)
def add_indicators(df):
    df['RSI'] = ta.momentum.rsi(df['Close'], window=14)
    macd = ta.trend.MACD(df['Close'])
    df['MACD'] = macd.macd()
    df['MACD_signal'] = macd.macd_signal()
    df['MACD_diff'] = macd.macd_diff()
    return df

# Simple signal strategy (buy/sell based on RSI and MACD cross)
def generate_signal(df):
    last = df.iloc[-1]
    prev = df.iloc[-2]

    signal = "Hold"

    # RSI oversold < 30, overbought > 70
    if last['RSI'] < 30 and last['MACD_diff'] > 0 and prev['MACD_diff'] <= 0:
        signal = "Buy"
    elif last['RSI'] > 70 and last['MACD_diff'] < 0 and prev['MACD_diff'] >= 0:
        signal = "Sell"
    return signal

if st.button("Get Signal"):
    with st.spinner("Fetching data and calculating signals..."):
        df = get_klines(selected_symbol, selected_tf)
        df = add_indicators(df)
        signal = generate_signal(df)

        st.subheader(f"Latest Data for {selected_symbol} - {selected_tf}")
        st.write(df.tail(5))

        st.markdown(f"### Trading Signal: **{signal}**")

        st.markdown("### Indicator values:")
        st.write(df[['RSI', 'MACD', 'MACD_signal', 'MACD_diff']].tail(5))

# Add Change Password (simple session-based demo)
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

def login():
    pw = st.text_input("Enter password:", type="password")
    if st.button("Login"):
        if pw == "Nunow1234":  # Bad example, hardcoded password (for demo only)
            st.session_state.logged_in = True
            st.success("Logged in!")
        else:
            st.error("Wrong password!")

if not st.session_state.logged_in:
    st.sidebar.title("Login")
    login()
else:
    st.sidebar.success("You are logged in")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.experimental_rerun()

