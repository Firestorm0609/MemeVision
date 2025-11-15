import os
import requests
import httpx
import asyncio
import time
import telegram
from dotenv import load_dotenv
import hashlib
import json
from flask import Flask, request, jsonify

# --- CONFIGURATION ---
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
HELIUS_API_KEY = os.getenv('HELIUS_API_KEY')
GOPLUS_APP_KEY = os.getenv('GOPLUS_APP_KEY')
GOPLUS_APP_SECRET = os.getenv('GOPLUS_APP_SECRET')

# --- API ENDPOINTS ---
HELIUS_API_URL = f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
GOPLUS_AUTH_URL = "https://api.gopluslabs.io/api/v1/token"
GOPLUS_TOKEN_API_URL = "https://api.gopluslabs.io/api/v1/solana/token_security"
GOPLUS_ADDRESS_API_URL = "https://api.gopluslabs.io/api/v1/address_security"

# --- STATE MANAGEMENT ---
# NOTE: Vercel is stateless. We can't use a simple `set()` to track seen mints
# across runs. A real database (like Vercel KV) would be needed for a perfect state.
# For simplicity, this will just check the latest 100 tokens on each run.
GOPLUS_AUTH_TOKEN = {}

# --- Initialize Flask App ---
app = Flask(__name__)

# --- All your functions go here (get_goplus_access_token, get_new_tokens, etc.) ---
# (I've copied them exactly from your script, just made them async compatible)

async def get_goplus_access_token():
    global GOPLUS_AUTH_TOKEN
    if 'token' in GOPLUS_AUTH_TOKEN and GOPLUS_AUTH_TOKEN.get('expires_at', 0) > (time.time() + 300):
        return GOPLUS_AUTH_TOKEN['token']
    print("Requesting new GoPlus access token...")
    try:
        request_time = str(int(time.time()))
        sign_str = GOPLUS_APP_KEY + request_time + GOPLUS_APP_SECRET
        signature = hashlib.sha1(sign_str.encode()).hexdigest()
        payload = {"app_key": GOPLUS_APP_KEY, "sign": signature, "time": request_time}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(GOPLUS_AUTH_URL, json=payload)
            response.raise_for_status()
        data = response.json()
        
        if data.get('code') == 1:
            access_token = data['result']['access_token']
            expires_in = int(data['result']['expires_in'])
            GOPLUS_AUTH_TOKEN = {'token': access_token, 'expires_at': time.time() + expires_in}
            print("Successfully obtained GoPlus token.")
            return access_token
        else:
            print(f"Error getting GoPlus token: {data.get('message')}")
            return None
    except Exception as e:
        print(f"Exception getting GoPlus token: {e}")
        return None

async def get_new_tokens():
    print("Checking Helius for new tokens...")
    try:
        payload = {
            "jsonrpc": "2.0", "id": "helius-bot", "method": "searchAssets",
            "params": {
                "tokenType": "fungible",
                "sortBy": {"sortBy": "created", "sortDirection": "desc"},
                "limit": 100, "page": 1
            }
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(HELIUS_API_URL, json=payload)
            response.raise_for_status() 
        result = response.json().get('result', {})
        return result.get('items', [])
    except Exception as e:
        print(f"General error in get_new_tokens: {e}")
        return []

async def analyze_token_safety(mint_address, deployer_wallet, ticker):
    print(f"Analyzing {ticker} ({mint_address})...")
    access_token = await get_goplus_access_token()
    if not access_token:
        return f"⚠️ Could not analyze {ticker}: Failed to get GoPlus auth token."
    headers = {"Authorization": f"Bearer {access_token}"}
    malicious_flags = []
    goplus_token_data = {}
    
    async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
        try:
            url = f"{GOPLUS_ADDRESS_API_URL}/{deployer_wallet}?chain_id=solana"
            response = await client.get(url)
            response.raise_for_status()
            wallet_analysis = response.json().get('result', {})
            if wallet_analysis.get('honeypot_related_address') == '1': malicious_flags.append("Honeypot Creator")
            if wallet_analysis.get('cybercrime') == '1': malicious_flags.append("Cybercrime")
        except Exception as e:
            print(f"Error analyzing wallet with GoPlus: {e}")
        
        try:
            params = {'contract_addresses': mint_address}
            response = await client.get(GOPLUS_TOKEN_API_URL, params=params)
            response.raise_for_status()
            goplus_token_data = response.json().get('result', {}).get(mint_address, {})
            if not goplus_token_data:
                return f"⚠️ Analysis for ${ticker} ({mint_address}) delayed. GoPlus has no data yet."
        except Exception as e:
            return f"⚠️ Could not analyze token: {mint_address}. GoPlus Error: {e}"

    if malicious_flags:
        alert_type = "🚨 RED ALERT: KNOWN MALICIOUS WALLET 🚨"
        alert_reason = f"GoPlus flagged deployer for: {', '.join(malicious_flags)}."
    elif goplus_token_data.get('is_honeypot') == "1":
        alert_type = "🚨 RED ALERT: HONEYPOT 🚨"
        alert_reason = "GoPlus reports this is a honeypot (buy only)."
    else:
        alert_type = "✅ Alert: Potential Runner"
        alert_reason = "No immediate red flags found."

    lp_status = "UNLOCKED" if goplus_token_data.get('lp_locked') == "0" else "LOCKED"
    deployer_pct = float(goplus_token_data.get('deployer_holdings_percent', 0)) * 100
    top_10_pct = float(goplus_token_data.get('top_10_holders_percent', 0)) * 100

    message = (
        f"{alert_type}\n\n"
        f"*Ticker:* ${ticker}\n"
        f"*Mint:* `{mint_address}`\n"
        f"*Deployer:* `{deployer_wallet}`\n\n"
        f"--- SAFETY ANALYSIS ---\n"
        f"*Risk:* {alert_reason}\n"
        f"*Liquidity:* {lp_status}\n"
        f"*Deployer Holdings:* {deployer_pct:.2f}%\n"
        f"*Top 10 Holders:* {top_10_pct:.2f}%"
    )
    return message

async def send_telegram_alert(bot, message):
    print("Sending Telegram alert...")
    try:
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode="Markdown")
    except Exception as e:
        print(f"Error sending Telegram message: {e}")

# --- THIS IS THE MAIN VERCEL FUNCTION ---
# This is the "doorbell" that Vercel will ring.
@app.route('/api/check', methods=['GET'])
def check_and_alert():
    # We must run our async code in a synchronous context
    asyncio.run(run_check())
    return jsonify(status="Check completed"), 200

async def run_check():
    # This is the body of your old `while True` loop
    try:
        bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
        
        # You need a simple way to track seen tokens. Vercel KV is best,
        # but for now, we just check the latest tokens and assume
        # if they are new in the last 10 mins, we haven't seen them.
        # This is a limitation of stateless functions.
        print("--- Vercel Cron Job Triggered ---")
        
        if not await get_goplus_access_token():
            print("CRITICAL: Failed to get GoPlus auth token.")
            await send_telegram_alert(bot, "🛑 BOT ERROR: Could not authenticate with GoPlusLabs.")
            return

        new_tokens = await get_new_tokens()
        if not new_tokens:
            print("No new tokens found.")
            return

        # Simple check: filter for tokens created in the last 10 minutes (600 seconds)
        # to avoid sending old alerts every time the cron job runs.
        current_time = int(time.time())
        really_new_tokens = []
        for asset in new_tokens:
            try:
                created_at = asset.get('time_info', {}).get('created_at', 0)
                if (current_time - created_at) < 600: # 10 minutes
                    ticker = asset['content']['metadata']['symbol']
                    mint_address = asset['id']
                    deployer_wallet = asset['creators'][0]['address']
                    
                    really_new_tokens.append({
                        'ticker': ticker,
                        'mint_address': mint_address,
                        'deployer_wallet': deployer_wallet
                    })
            except Exception:
                continue # Skip malformed asset

        if not really_new_tokens:
            print("Tokens found, but none are new in the last 10 minutes.")
            return
            
        for token in really_new_tokens:
            print(f"--- New Token Detected: ${token['ticker']} ---")
            analysis_message = await analyze_token_safety(token['mint_address'], token['deployer_wallet'], token['ticker'])
            await send_telegram_alert(bot, analysis_message)
            
    except Exception as e:
        print(f"An error occurred in the main check: {e}")
        try:
            bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
            await send_telegram_alert(bot, f"🛑 BOT CRITICAL ERROR: {e}")
        except Exception as e2:
            print(f"Failed to send critical error alert: {e2}")

# A simple root route to prove the app is alive
@app.route('/', methods=['GET'])
def home():
    return "Your Vercel-Python bot is alive. The cron job runs at /api/check.", 200

