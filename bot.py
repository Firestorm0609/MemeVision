import os
import requests # Still used for the 'exceptions' in try/except blocks
import httpx # The async HTTP client
import asyncio # The async library
import time
import telegram
from dotenv import load_dotenv
import hashlib
import json

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
SEEN_MINTS = set()
GOPLUS_AUTH_TOKEN = {}

async def get_goplus_access_token():
    """
    Gets a valid GoPlusLabs access token, refreshing if necessary.
    Uses async httpx.
    """
    global GOPLUS_AUTH_TOKEN

    if 'token' in GOPLUS_AUTH_TOKEN and GOPLUS_AUTH_TOKEN.get('expires_at', 0) > (time.time() + 300):
        return GOPLUS_AUTH_TOKEN['token']

    print("Requesting new GoPlus access token...")
    try:
        request_time = str(int(time.time()))
        sign_str = GOPLUS_APP_KEY + request_time + GOPLUS_APP_SECRET
        signature = hashlib.sha1(sign_str.encode()).hexdigest()
        
        payload = {
            "app_key": GOPLUS_APP_KEY,
            "sign": signature,
            "time": request_time
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(GOPLUS_AUTH_URL, json=payload)
            response.raise_for_status()
        
        data = response.json()
        
        if data.get('code') == 1:
            access_token = data['result']['access_token']
            expires_in = int(data['result']['expires_in'])
            
            GOPLUS_AUTH_TOKEN = {
                'token': access_token,
                'expires_at': time.time() + expires_in
            }
            print("Successfully obtained GoPlus token.")
            return access_token
        else:
            print(f"Error getting GoPlus token: {data.get('message')}")
            return None

    except Exception as e:
        print(f"Exception getting GoPlus token: {e}")
        return None

async def get_new_tokens():
    """
    Polls the Helius DAS API to find the newest fungible tokens.
    Uses async httpx.
    """
    print("Checking Helius for new tokens...")
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": "helius-bot",
            "method": "searchAssets",
            "params": {
                "tokenType": "fungible",
                "sortBy": {"sortBy": "created", "sortDirection": "desc"},
                "limit": 100,
                "page": 1
            }
        }
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(HELIUS_API_URL, json=payload)
            response.raise_for_status() 
        
        result = response.json().get('result', {})
        helius_assets = result.get('items', [])
        
        new_tokens = []
        for asset in helius_assets:
            try:
                if not asset.get('content', {}).get('metadata', {}).get('symbol') or not asset.get('creators'):
                    continue

                ticker = asset['content']['metadata']['symbol']
                mint_address = asset['id']
                deployer_wallet = asset['creators'][0]['address']
                timestamp = asset.get('time_info', {}).get('created_at', int(time.time()))
                
                new_tokens.append({
                    'ticker': ticker,
                    'mint_address': mint_address,
                    'deployer_wallet': deployer_wallet,
                    'timestamp': timestamp
                })
            except KeyError as e:
                print(f"Error parsing asset {asset.get('id')}: {e}")
                continue
                
        return new_tokens

    except (httpx.RequestError, requests.exceptions.RequestException) as e:
        print(f"Error fetching new tokens from Helius: {e}")
        return []
    except Exception as e:
        print(f"General error in get_new_tokens: {e}")
        return []

async def analyze_token_safety(mint_address, deployer_wallet, ticker):
    """
    Uses GoPlus APIs for BOTH token and wallet analysis.
    Uses async httpx.
    """
    print(f"Analyzing {ticker} ({mint_address})...")
    
    access_token = await get_goplus_access_token()
    if not access_token:
        return f"⚠️ Could not analyze {ticker}: Failed to get GoPlus auth token."
        
    headers = {"Authorization": f"Bearer {access_token}"}
    
    wallet_is_malicious = False
    malicious_flags = []
    goplus_token_data = {}
    
    async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
        # --- CALL 1: GoPlus (Wallet Check) ---
        try:
            url = f"{GOPLUS_ADDRESS_API_URL}/{deployer_wallet}?chain_id=solana"
            response = await client.get(url)
            response.raise_for_status()
            
            wallet_analysis = response.json().get('result', {})
            
            if wallet_analysis.get('honeypot_related_address') == '1': malicious_flags.append("Honeypot Creator")
            if wallet_analysis.get('cybercrime') == '1': malicious_flags.append("Cybercrime")
            if wallet_analysis.get('phishing_activities') == '1': malicious_flags.append("Phishing")
            if wallet_analysis.get('stealing_attack') == '1': malicious_flags.append("Stealing Attacks")
                
            if malicious_flags:
                wallet_is_malicious = True
            
        except (httpx.RequestError, requests.exceptions.RequestException) as e:
            print(f"Error analyzing wallet with GoPlus: {e}")
        
        # --- CALL 2: GoPlus (Token Check) ---
        try:
            params = {'contract_addresses': mint_address}
            response = await client.get(GOPLUS_TOKEN_API_URL, params=params)
            response.raise_for_status()
            
            goplus_report = response.json()
            goplus_token_data = goplus_report.get('result', {}).get(mint_address, {})
            
            if not goplus_token_data:
                return f"⚠️ Analysis for ${ticker} ({mint_address}) delayed. GoPlus has no data yet."

        except (httpx.RequestError, requests.exceptions.RequestException) as e:
            print(f"Error analyzing token with GoPlus: {e}")
            return f"⚠️ Could not analyze token: {mint_address}. GoPlus Error: {e}"
        except KeyError:
            return f"⚠️ Analysis failed for {mint_address}. Unexpected data from GoPlus."

    # --- 3. Build the Alert Message ---
    if wallet_is_malicious:
        alert_type = "🚨 RED ALERT: KNOWN MALICIOUS WALLET 🚨"
        alert_reason = f"GoPlus flagged deployer for: {', '.join(malicious_flags)}."
    elif goplus_token_data.get('is_honeypot') == "1":
        alert_type = "🚨 RED ALERT: HONEYPOT 🚨"
        alert_reason = "GoPlus reports this is a honeypot (buy only)."
    elif goplus_token_data.get('lp_locked') == "0":
        alert_type = "⚠️ HIGH RISK: LIQUIDITY UNLOCKED ⚠️"
        alert_reason = "Liquidity is NOT locked. Deployer can rug."
    else:
        alert_type = "✅ Alert: Potential Runner"
        alert_reason = "No immediate red flags found."

    try:
        lp_status = "UNLOCKED" if goplus_token_data.get('lp_locked') == "0" else "LOCKED"
        deployer_pct = float(goplus_token_data.get('deployer_holdings_percent', 0)) * 100
        top_10_pct = float(goplus_token_data.get('top_10_holders_percent', 0)) * 100
    except (ValueError, TypeError):
        lp_status, deployer_pct, top_10_pct = "Unknown", "Unknown", "Unknown"

    message = (
        f"{alert_type}\n\n"
        f"*Ticker:* ${ticker}\n"
        f"*Mint:* `{mint_address}`\n"
        f"*Deployer:* `{deployer_wallet}`\n\n"
        f"--- SAFETY ANALYSIS ---\n"
        f"*Risk:* {alert_reason}\n"
        f"*Liquidity:* {lp_status}\n"
        f"*Deployer Holdings:* {deployer_pct if deployer_pct == 'Unknown' else f'{deployer_pct:.2f}%'}\n"
        f"*Top 10 Holders:* {top_10_pct if top_10_pct == 'Unknown' else f'{top_10_pct:.2f}%'}"
    )
    return message

async def send_telegram_alert(bot, message):
    """
    Sends a formatted message to your Telegram chat.
    Uses async/await.
    """
    print("Sending Telegram alert...")
    try:
        # --- THIS IS THE FIX ---
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=message,
            parse_mode="Markdown"
        )
    except Exception as e:
        print(f"Error sending Telegram message: {e}")

async def main():
    """
    Main loop for the bot. Now async.
    """
    try:
        bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
        print("Bot started. Awaiting new tokens...")
        
        if not await get_goplus_access_token():
            print("CRITICAL: Failed to get GoPlus auth token. Check Goplus keys.")
            await send_telegram_alert(bot, "🛑 BOT ERROR: Could not authenticate with GoPlusLabs. Check App Key/Secret.")
            return
            
        await send_telegram_alert(bot, "✅ Solana First-Mover Bot (v5.0 - Async) is ONLINE.")
    
    except Exception as e:
        print(f"Error initializing Telegram bot. Check your TELEGRAM_BOT_TOKEN. Error: {e}")
        return

    while True:
        try:
            new_tokens = await get_new_tokens()
            
            if not new_tokens:
                await asyncio.sleep(10) # Use async sleep
                continue

            new_tokens.sort(key=lambda x: x['timestamp'])

            for token in new_tokens:
                mint_address = token['mint_address']
                
                if mint_address not in SEEN_MINTS:
                    ticker = token['ticker']
                    deployer_wallet = token['deployer_wallet']
                    
                    print(f"--- New First-Mover Detected: ${ticker} ({mint_address}) ---")
                    SEEN_MINTS.add(mint_address)
                    
                    analysis_message = await analyze_token_safety(mint_address, deployer_wallet, ticker)
                    
                    await send_telegram_alert(bot, analysis_message)

            await asyncio.sleep(10) # Use async sleep

        except KeyboardInterrupt:
            print("\nBot shutting down...")
            await send_telegram_alert(bot, "🛑 Solana First-Mover Bot (v5.0) is OFFLINE.")
            break
        except Exception as e:
            print(f"An error occurred in the main loop: {e}")
            try:
                await send_telegram_alert(bot, f"🛑 BOT ERROR: {e}. Restarting loop...")
            except Exception as e2:
                print(f"Failed to send error alert: {e2}")
            await asyncio.sleep(30) # Use async sleep

if __name__ == "__main__":
    # --- THIS IS THE FIX for starting an async main function ---
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot shut down by user.")

