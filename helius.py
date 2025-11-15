import requests
import config  # Your config.py file
import logging
import html    # --- FIX 1: Import the HTML escaper ---

# --- Setup ---
logger = logging.getLogger("MemeVision")
HELIUS_API_URL = f"https://mainnet.helius-rpc.com/?api-key={config.HELIUS_API_KEY}"
DEXSCREENER_API_URL = "https://api.dexscreener.com/latest/dex/search?q="
PUMP_FUN_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P" # --- FIX 2: We need this back ---

def get_token_audit(mint_ca: str) -> dict:
    """
    Uses DexScreener to get name, mcap, and liquidity.
    Finds the pair with the MOST liquidity.
    """
    try:
        url = f"{DEXSCREENER_API_URL}{mint_ca}"
        response = requests.get(url)
        response_json = response.json()
        
        pairs = response_json.get('pairs')
        if not pairs:
            # --- FIX 3: THIS IS NOT A RUG, IT'S JUST NOT ON DEXSCREENER ---
            return {"name": "Unknown (Not on DexScreener)", "mcap": 0, "liquidity": 0, "is_rug": False, "not_on_dex": True}
            
        best_pair = None
        max_liquidity = -1
        for pair in pairs:
            pair_liquidity_str = pair.get('liquidity', {}).get('usd')
            pair_liquidity = 0
            if pair_liquidity_str:
                try: pair_liquidity = float(pair_liquidity_str)
                except (ValueError, TypeError): pair_liquidity = 0
            
            if pair_liquidity > max_liquidity:
                max_liquidity = pair_liquidity
                best_pair = pair

        if not best_pair:
             return {"name": "Unknown (No Valid Pair)", "mcap": 0, "liquidity": 0, "is_rug": True, "not_on_dex": False}

        # --- FIX 4: Escape the name! ---
        name = html.escape(best_pair.get('baseToken', {}).get('name', 'Unknown Name'))
        mcap_str = best_pair.get('marketCap')
        liquidity = max_liquidity
        
        mcap = 0
        if mcap_str:
            try: mcap = float(mcap_str)
            except (ValueError, TypeError): mcap = 0
                
        is_rug = (liquidity < 1000) # Our "rug" definition (if it's on DexScreener)
        
        return {"name": name, "mcap": mcap, "liquidity": liquidity, "is_rug": is_rug, "not_on_dex": False}
        
    except Exception as e:
        logger.error(f"DexScreener API Error: {e}")
        return {"name": "Error (DexScreener)", "mcap": 0, "liquidity": 0, "is_rug": True, "not_on_dex": False}

def find_dev_from_state(asset: dict) -> tuple[str, str]:
    """
    Finds the dev wallet OR "pump.fun" OR "renounced"
    Returns: (wallet_type, wallet_address)
    """
    # 1. Check owner first for pump.fun
    owner = asset.get('owner')
    if owner == PUMP_FUN_PROGRAM_ID:
        logger.info("Found via: pump.fun")
        return "pump.fun", PUMP_FUN_PROGRAM_ID

    # 2. Check 'mint_authority'
    token_info = asset.get('token_info')
    if token_info and token_info.get('mint_authority'):
        logger.info("Found via: token_info.mint_authority")
        return "Mint Authority", token_info.get('mint_authority')
        
    # 3. Check if renounced (mint_authority is null)
    if token_info and token_info.get('mint_authority') is None:
         logger.info("Found via: Renounced Mint")
         return "renounced", None

    # 4. Fallback checks (less common)
    if authorities := asset.get('authorities'):
        if authorities[0].get('address'):
            logger.info("Found via: authorities")
            return "Authority", authorities[0].get('address')
            
    if creators := asset.get('creators'):
        if creators[0].get('address'):
            logger.info("Found via: creators")
            return "Creator", creators[0].get('address')
            
    return None, None

def get_dev_report(contract_address: str) -> str:
    """
    --- THIS IS THE NEW v1.0 REPORT GENERATOR ---
    It correctly handles pump.fun, renounced, and active devs.
    """
    try:
        # --- Step 1: Get the Token's State ---
        logger.info(f"Step 1: Fetching asset state for {contract_address}")
        payload = {
            "jsonrpc": "2.0", "id": "memevision-v1.0", "method": "getAsset",
            "params": {
                "id": contract_address,
                "displayOptions": {"showFungible": True} # Ask for token info
            }
        }
        response = requests.post(HELIUS_API_URL, json=payload)
        response_json = response.json()
        if "error" in response_json:
            return f"❌ <b>Error (getAsset):</b> {response_json['error']['message']}"
        asset = response_json.get('result')
        if not asset:
            return "❌ <b>Error:</b> Could not find this token. Is it a valid Solana CA?"
            
        # --- Step 2: Find the Dev using the Waterfall ---
        wallet_type, dev_wallet = find_dev_from_state(asset)

        if not wallet_type:
            return ("❌ <b>Error: Un-analyzable Token</b>\n\n"
                    "This token has no clear owner or authority. This is a major red flag.")

        # Escape all text for safety
        safe_ca = html.escape(contract_address)
        safe_dev_wallet = html.escape(dev_wallet) if dev_wallet else ""

        # --- ================================== ---
        # --- BRAIN #1: PUMP.FUN TOKEN ---
        # --- ================================== ---
        if wallet_type == "pump.fun":
            logger.info("Token is on pump.fun. Running pump.fun report.")
            # We can't check dev history, but we can audit the token itself
            audit = get_token_audit(safe_ca) # Checks DexScreener
            name = audit['name']
            
            if audit['not_on_dex']:
                return (
                    f"⚠️ <b>PUMP.FUN TOKEN (Pre-Launch)</b> ⚠️\n\n"
                    f"<b>Token:</b> <code>{safe_ca[:10]}...</code>\n\n"
                    "This token is on the <b>pump.fun</b> bonding curve. It has not launched on Raydium/Jupiter yet.\n\n"
                    "<b>Verdict:</b> Cannot be audited. This is a brand new token."
                )
            else:
                # It's on pump.fun *and* DexScreener? Weird, but we can report it.
                mcap = audit['mcap']
                liquidity = audit['liquidity']
                return (
                    f"⚠️ <b>PUMP.FUN TOKEN (Active)</b> ⚠️\n\n"
                    f"<b>Token:</b> \"{name}\" <code>({safe_ca[:6]}...)</code>\n"
                    f"<b>MCap:</b> ${mcap:,.0f}\n"
                    f"<b>Liquidity:</b> ${liquidity:,.0f}\n\n"
                    "This token is owned by the <b>pump.fun</b> program. Dev history cannot be analyzed."
                )

        # --- ================================== ---
        # --- BRAIN #2: RENOUNCED TOKEN AUDIT ---
        # --- ================================== ---
        elif wallet_type == "renounced":
            logger.info("Token is renounced. Running Token Health Audit...")
            audit = get_token_audit(safe_ca)
            name = audit['name']
            mcap = audit['mcap']
            liquidity = audit['liquidity']
            report_lines = [
                f"<b>Token:</b> \"{name}\" <code>({safe_ca[:6]}...)</code>",
                f"<b>MCap:</b> ${mcap:,.0f}",
                f"<b>Liquidity:</b> ${liquidity:,.0f}\n"
            ]
            
            if audit['is_rug']:
                report_lines.insert(0, "❌ <b>VERDICT: CONFIRMED RUG PULL</b> ❌\n")
                report_lines.append("Mint is renounced, but <b>liquidity is $0</b> (or < $1k).")
                report_lines.append("This is a 100% rug pull.")
            else:
                report_lines.insert(0, "✅ <b>TOKEN HEALTH: GOOD (Renounced)</b> ✅\n")
                report_lines.append("Mint is renounced and token has liquidity.")
                report_lines.append("This is a very good sign of safety.")
            return "\n".join(report_lines)

        # --- ================================== ---
        # --- BRAIN #3: ACTIVE DEV AUDIT ---
        # --- ================================== ---
        else:
            logger.info(f"Step 2: Found Active Dev Wallet ({wallet_type}): {safe_dev_wallet}")
            payload_rap_sheet = {
                "jsonrpc": "2.0", "id": "memevision-rap-1", "method": "getAssetsByCreator",
                "params": {"creatorAddress": safe_dev_wallet, "onlyVerified": False, "page": 1, "limit": 10}
            }
            response_rap = requests.post(HELIUS_API_URL, json=payload_rap_sheet)
            response_rap_json = response_rap.json()
            if "error" in response_rap_json:
                return f"❌ <b>Error (getAssetsByCreator):</b> {response_rap_json['error']['message']}"
            past_projects = response_rap_json.get('result', {}).get('items', [])
            other_projects = [p for p in past_projects if p.get('id') != safe_ca]
            num_other_projects = len(other_projects)
            report_lines = [
                "<b>DEV CHECK REPORT (v1.0 Audit)</b>\n",
                f"<b>Token:</b> <code>{safe_ca[:10]}...</code>",
                f"<b>Dev Wallet ({wallet_type}):</b> <code>{safe_dev_wallet}</code>",
                "⚠️ <b>WARNING: Mint Authority is Active!</b> ⚠️\n"
            ]
            if num_other_projects == 0:
                rating = "★☆☆☆☆ (HIGH RISK)"
                report_lines.append(f"<b>Dev Rating: {rating}</b>\n")
                report_lines.append("This developer wallet has <b>no other projects</b> linked to it.")
                report_lines.append("This is a <b>brand new wallet</b>, a common tactic for rug pulls.")
                report_lines.append("\n<b>Verdict:</b> The dev is new AND still has mint control. <b>EXTREME RISK.</b>")
            else:
                logger.info(f"Step 4: Auditing {num_other_projects} past projects...")
                report_lines.append(f"This dev wallet is linked to <b>{num_other_projects}</b> other projects:")
                total_rugs = 0
                for i, proj in enumerate(other_projects[:5]):
                    proj_ca = proj.get('id', 'unknown_id')
                    audit = get_token_audit(proj_ca)
                    name = audit['name'] # Already escaped by get_token_audit
                    mcap = audit['mcap']
                    liquidity = audit['liquidity']
                    is_rug = audit['is_rug']
                    if is_rug:
                        total_rugs += 1
                        status = "<b>(CONFIRMED RUG)</b>"
                    else:
                        status = "(Alive)"
                    report_lines.append(f"\n  <b>{i+1}. Token:</b> \"{name}\" <code>({html.escape(proj_ca[:6])}...)</code>")
                    report_lines.append(f"     - <b>MCap:</b> ${mcap:,.0f}")
                    report_lines.append(f"     - <b>Liquidity:</b> ${liquidity:,.0f} {status}")
                if total_rugs == num_other_projects:
                    rating = "★☆☆☆☆ (SERIAL RUGGER)"
                    verdict = f"This dev has rugged <b>all {total_rugs}</b> tracked projects. <b>DO NOT BUY.</b>"
                elif total_rugs > 0:
                    rating = "★★☆☆☆ (HIGH RISK)"
                    verdict = f"This dev has rugged <b>{total_rugs} out of {num_other_projects}</b> projects. High risk."
                else:
                    rating = "★★★☆☆ (REPUTABLE BUT RISKY)"
                    verdict = "All past projects appear alive, but the dev still has mint control of this new token. Be cautious."
                report_lines.insert(4, f"<b>Dev Rating: {rating}</b>\n")
                report_lines.append(f"\n<b>Verdict:</b> {verdict}")
            return "\n".join(report_lines)

    except Exception as e:
        logger.error(f"Error in get_dev_report: {e}")
        return f"❌ <b>API Error:</b> Could not complete the check. (Error: {e})"

