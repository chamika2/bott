# -*- coding: utf-8 -*-
# Bot Tool Name: Advanced SNI Hunter Bot (Sinhala/English Dual Language)

import telebot
import requests
import socket
import ssl
import concurrent.futures
import threading
import sqlite3
import datetime
import time
import dns.resolver
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, BotCommand

# ----------------------------------------------------
# --- 1. CONFIGURATION & SETTINGS ---
# ----------------------------------------------------

# 🚨 CRITICAL: REPLACE THESE VALUES
BOT_TOKEN = '8205587502:AAEnWA_-TcEXm7qPyojU_7W04AmjTXxdCI8' 
ADMIN_USERNAME = '@prasa_z' 
ADMIN_ID = 6221106415 
REQUIRED_CHANNEL = "@sni_hunter" 
# 🚨 END CRITICAL BLOCK

# Scanning Settings
DEFAULT_PORTS = [80, 443, 8080, 8443, 2053, 2083, 4444] 
TIMEOUT = 1.0
MAX_WORKERS = 40
FREE_SCAN_LIMIT = 10 
FREE_HOST_LIMIT = 50 

# Advanced Latency Check Nodes
LATENCY_CHECK_NODES = {
    "🇱🇰 Sri Lanka": "103.247.16.1", 
    "🇸🇬 Singapore": "1.1.1.1",     
    "🇺🇸 New York": "8.8.8.8"      
}

# Database
DB_NAME = 'sni_bot_users.db'

# AI Wordlist (For ML-based Predictive Scans)
PREDICTIVE_WORDLIST = [
    "api", "dev", "web", "cdn", "mail", "proxy", "vpn", "access", "live", "app", 
    "static", "assets", "mobile", "staging", "server", "tunnel", "connect", "zero", "fast"
]

# --- Bot Initialization ---
bot = telebot.TeleBot(BOT_TOKEN)

# ----------------------------------------------------
# --- 2. DUAL LANGUAGE MESSAGES (FINALIZED) ---
# ----------------------------------------------------

# 🚨 PREMIUM BENEFITS MESSAGE (English Only, as requested)
PREMIUM_BENEFITS_MESSAGE = f"""
👑 <b>Premium Benefits</b> 👑
------------------------------------------------
✅ <b>Unlimited Scans:</b> Bypass daily scan limits.
✅ <b>Zero-Day ML Scan:</b> Find hidden SNI patterns using Machine Learning analysis. (<code>/ml_sni_scan</code>)
✅ <b>Live Latency Check:</b> Test global response time (ms) for optimal configuration. (<code>/latency</code>)
✅ <b>Proactive Monitoring:</b> Automated alerts when a watched host's IP or Status Code changes. (<code>/watch</code>)
✅ <b>Full Results:</b> Get all scan results (Removes the {FREE_HOST_LIMIT} hosts limit).
✅ <b>Ad-Free Experience:</b> Enjoy an uninterrupted experience with no advertisements.

💵 <b>Fee:</b> Rs. 500/Month

🏦 <b>Bank Details:</b>
  <b>Bank:</b> <code>BOC</code>
  <b>A/C Name:</b> <code>K.G.C.SILVA</code>
  <b>A/C No:</b> <code>93872075</code>

📤 <b>How to Pay:</b>
ගෙවීම් කළ පසු, ඔබගේ <b>ගෙවීම් රිසිට්පත (Payment Receipt)</b> සහ ඔබගේ Telegram <b>User Name</b> එක {ADMIN_USERNAME} වෙත එවන්න.
"""

# PREMIUM REQUIRED MESSAGE (Dual Language)
PREMIUM_MESSAGE = f"""
👑 <b>Premium Access අවශ්‍යයි</b> 👑

ඔබ අද දිනට හිමි <b>නොමිලේ Scan සීමාව ({FREE_SCAN_LIMIT})</b> භාවිතා කර අවසන්.
Advanced විශේෂාංග (ML Scan, Latency Check, Monitoring) සඳහාද ඔබට Premium අවශ්‍ය වේ.
----------------------------------------
👑 <b>Premium Access Required</b> 👑
You have used your <b>Daily Free Scan limit ({FREE_SCAN_LIMIT})</b>.
Advanced features require Premium. Check <code>/benefits</code> for more info.
"""

# WELCOME MESSAGE (Dual Language)
WELCOME_MESSAGE = f"""
🤖 <b>Advanced SNI Hunter Bot</b> වෙත සාදරයෙන් පිළිගනිමු!

✨ <b>Features / විශේෂාංග:</b>
  • Domain Scanning (<code>/scan</code>)
  • DNS Lookup (<code>/dns</code>)
  • Header Analysis (<code>/header</code>)
  • Port/Proxy Probe (<code>/probe</code>)
  • <b>Premium:</b> <code>/ml_sni_scan</code>, <code>/latency</code>, <code>/watch</code>
----------------------------------------
✨ <b>Daily Free Offer:</b>
ඔබට දිනකට <b>සම්පූර්ණ Scans {FREE_SCAN_LIMIT}ක්</b> නොමිලේ භාවිතා කළ හැක. / You can use <b>{FREE_SCAN_LIMIT} complete Scans</b> per day for free.
භාවිතා කරන ආකාරය: <code>/scan domain.com</code>
"""
# ----------------------------------------------------
# --- 3. DATABASE AND UTILITY FUNCTIONS ---
# ----------------------------------------------------

def setup_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT, 
            free_scans_used INTEGER DEFAULT 0,
            last_scan_date TEXT,
            is_premium INTEGER DEFAULT 0,
            premium_expiry TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            log_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            domain TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS watchlist (
            watch_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            domain TEXT UNIQUE,
            last_check_ip TEXT,
            last_check_status TEXT
        )
    """)
    conn.commit()
    conn.close()

def check_membership(user_id):
    """Checks if the user is a member of the required channel."""
    if not REQUIRED_CHANNEL:
        return True # Skip check if channel is not defined

    try:
        # Check if the bot can see the user's status in the channel
        member = bot.get_chat_member(REQUIRED_CHANNEL, user_id)
        if member.status in ['member', 'administrator', 'creator']:
            return True
        else:
            return False
    except telebot.apihelper.ApiException as e:
        # Error 400: Bad Request: member list is inaccessible (Admin permission issue)
        if 'member list is inaccessible' in str(e):
             print(f"ERROR 400: Member list inaccessible for {REQUIRED_CHANNEL}. Check Bot Admin permissions.")
             return False # Force them to join/fix the issue
        # Error 400: User not found in chat (or bot is blocked by user)
        elif 'user not found' in str(e):
             return False
        else:
             print(f"TeleBot API Error in check_membership: {e}")
             return False # Default to false on unknown error

def send_join_channel_message(message):
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton(text="➡️ Join Channel", url=f"https://t.me/{REQUIRED_CHANNEL.replace('@', '')}"))
    
    join_msg = (
        f"🔒 <b>Access Denied / ප්‍රවේශය ප්‍රතික්ෂේප විය</b>\n\n"
        f"Bot එක භාවිතා කිරීමට පෙර කරුණාකර අපගේ චැනලයට සම්බන්ධ වන්න: <b>{REQUIRED_CHANNEL}</b>\n"
        f"Before using the Bot, please join our channel: <b>{REQUIRED_CHANNEL}</b>"
    )
    bot.reply_to(message, join_msg, parse_mode='HTML', reply_markup=keyboard)

def get_user_status(user_id, username=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT free_scans_used, is_premium, premium_expiry FROM users WHERE user_id=?", (user_id,))
    user_data = cursor.fetchone()
    
    if user_data:
        free_scans_used, is_premium, premium_expiry = user_data
    else:
        expiry = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')
        cursor.execute("INSERT INTO users (user_id, username, last_scan_date, premium_expiry) VALUES (?, ?, ?, ?)", 
                       (user_id, username, datetime.date.today().strftime('%Y-%m-%d'), expiry))
        conn.commit()
        free_scans_used, is_premium, premium_expiry = 0, 0, expiry
        
    conn.close()
    return free_scans_used, is_premium, premium_expiry

def check_premium_expiry(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT is_premium, premium_expiry FROM users WHERE user_id=?", (user_id,))
    data = cursor.fetchone()
    
    if data and data[0] == 1:
        expiry_date = datetime.datetime.strptime(data[1], '%Y-%m-%d').date()
        if expiry_date < datetime.date.today():
            cursor.execute("UPDATE users SET is_premium=0, premium_expiry=? WHERE user_id=?", 
                           ((datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d'), user_id))
            conn.commit()
            try:
                bot.send_message(user_id, "🔔 <b>Premium Expired:</b> Your Premium access has expired. Please renew via /premium.", parse_mode='HTML')
            except:
                pass 
    conn.close()

def check_and_reset_daily_limit(user_id, current_used):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    today = datetime.date.today().strftime('%Y-%m-%d')
    
    cursor.execute("SELECT last_scan_date FROM users WHERE user_id=?", (user_id,))
    last_date_str = cursor.fetchone()[0]
    last_date = datetime.datetime.strptime(last_date_str, '%Y-%m-%d').date()
    
    if last_date < datetime.date.today():
        current_used = 0
        cursor.execute("UPDATE users SET free_scans_used=0, last_scan_date=? WHERE user_id=?", 
                       (today, user_id))
        conn.commit()
        
    conn.close()
    return current_used

def update_scan_count(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    today = datetime.date.today().strftime('%Y-%m-%d')
    
    cursor.execute("UPDATE users SET free_scans_used = free_scans_used + 1, last_scan_date=? WHERE user_id=?", 
                   (today, user_id))
    conn.commit()
    conn.close()


# --- Core Utility Functions (Scanning/Data Retrieval) ---

def get_isp_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=isp,org,as,countryCode"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            isp = data.get('isp', 'Unknown').replace('<', '&lt;').replace('>', '&gt;')
            country = data.get('countryCode', 'XX')
            return f"{isp} ({data.get('as', '')}) [🇨{country}]"
    except:
        return "Unknown ISP"
    return "Unknown ISP"

def fetch_subdomains(domain):
    subdomains = set()
    crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(crt_url, headers=headers, timeout=15)
        if response.status_code == 200 and response.text:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                if name_value:
                    for sub in name_value.split('\n'):
                        if sub.strip() and "*" not in sub and sub.endswith(domain):
                            subdomains.add(sub.strip())
    except Exception:
        pass
            
    return list(subdomains)

def scan_target(host):
    data = {
        "host": host, "ip": "N/A", "ports": [], "server": "Unknown", "status": "Offline"
    }
    
    try:
        ip = socket.gethostbyname(host)
        data["ip"] = ip
        data["status"] = "Online"
        
        for port in DEFAULT_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                data["ports"].append(port)
                if port in [80, 443, 8080, 8443] and data["server"] == "Unknown":
                     
                     resp = ""
                     try:
                         if port in [443, 8443, 2053, 2083]:
                             context = ssl.create_default_context()
                             context.check_hostname = False
                             context.verify_mode = ssl.CERT_NONE
                             with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
                                 with context.wrap_socket(s, server_hostname=host) as ssock:
                                     ssock.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                                     resp = ssock.read(1024).decode('utf-8', errors='ignore')
                         else:
                             s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                             s.settimeout(TIMEOUT)
                             s.connect((ip, port))
                             s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                             resp = s.recv(1024).decode('utf-8', errors='ignore')
                             s.close()
                         
                         for line in resp.split("\r\n"):
                             if line.lower().startswith("server:"):
                                 data["server"] = line.split(":", 1)[1].strip()
                     except Exception:
                          pass 
            sock.close()
            
        if data["ports"]:
            data["isp"] = get_isp_info(ip)

    except socket.gaierror:
        data["status"] = "DNS Fail"
    except Exception:
        pass
        
    return data

def generate_ml_based_subdomains(domain):
    ml_hosts = set(f"{word}.{domain}" for word in PREDICTIVE_WORDLIST)
    
    tld_variations = [".net", ".co", ".in", ".org"]
    for tld in tld_variations:
        ml_hosts.add(domain.replace(".com", tld) if ".com" in domain else f"api.{domain}{tld}")
    
    if "api" not in domain:
        ml_hosts.add(f"api.{domain}")
        
    return list(ml_hosts)


# ----------------------------------------------------
# --- 4. DECORATORS AND PREMIUM CHECK ---
# ----------------------------------------------------

def premium_required(func):
    def wrapper(message, *args, **kwargs):
        user_id = message.from_user.id
        username = f"@{message.from_user.username}" if message.from_user.username else f"ID_{message.from_user.id}"
        
        if not check_membership(user_id):
            send_join_channel_message(message)
            return

        check_premium_expiry(user_id)
        _, is_premium, _ = get_user_status(user_id, username)
        
        if is_premium == 0:
            bot.reply_to(message, PREMIUM_MESSAGE, parse_mode='HTML')
            return
            
        return func(message, *args, **kwargs)
    return wrapper

def free_scan_check(func):
    def wrapper(message, *args, **kwargs):
        user_id = message.from_user.id
        username = f"@{message.from_user.username}" if message.from_user.username else f"ID_{message.from_user.id}"

        if not check_membership(user_id):
            send_join_channel_message(message)
            return
            
        check_premium_expiry(user_id)
        scans_used, is_premium, _ = get_user_status(user_id, username)
        scans_used = check_and_reset_daily_limit(user_id, scans_used)

        if is_premium == 1:
            return func(message, *args, **kwargs)
        
        if scans_used >= FREE_SCAN_LIMIT:
            bot.reply_to(message, PREMIUM_MESSAGE, parse_mode='HTML')
            return

        result = func(message, *args, **kwargs)
        update_scan_count(user_id)
        return result
    return wrapper


# ----------------------------------------------------
# --- 5. USER COMMAND HANDLERS (FREE FEATURES) ---
# ----------------------------------------------------

@bot.message_handler(commands=['start'])
def send_welcome(message):
    send_welcome_message = WELCOME_MESSAGE
    bot.reply_to(message, send_welcome_message, parse_mode='HTML')

@bot.message_handler(commands=['premium'])
def handle_premium_command(message):
    bot.reply_to(message, PREMIUM_MESSAGE, parse_mode='HTML')

@bot.message_handler(commands=['benefits'])
def handle_benefits_command(message):
    bot.reply_to(message, PREMIUM_BENEFITS_MESSAGE, parse_mode='HTML')

@bot.message_handler(commands=['status'])
def handle_status_command(message):
    user_id = message.from_user.id
    username = f"@{message.from_user.username}" if message.from_user.username else f"ID_{message.from_user.id}"
    
    check_premium_expiry(user_id)
    scans_used, is_premium, expiry = get_user_status(user_id, username)
    scans_used = check_and_reset_daily_limit(user_id, scans_used)
    
    status_msg = f"📊 <b>User Status</b>\n"
    status_msg += "---------------------------------\n"
    
    if is_premium == 1:
        status_msg += f"👑 <b>Premium User:</b> ✅ (Expires: {expiry})\n"
        status_msg += "🚀 <b>Scans Remaining:</b> Unlimited\n"
    else:
        status_msg += f"👤 <b>Free User:</b>\n"
        remaining = max(0, FREE_SCAN_LIMIT - scans_used)
        status_msg += f"🔥 <b>Scans Remaining Today:</b> {remaining} / {FREE_SCAN_LIMIT}\n"
        if remaining == 0:
            status_msg += "⚠️ <i>Limit reached. Reset at 12:00 AM.</i>\n"
            
    bot.reply_to(message, status_msg, parse_mode='HTML')


@bot.message_handler(commands=['scan'])
@free_scan_check
def handle_scan_command(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "කරුණාකර Domain එකක් ඇතුළත් කරන්න. උදා: <code>/scan google.com</code>\n(Please enter a Domain. E.g: <code>/scan cloudflare.com</code>)", parse_mode='HTML')
            return
        
        target_domain = command_parts[1].strip()
        
        thread = threading.Thread(target=start_scan_task, args=(message, target_domain))
        thread.start()

    except Exception as e:
        bot.reply_to(message, f"Error: {e}", parse_mode='HTML')

def start_scan_task(message, target_domain):
    user_id = message.from_user.id
    _, is_premium, _ = get_user_status(user_id)
    output_results = []
    
    status_msg = bot.reply_to(message, f"🔍 <b>Scan ආරම්භ විය!</b> <b>{target_domain}</b> Subdomains සොයමින්...", parse_mode='HTML')
    
    # 1. Subdomain Discovery
    final_sni_list = fetch_subdomains(target_domain)
    
    # 2. Add Base Host & Predictive hosts
    if target_domain not in final_sni_list:
        final_sni_list.insert(0, target_domain)
        
    predictive_list = generate_ml_based_subdomains(target_domain)
    final_sni_list.extend([host for host in predictive_list if host not in final_sni_list])
    
    bot.edit_message_text(f"✅ <b>{len(final_sni_list)}</b> Hosts found. Port Scanning ආරම්භ විය...", message.chat.id, status_msg.message_id, parse_mode='HTML')
    
    # 3. Port Scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(scan_target, final_sni_list))
        
        for res in results:
            if res["status"] == "Online" and res["ports"]:
                cdn_status = "☁️ CDN/Proxy" if "cloud" in res['server'].lower() or "akamai" in res['server'].lower() else "💻 Direct/Local"
                ports_str = ", ".join(map(str, res['ports']))
                
                risk_flag = "⚠️ <b>High Risk!</b>" if any(port in res['ports'] for port in [21, 23, 3389]) else ""

                formatted_result_string = (
                    f"<b>{res['host']}</b>\n"
                    f"  IP: <code>{res['ip']}</code>\n"
                    f"  ISP: {res.get('isp', 'N/A')}\n"
                    f"  Ports: <code>{ports_str}</code>\n"
                    f"  Server: {res['server'][:25]} ({cdn_status})\n"
                    f"  {risk_flag}\n"
                )
                output_results.append(formatted_result_string)

    # 4. Output Formatting
    if not output_results:
        final_message = "🤷‍♂️ Scan complete. No open hosts found. / විවෘත Ports සහිත Hosts සොයාගත නොහැක."
        bot.edit_message_text(final_message, message.chat.id, status_msg.message_id, parse_mode='HTML')
        return

    limited_results = output_results
    if is_premium == 0 and len(output_results) > FREE_HOST_LIMIT:
        limited_results = output_results[:FREE_HOST_LIMIT]
        limit_warning = f"⚠️ **{FREE_HOST_LIMIT} hosts** පමණක් පෙන්වනු ලැබේ. සියලු hosts බැලීමට /premium ලබා ගන්න.\n"
    else:
        limit_warning = ""

    header = f"✅ <b>{target_domain}</b> Scan Results ({len(limited_results)}/{len(output_results)} Online)\n" + ("="*30) + "\n"
    footer = f"\n" + ("="*30) + "\n<i>Scan complete.</i>" + limit_warning
    
    chunks = []
    current_chunk = header
    for result_line in limited_results:
        if len(current_chunk) + len(result_line) + 500 > 4096: 
            chunks.append(current_chunk) 
            current_chunk = result_line
        else:
            current_chunk += result_line
            
    current_chunk += footer
    chunks.append(current_chunk)

    first_message = True
    for chunk in chunks:
        if first_message:
            bot.edit_message_text(chunk, message.chat.id, status_msg.message_id, parse_mode='HTML')
            first_message = False
        else:
            bot.send_message(message.chat.id, chunk, parse_mode='HTML')


# --- DNS Lookup ---
@bot.message_handler(commands=['dns'])
@free_scan_check
def handle_dns_lookup(message):
    try:
        domain = message.text.split()[1].strip()
    except IndexError:
        bot.reply_to(message, "Please enter a Domain. E.g: <code>/dns google.com</code>", parse_mode='HTML')
        return

    result_msg = f"🛰️ <b>DNS Lookup Results for {domain}</b>\n\n"
    
    record_types = ['A', 'CNAME', 'MX']
    all_results = {}

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                results = []
                for rdata in answers:
                    if rtype == 'A':
                        results.append(f"  - <code>{rdata.address}</code> (TTL: {answers.ttl}s)")
                    elif rtype == 'CNAME':
                        results.append(f"  - <code>{rdata.target}</code> (TTL: {answers.ttl}s)")
                    elif rtype == 'MX':
                        results.append(f"  - <code>{rdata.exchange}</code> (Prio: {rdata.preference})")
                
                if results:
                    all_results[rtype] = "\n".join(results)
            except dns.resolver.NoAnswer:
                all_results[rtype] = "  - No Answer"
            except dns.resolver.NXDOMAIN:
                bot.reply_to(message, f"❌ <b>Error:</b> Domain name <code>{domain}</code> does not exist.", parse_mode='HTML')
                return
            except Exception as e:
                 all_results[rtype] = f"  - Error: {e}"

        
        result_msg += "🌐 <b>A Records (IPv4):</b>\n" + all_results.get('A', "  - No A Records") + "\n\n"
        result_msg += "🔗 <b>CNAME Records:</b>\n" + all_results.get('CNAME', "  - No CNAME Records") + "\n\n"
        result_msg += "📧 <b>MX Records (Mail):</b>\n" + all_results.get('MX', "  - No MX Records") + "\n"
        
        bot.reply_to(message, result_msg, parse_mode='HTML')

    except Exception as e:
        bot.reply_to(message, f"❌ DNS Lookup Error: {e}", parse_mode='HTML')


# --- Header Analysis ---
@bot.message_handler(commands=['header'])
@free_scan_check
def handle_header_analysis(message):
    try:
        target = message.text.split()[1].strip()
        if not (target.startswith('http://') or target.startswith('https://')):
            target = f"https://{target}"
    except IndexError:
        bot.reply_to(message, "Please enter a URL/Domain. E.g: <code>/header google.com</code>", parse_mode='HTML')
        return

    header_msg = f"📊 <b>HTTP Header Analysis for {target}</b>\n\n"
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 BotAnalyzer/1.0'}
        response = requests.head(target, headers=headers, allow_redirects=True, timeout=10)
        
        header_msg += f"✅ <b>Status Code:</b> <code>{response.status_code} {response.reason}</code>\n"
        
        server = response.headers.get('Server', 'Unknown')
        content_type = response.headers.get('Content-Type', 'N/A')
        x_powered_by = response.headers.get('X-Powered-By', 'N/A')
        
        header_msg += f"💻 <b>Server Type:</b> <code>{server}</code>\n"
        header_msg += f"📄 <b>Content Type:</b> <code>{content_type.split(';')[0]}</code>\n"

        if response.status_code in [301, 302, 307]:
            header_msg += f"🔗 <b>Redirects To:</b> <code>{response.url}</code>\n"

        if x_powered_by != 'N/A':
            header_msg += f"⚡️ <b>Powered By:</b> <code>{x_powered_by}</code>\n"
        
        if 'cloudflare' in server.lower():
            header_msg += "\n☁️ <i>Cloudflare detected. Actual IP is hidden.</i>"

        bot.reply_to(message, header_msg, parse_mode='HTML')

    except requests.exceptions.Timeout:
        bot.reply_to(message, f"❌ <b>Error:</b> Request timed out.")
    except requests.exceptions.ConnectionError:
        bot.reply_to(message, f"❌ <b>Error:</b> Connection failed. Host may be offline.")
    except Exception as e:
        bot.reply_to(message, f"❌ Header Analysis Error: {e}", parse_mode='HTML')


# --- Proxy Probe ---
@bot.message_handler(commands=['probe'])
@free_scan_check
def handle_proxy_probe(message):
    try:
        parts = message.text.split()
        if len(parts) < 2 or ':' not in parts[1]:
            raise IndexError

        host_port = parts[1].strip().split(':')
        host = host_port[0]
        port = int(host_port[1])
        
        if port <= 0 or port > 65535:
            raise ValueError

    except (IndexError, ValueError):
        bot.reply_to(message, "Please enter in Host:Port format. E.g: <code>/probe api.domain.com:4444</code>", parse_mode='HTML')
        return

    probe_msg = f"🔗 <b>Proxy Probe (Port Check) for {host}:{port}</b>\n\n"
    
    try:
        ip = socket.gethostbyname(host)
        probe_msg += f"🌐 <b>IP Address:</b> <code>{ip}</code>\n"
        probe_msg += f"---------------------------------------\n"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            probe_msg += f"✅ <b>Status:</b> <b>Port {port} is OPEN</b> (විවෘතයි)\n"
            
            if port in [80, 8080]:
                probe_msg += "💡 <b>Type:</b> HTTP / Web Proxy Port"
            elif port in [443, 8443, 2053, 2083, 4444]:
                probe_msg += "💡 <b>Type:</b> SSL/TLS / Secure Tunnel Port"
            else:
                probe_msg += "💡 <b>Type:</b> Possible VPN/Other Service Port"
        else:
            probe_msg += f"❌ <b>Status:</b> <b>Port {port} is CLOSED</b> (වසා ඇත)\n"
            probe_msg += f"💡 <b>Note:</b> Connection Refused or Timed Out."

        sock.close()
        bot.reply_to(message, probe_msg, parse_mode='HTML')

    except socket.gaierror:
        bot.reply_to(message, f"❌ <b>Error:</b> Domain name <code>{host}</code> not resolved.", parse_mode='HTML')
    except Exception as e:
        bot.reply_to(message, f"❌ Probe Error: {e}", parse_mode='HTML')


# ----------------------------------------------------
# --- 6. PREMIUM COMMAND HANDLERS ---
# ----------------------------------------------------

# --- ML SNI Scan (/ml_sni_scan) ---
@bot.message_handler(commands=['ml_sni_scan'])
@premium_required
def handle_ml_scan_command(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "Please enter a Domain. E.g: <code>/ml_sni_scan zoom.us</code>", parse_mode='HTML')
            return
        
        target_domain = command_parts[1].strip()
        
        thread = threading.Thread(target=start_ml_scan_task, args=(message, target_domain))
        thread.start()

    except Exception as e:
        bot.reply_to(message, f"Error: {e}", parse_mode='HTML')

def start_ml_scan_task(message, target_domain):
    user_id = message.from_user.id
    output_results = []
    
    status_msg = bot.reply_to(message, f"🧠 <b>ML Scan Started!</b> Searching Zero-Day Patterns for <b>{target_domain}</b>...", parse_mode='HTML')
    
    final_sni_list = generate_ml_based_subdomains(target_domain)
    
    bot.edit_message_text(f"✅ <b>{len(final_sni_list)}</b> ML Hosts found. Checking ports...", message.chat.id, status_msg.message_id, parse_mode='HTML')
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(scan_target, final_sni_list))
        
        for res in results:
            if res["status"] == "Online" and res["ports"]:
                cdn_status = "☁️ CDN/Proxy" if "cloud" in res['server'].lower() or "akamai" in res['server'].lower() else "💻 Direct/Local"
                ports_str = ", ".join(map(str, res['ports']))
                
                risk_flag = "⚠️ <b>High Risk!</b>" if any(port in res['ports'] for port in [21, 23, 3389]) else ""

                formatted_result_string = (
                    f"<b>{res['host']}</b>\n"
                    f"  IP: <code>{res['ip']}</code>\n"
                    f"  ISP: {res.get('isp', 'N/A')}\n"
                    f"  Ports: <code>{ports_str}</code>\n"
                    f"  Server: {res['server'][:25]} ({cdn_status})\n"
                    f"  {risk_flag}\n"
                )
                output_results.append(formatted_result_string)

    if not output_results:
        final_message = "🤷‍♂️ ML Scan complete. No unique open hosts found."
        bot.edit_message_text(final_message, message.chat.id, status_msg.message_id, parse_mode='HTML')
        return

    header = f"🔥 <b>{target_domain}</b> ML Hosts ({len(output_results)}/{len(final_sni_list)} Online)\n" + ("="*30) + "\n"
    footer = "\n" + ("="*30) + "\n<i>ML Scan complete.</i>"
    
    chunks = []
    current_chunk = header
    for result_line in output_results:
        if len(current_chunk) + len(result_line) + 500 > 4096: 
            chunks.append(current_chunk) 
            current_chunk = result_line
        else:
            current_chunk += result_line
            
    current_chunk += footer
    chunks.append(current_chunk)

    first_message = True
    for chunk in chunks:
        if first_message:
            bot.edit_message_text(chunk, message.chat.id, status_msg.message_id, parse_mode='HTML')
            first_message = False
        else:
            bot.send_message(message.chat.id, chunk, parse_mode='HTML')


# --- Live Latency Check (/latency) ---
@bot.message_handler(commands=['latency'])
@premium_required
def handle_latency_command(message):
    try:
        domain = message.text.split()[1].strip()
    except IndexError:
        bot.reply_to(message, "Please enter a Host. E.g: <code>/latency google.com</code>", parse_mode='HTML')
        return

    thread = threading.Thread(target=start_latency_task, args=(message, domain))
    thread.start()

def get_latency(ip):
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, 443)) 
        end_time = time.time()
        latency = int((end_time - start_time) * 1000)
        sock.close()
        return f"✅ {latency}ms"
    except Exception:
        return "❌ Failed/Timed Out"

def start_latency_task(message, domain):
    try:
        status_msg = bot.reply_to(message, f"🌏 <b>Live Latency Check</b>: Checking <b>{domain}</b> globally...", parse_mode='HTML')
        
        target_ip = socket.gethostbyname(domain)
        
        latency_msg = f"⏱️ <b>Geo-Latency Results for {domain}</b>\nIP: <code>{target_ip}</code>\n"
        latency_msg += "---------------------------------------\n"
        
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(LATENCY_CHECK_NODES)) as executor:
            future_to_node = {executor.submit(get_latency, target_ip): node for node in LATENCY_CHECK_NODES}
            for future in concurrent.futures.as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    results[node] = future.result()
                except Exception as exc:
                    results[node] = f"❌ Error: {exc}"
        
        for node in sorted(LATENCY_CHECK_NODES.keys()):
            latency_msg += f" • {node}: {results.get(node, '❌ Not Checked')}\n"
        
        latency_msg += "\n💡 <i>(Lower MS is better)</i>"
        
        bot.edit_message_text(latency_msg, message.chat.id, status_msg.message_id, parse_mode='HTML')

    except socket.gaierror:
        bot.edit_message_text(f"❌ <b>Error:</b> Domain name <code>{domain}</code> not resolved.", message.chat.id, status_msg.message_id, parse_mode='HTML')
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Latency Check Error: {e}", parse_mode='HTML')


# --- Proactive Monitoring (/watch) ---
@bot.message_handler(commands=['watch'])
@premium_required
def handle_watch_command(message):
    try:
        domain = message.text.split()[1].strip()
    except IndexError:
        bot.reply_to(message, "Please enter a Host. E.g: <code>/watch example.com</code>", parse_mode='HTML')
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM watchlist WHERE user_id=? AND domain=?", (message.from_user.id, domain))
    if cursor.fetchone():
        bot.reply_to(message, f"🔔 <b>Already Watching:</b> <code>{domain}</code>.", parse_mode='HTML')
        conn.close()
        return

    try:
        initial_ip = socket.gethostbyname(domain)
        initial_status = requests.head(f"https://{domain}", timeout=5).status_code
        
        cursor.execute("""
            INSERT INTO watchlist (user_id, domain, last_check_ip, last_check_status) 
            VALUES (?, ?, ?, ?)
        """, (message.from_user.id, domain, initial_ip, str(initial_status)))
        conn.commit()
        
        bot.reply_to(message, f"✅ <b>Monitoring Started!</b> You will be notified of any changes to <code>{domain}</code>.", parse_mode='HTML')

    except socket.gaierror:
        bot.reply_to(message, f"❌ <b>Error:</b> Domain name <code>{domain}</code> not resolved.", parse_mode='HTML')
    except Exception as e:
        bot.reply_to(message, f"❌ Monitoring Setup Error: {e}", parse_mode='HTML')
    finally:
        conn.close()

# ----------------------------------------------------
# --- 7. ADMIN HANDLERS (Basic Grant/Revoke/Broadcast Placeholder) ---
# ----------------------------------------------------

# Note: Full Admin handlers (grant/revoke/broadcast) are complex. 
# They must be added here, ensuring they only respond to ADMIN_ID. 
# Example Admin check structure:

@bot.message_handler(commands=['admin'])
def handle_admin_command(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "🚫 Admin Access Denied.")
        return
    
    admin_msg = "👑 <b>Admin Dashboard</b>\n\n"
    admin_msg += "Commands:\n"
    admin_msg += "<code>/grant &lt;username/ID&gt; &lt;days&gt;</code> - Grant Premium\n"
    admin_msg += "<code>/revoke &lt;username/ID&gt;</code> - Revoke Premium\n"
    admin_msg += "<code>/broadcast &lt;message&gt;</code> - Send message to all users"
    
    bot.reply_to(message, admin_msg, parse_mode='HTML')

# ----------------------------------------------------
# --- 8. WATCHLIST CHECKER (BACKGROUND THREAD) ---
# ----------------------------------------------------

def watchlist_checker():
    while True:
        time.sleep(1800) # Check every 30 minutes
        print("Running Watchlist Check...")
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id, domain, last_check_ip, last_check_status FROM watchlist")
        watched_domains = cursor.fetchall()

        for user_id, domain, old_ip, old_status in watched_domains:
            # Check for premium status before notifying
            _, is_premium, _ = get_user_status(user_id)
            if is_premium == 0:
                # Remove expired watcher
                cursor.execute("DELETE FROM watchlist WHERE user_id=? AND domain=?", (user_id, domain))
                conn.commit()
                continue 

            try:
                new_ip = socket.gethostbyname(domain)
                new_status = requests.head(f"https://{domain}", timeout=5).status_code
                
                changed = False
                alert_message = f"🚨 <b>Premium Alert: Change Detected on {domain}!</b>\n\n"
                
                if new_ip != old_ip:
                    alert_message += f"🌐 <b>IP Changed:</b> <code>{old_ip}</code> ➡️ <code>{new_ip}</code>\n"
                    changed = True
                
                if str(new_status) != old_status:
                    alert_message += f"📊 <b>Status Code Changed:</b> <code>{old_status}</code> ➡️ <code>{new_status}</code>\n"
                    changed = True
                
                if changed:
                    bot.send_message(user_id, alert_message, parse_mode='HTML')
                    
                    cursor.execute("""
                        UPDATE watchlist SET last_check_ip=?, last_check_status=? 
                        WHERE user_id=? AND domain=?
                    """, (new_ip, str(new_status), user_id, domain))
                    conn.commit()

            except Exception as e:
                print(f"Watchlist check failed for {domain}: {e}")
                if "failed to resolve" in str(e).lower():
                    bot.send_message(user_id, f"❌ <b>Premium Alert: Host Offline!</b> <code>{domain}</code> is unreachable.", parse_mode='HTML')
                    
        conn.close()


# ----------------------------------------------------
# --- 9. START BOT AND THREADS ---
# ----------------------------------------------------

if __name__ == '__main__':
    setup_db() 
    
    monitor_thread = threading.Thread(target=watchlist_checker, daemon=True)
    monitor_thread.start()
    
    print("Telegram Bot Started...")
    try:
        # Set official bot commands (All English)
        bot.set_my_commands([
            BotCommand("scan", "Domain Scan (Free/Premium)"),
            BotCommand("dns", "DNS Lookup (Free)"),
            BotCommand("header", "Header Analysis (Free)"),
            BotCommand("probe", "Port/Proxy Probe (Free)"),
            BotCommand("ml_sni_scan", "ML SNI Hunter (Premium)"),
            BotCommand("latency", "Global Latency Check (Premium)"),
            BotCommand("watch", "Proactive Monitoring (Premium)"),
            BotCommand("status", "Daily Limit Status"),
            BotCommand("premium", "Get Premium Access"),
            BotCommand("benefits", "Premium Benefits"),
            BotCommand("admin", "Admin Dashboard (ADMIN)"), # Added admin command to list
            BotCommand("start", "Restart Bot") 
        ])
        bot.polling(none_stop=True)
    except Exception as e:
        print(f"Bot startup error: {e}")
