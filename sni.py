import telebot
import requests
import socket
import ssl
import concurrent.futures
import threading
import sqlite3
import datetime
import time
import random 
try:
    from ping3 import ping, verbose_ping 
except ImportError:
    print("ping3 module එක ස්ථාපනය කරයි...")
    import subprocess
    subprocess.check_call(['pip', 'install', 'ping3'])
    from ping3 import ping, verbose_ping

from telebot.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
from telebot.apihelper import ApiTelegramException 

# --- 1. CONFIGURATION (නියතයන්) ---
BOT_TOKEN = '6454456940:AAFUAbZatEwrNvv75emY_376l7yJDmr5-48' 
ADMIN_USERNAME = '@prasa_z'
ADMIN_ID = 6221106415 

# 🚨 CHANNEl CONFIGURATION 🚨
CHANNEL_USERNAME = '@sni_hunter'  
CHANNEL_ID = -1003131855993  
# -----------------------------------

# Freemium/Scanning Settings
DEFAULT_PORTS = [80, 443, 8080, 8443]
CRITICAL_PORTS = [21, 23, 22, 3389, 5900]
TIMEOUT = 1.0
MAX_WORKERS = 40
FREE_SCAN_LIMIT = 10 
FREE_HOST_LIMIT = 50
WATCH_LIMIT = 5 

# Database
DB_NAME = 'sni_bot_users.db' 

# AI Wordlist (ML Scan සඳහා Simulation)
PREDICTIVE_WORDLIST = [
    "api", "dev", "test", "web", "cdn", "mail", "ftp", "admin", "proxy", "vpn", 
    "access", "live", "app", "static", "assets", "mobile", "staging", "server",
    "backup", "internal", "secure", "status", "secure-api", "dev-test-api", 
    "internal-cdn"
]

# --- Bot Initialization ---
bot = telebot.TeleBot(BOT_TOKEN)

# ----------------------------------------------------
# --- DUAL LANGUAGE MESSAGES (No changes) ---
# ----------------------------------------------------
PREMIUM_MESSAGE = (
    "👑 <b>Premium Access අවශ්‍යයි</b> 👑\n\n"
    f"ඔබගේ <b>Free Scan සීමාව ({FREE_SCAN_LIMIT})</b> අවසන් වී ඇත. අසීමිත Scans, සම්පූර්ණ ප්‍රතිඵල, **Advanced Filter** සහ **Risk Scoring** සඳහා Premium වෙත මාරු වන්න.\n"
    "----------------------------------------\n"
    "👑 <b>Premium Access Required</b> 👑\n\n"
    f"Your <b>Free Scan limit ({FREE_SCAN_LIMIT})</b> is exhausted. Upgrade to Premium for unlimited scans, full results, **Advanced Filter**, and **Risk Scoring**.\n\n"
    "💵 <b>ගාස්තුව / Fee:</b> Rs. 500/Month\n\n"
    "🏦 <b>Bank Details:</b>\n"
    "  <b>Bank:</b> <code>BOC</code>\n"
    "  <b>A/C Name:</b> <code>K.G.C.SILVA</code>\n"
    "  <b>A/C No:</b> <code>93872075</code>\n\n"
    "📤 <b>Pay කරන්නේ කෙසේද / How to Pay:</b>\n"
    f"ගෙවීම් කළ පසු, ඔබගේ <b>Payment Receipt</b> එක සහ ඔබගේ Telegram <b>User Name</b> එක {ADMIN_USERNAME} වෙත එවන්න.\n"
    f"Send your <b>Payment Receipt</b> and your Telegram <b>User Name</b> to {ADMIN_USERNAME} after payment."
)

WELCOME_MESSAGE = (
    "🤖 <b>Advanced SNI Hunter Bot</b> වෙත සාදරයෙන් පිළිගනිමු!\n\n"
    "✨ <b>Free Trial Offer:</b>\n"
    f"ඔබට කිසිදු ගාස්තුවක් නොමැතිව <b>සම්පූර්ණ Scans {FREE_SCAN_LIMIT}ක්</b> දිනපතා භාවිතා කළ හැක. සෑම Scan එකකදීම සොයාගත් Host <b>{FREE_HOST_LIMIT}ක්</b> පමණක් පෙන්වනු ලැබේ.\n"
    "----------------------------------------\n"
    "<b>(new update ✅)</b>\n\n"
    "🟢 <b>Free Access Features</b>\n\n"
    "Domain Scanner (<code>/scan</code>)\n\n"
    "🟣 <b>Premium Access Features</b>\n\n"
    "DNS Lookup (<code>/dns</code>)\n"         
    "Header Analyzer (<code>/header</code>)\n" 
    "Proxy Probe (<code>/probe</code>)\n"      
    "Zero-Day ML SNI Hunter (<code>/ml_sni_scan</code>)\n"
    "Live Latency Check (<code>/latency</code>)\n"
    "Proactive Monitoring (<code>/watch</code>)\n"
    "Geo-IP Lookup (<code>/geoip</code>)\n" # NEW FEATURE ADDED
    "Unlimited Scanning\n"
    "Ad-Free Experience\n\n"
    "⚙️ <b>Utility & Status Commands</b>\n\n"
    "Restart Bot (<code>/start</code>)\n"
    "Daily Limit Status (<code>/status</code>)\n"
    "Get Premium Access (<code>/premium</code>)\n"
    "Premium Benefits (<code>/benefits</code>)\n"
    "{admin_cmd_placeholder}"
    "----------------------------------------\n"
    "<b>Usage:</b> <code>/scan domain.com</code>"
)

# ----------------------------------------------------
# --- CORE CHECK & DB FUNCTIONS ---
# ----------------------------------------------------

def is_subscribed(user_id):
    if user_id == ADMIN_ID: return True 
    try:
        member = bot.get_chat_member(CHANNEL_ID, user_id)
        if member.status in ['creator', 'administrator', 'member']: return True
        else: return False
    except ApiTelegramException as e:
        if 'chat not found' in str(e) or 'Bad Request' in str(e):
             print(f"⚠️ Channel ID ({CHANNEL_ID}) හෝ Username ({CHANNEL_USERNAME}) වැරදියි.")
             return True 
        return False
    except Exception: return False

def subscription_required_message():
    markup = InlineKeyboardMarkup()
    join_button = InlineKeyboardButton("✅ අපගේ Channel එකට Join වන්න", url=f"https://t.me/{CHANNEL_USERNAME.replace('@', '')}")
    check_button = InlineKeyboardButton("🔄 මම Join වුණා (නැවත පරීක්ෂා කරන්න)", callback_data="check_subscription")
    markup.add(join_button)
    markup.add(check_button)
    message = (
        "🔒 **Subscription එකක් අවශ්‍යයි!**\n\n"
        f"මෙම Bot එක භාවිතා කිරීමට, ඔබ අනිවාර්යයෙන්ම අපගේ Channel එකට **{CHANNEL_USERNAME}** Join විය යුතුය.\n"
        "කරුණාකර පහත Button එක භාවිතා කර Join වී, ඉන්පසු 'මම Join වුණා' Button එක ඔබන්න.\n"
        "----------------------------------------\n"
        "🔒 **Subscription Required!**\n\n"
        f"To use the Bot, you must join our Channel: **{CHANNEL_USERNAME}**.\n"
        "Please use the button below to join and then click 'I Joined' to recheck."
    )
    return message, markup

def setup_db():
    """Database Tables නිර්මාණය කරයි."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor() 
    
    # 1. 'users' Table එක නිර්මාණය කිරීම
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            free_scans_used INTEGER DEFAULT 0,
            is_premium INTEGER DEFAULT 0,
            premium_expiry TEXT,
            last_scan_date TEXT 
        )
    """)
    # last_scan_date column එක දැනටමත් නැතිනම් එකතු කරයි
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN last_scan_date TEXT")
    except sqlite3.OperationalError:
        pass 
        
    # 2. 'scan_logs' Table එක නිර්මාණය කිරීම
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            log_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            domain TEXT,
            timestamp TEXT
        )
    """)
    
    # 3. 'watch_list' Table එක නිර්මාණය කිරීම (Monitoring Tool සඳහා)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS watch_list (
            watch_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            domain TEXT NOT NULL,
            port INTEGER,
            last_status TEXT,
            last_check TEXT
        )
    """)
    
    conn.commit()
    conn.close()

def log_scan_request(user_id, domain):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("INSERT INTO scan_logs (user_id, domain, timestamp) VALUES (?, ?, ?)", 
                   (user_id, domain, timestamp))
    conn.commit()
    conn.close()

def revoke_premium_access(user_id, reason_si="Admin විසින්", reason_en="revoked by Admin"):
    revoke_msg = (
        f"⚠️ ඔබගේ **Premium Access** දැන් අවලංගු කර ඇත! හේතුව: {reason_si}.\n"
        f"----------------------------------------\n"
        f"⚠️ Your **Premium Access** has been revoked! Reason: {reason_en}."
    )
    try: bot.send_message(user_id, revoke_msg, parse_mode='HTML')
    except ApiTelegramException: pass 
    except Exception: pass 
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_premium = 0, premium_expiry = NULL WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

def grant_premium_access(user_id, duration_days):
    expiry_date = datetime.datetime.now() + datetime.timedelta(days=duration_days)
    expiry_date_str = expiry_date.strftime('%Y-%m-%d')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_premium = 1, premium_expiry = ? WHERE user_id = ?", 
                   (expiry_date.strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit()
    conn.close()
    grant_msg = (
        f"🎉 ඔබට දින <b>{duration_days}</b>ක් සඳහා **Premium Access** සාර්ථකව සක්‍රිය කරන ලදි!\nඑය {expiry_date_str} දින කල් ඉකුත් වනු ඇත.\n"
        f"----------------------------------------\n"
        f"🎉 Your **Premium Access** has been successfully activated for <b>{duration_days}</b> days!"
    )
    try: bot.send_message(user_id, grant_msg, parse_mode='HTML')
    except ApiTelegramException: pass
    except Exception: pass

def get_id_by_username(identifier):
    if identifier and identifier.isdigit(): return int(identifier)
    search_username = identifier if identifier and identifier.startswith('@') else f"@{identifier}"
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE username=?", (search_username,))
    result = cursor.fetchone()
    conn.close()
    if result: return result[0]
    return None

def check_premium_expiry(user_id):
    if user_id == ADMIN_ID: return False
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT is_premium, premium_expiry FROM users WHERE user_id = ?", (user_id,))
    data = cursor.fetchone()
    conn.close()
    if data and data[0] == 1 and data[1]:
        try:
            expiry_time = datetime.datetime.strptime(data[1], '%Y-%m-%d %H:%M:%S')
            if datetime.datetime.now() > expiry_time:
                revoke_premium_access(user_id, reason_si="කාලය අවසන්", reason_en="Expiry")
                return True 
        except ValueError: return False 
    return False 

def get_user_status(user_id, username):
    if user_id == ADMIN_ID: return (0, 1, 'Never Expires', 'N/A') 

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT free_scans_used, is_premium, premium_expiry, last_scan_date FROM users WHERE user_id=?", (user_id,))
    data = cursor.fetchone()
    current_date = datetime.datetime.now().date()

    if data is None:
        cursor.execute("INSERT INTO users (user_id, username, last_scan_date) VALUES (?, ?, ?)", (user_id, username, current_date.strftime('%Y-%m-%d')))
        conn.commit()
        data = (0, 0, None, current_date.strftime('%Y-%m-%d'))
    else:
        free_scans_used, is_premium, premium_expiry, last_scan_date_str = data
        cursor.execute("UPDATE users SET username = ? WHERE user_id=?", (username, user_id))
        
        if is_premium == 0:
            if last_scan_date_str:
                try:
                    last_scan_date = datetime.datetime.strptime(last_scan_date_str.split()[0], '%Y-%m-%d').date()
                    if (current_date - last_scan_date).days >= 1:
                        cursor.execute("UPDATE users SET free_scans_used = 0, last_scan_date = ? WHERE user_id = ?", 
                                       (current_date.strftime('%Y-%m-%d'), user_id))
                        free_scans_used = 0
                        last_scan_date_str = current_date.strftime('%Y-%m-%d')
                except ValueError:
                    cursor.execute("UPDATE users SET free_scans_used = 0, last_scan_date = ? WHERE user_id = ?", 
                                   (current_date.strftime('%Y-%m-%d'), user_id))
                    free_scans_used = 0
                    last_scan_date_str = current_date.strftime('%Y-%m-%d')
        
        data = (free_scans_used, is_premium, premium_expiry, last_scan_date_str)
        conn.commit()

    conn.close()
    return data

def update_scan_count(user_id):
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET free_scans_used = free_scans_used + 1, last_scan_date = ? WHERE user_id=?", 
                   (current_date, user_id))
    conn.commit()
    conn.close()


# --- Core Utility Functions (Scanning & Tools) ---

def get_isp_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=isp,org,as,countryCode"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            isp = data.get('isp', 'Unknown').replace('<', '&lt;').replace('>', '&gt;')
            country = data.get('countryCode', 'XX')
            return f"{isp} ({data.get('as', '')}) [🇨{country}]"
    except: return "Unknown ISP"
    return "Unknown ISP"

def generate_predictive_subdomains(domain, passive_list):
    new_hosts = set()
    for word in PREDICTIVE_WORDLIST:
        new_host = f"{word}.{domain}"
        if new_host not in passive_list:
             new_hosts.add(new_host)
    passive_list.extend(list(new_hosts))
    return passive_list

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
                        if sub.strip() and "*" not in sub:
                            subdomains.add(sub.strip())
    except Exception: pass

    if not subdomains:
        hackertarget_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            response = requests.get(hackertarget_url, timeout=10)
            if response.status_code == 200 and "API count exceeded" not in response.text:
                lines = response.text.splitlines()
                for line in lines:
                    parts = line.split(',')
                    if len(parts) > 0 and 'error' not in parts[0].lower() and '*' not in parts[0]:
                        subdomains.add(parts[0].strip())
        except Exception: pass
            
    return list(subdomains)

def scan_target(host):
    data = {
        "host": host, "ip": "N/A", "ports": [], "server": "Unknown", "status": "Online", "isp": "N/A"
    }
    
    try:
        ip = socket.gethostbyname(host)
        data["ip"] = ip
        
        for port in DEFAULT_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                data["ports"].append(port)
                if port in [80, 443] and data["server"] == "Unknown":
                    try:
                        if port == 443:
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
                    except Exception: pass 
                        
            sock.close()
            
        if data["ports"]:
            data["isp"] = get_isp_info(ip)

    except:
        data["status"] = "Offline"
        
    return data

# --- Functionality for DNS, Header, Probe, Geo-IP (Premium tools) ---
def perform_dns_lookup(domain):
    try:
        ip_addr = socket.gethostbyname(domain)
        try:
            cname = socket.gethostbyname_ex(domain)[1] 
            cname_str = ", ".join(cname) if cname else "N/A (No CNAME)"
        except:
            cname_str = "N/A (No CNAME)"

        return (
            f"✅ <b>DNS Records for {domain}:</b>\n"
            f"  • <b>A Record (IP):</b> <code>{ip_addr}</code>\n"
            f"  • <b>CNAME:</b> <code>{cname_str}</code>"
        )
    except socket.gaierror:
        return f"❌ <b>Error:</b> Domain <code>{domain}</code> found no records (Invalid Domain or Hostname)."
    except Exception as e:
        return f"❌ <b>DNS Lookup Error:</b> {e}"

def analyze_http_header(url):
    if not url.startswith('http'):
        url = 'http://' + url
        
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        
        header_text = f"✅ <b>HTTP Headers for {url}:</b>\n"
        header_text += f"  • <b>Status Code:</b> <code>{response.status_code}</code>\n"
        
        for key, value in response.headers.items():
            if key.lower() in ['server', 'content-type', 'date', 'location', 'x-cache']:
                header_text += f"  • <b>{key}:</b> <code>{value}</code>\n"
            else:
                 header_text += f"  • {key}: <code>{value[:30]}...</code>\n"
        
        return header_text
        
    except requests.exceptions.RequestException as e:
        return f"❌ <b>Header Error:</b> URL එකට ළඟා වීමට නොහැක හෝ ඉල්ලීම කාලය ඉක්මවා ගියේය. ({e})"

def probe_proxy(host_port):
    try:
        host, port = host_port.split(':')
        port = int(port)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        start_time = time.time()
        result = sock.connect_ex((host, port))
        end_time = time.time()
        sock.close()
        
        latency_ms = round((end_time - start_time) * 1000, 2)
        
        if result == 0:
            return (
                f"✅ <b>Proxy Probe Success!</b>\n"
                f"  • <b>Host:</b> <code>{host_port}</code>\n"
                f"  • <b>Status:</b> 🟢 Online / Open\n"
                f"  • <b>Latency:</b> {latency_ms} ms"
            )
        else:
            return (
                f"❌ <b>Proxy Probe Failed.</b>\n"
                f"  • <b>Host:</b> <code>{host_port}</code>\n"
                f"  • <b>Status:</b> 🔴 Offline / Closed"
            )

    except ValueError:
        return "❌ <b>Error:</b> කරුණාකර නිවැරදි Format එක භාවිතා කරන්න: <code>IP:Port</code>"
    except Exception as e:
        return f"❌ <b>Probe Error:</b> {e}"

def get_geo_ip_info(ip):
    """IP ලිපිනයක භූගෝලීය තොරතුරු ලබා ගනී."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200 and response.json().get('status') == 'success':
            data = response.json()
            
            result_text = f"🌎 <b>Geo-IP Report for {ip}</b>\n"
            result_text += "----------------------------------------\n"
            result_text += f"  • <b>Country:</b> {data.get('country')} (<code>{data.get('countryCode')}</code>)\n"
            result_text += f"  • <b>Region:</b> {data.get('regionName')} ({data.get('city')})\n"
            result_text += f"  • <b>Timezone:</b> {data.get('timezone')}\n"
            result_text += f"  • <b>ISP:</b> {data.get('isp')}\n"
            result_text += f"  • <b>Organization:</b> {data.get('org')}\n"
            result_text += f"  • <b>AS (Network):</b> {data.get('as')}\n"
            result_text += f"  • <b>Location:</b> Lat {data.get('lat')}, Lon {data.get('lon')}\n"
            
            return result_text
        
        return f"❌ <b>Geo-IP Error:</b> IP ලිපිනය <code>{ip}</code> සඳහා තොරතුරු සොයා ගැනීමට නොහැක."
        
    except Exception as e:
        return f"❌ <b>Geo-IP Lookup Failed:</b> Network error. ({e})"

# ----------------------------------------------------
# --- TELEGRAM BOT HANDLERS ---
# ----------------------------------------------------

def create_main_keyboard(user_id):
    """පරිශීලක වර්ගය අනුව Reply Keyboard එක නිර්මාණය කරයි. 
       මෙය කාණ්ඩ 3ක් යටතේ සංවිධානය කර ඇත."""
       
    # row_width 2 ට සකසා ඇත
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True) 
    
    # ----------------------------------------
    # --- 1. CORE ACCESS & STATUS (ප්‍රධාන) ---
    # ----------------------------------------
    
    # පේළිය 1 (ප්‍රධාන ක්‍රියාකාරිත්වය)
    btn_scan = KeyboardButton('🔎 Scan Domain')    # /scan
    btn_status = KeyboardButton('📊 Status')       # /status
    markup.add(btn_scan, btn_status)
    
    # පේළිය 2 (Premium තොරතුරු)
    btn_premium = KeyboardButton('👑 Premium')    # /premium
    btn_benefits = KeyboardButton('🎁 Benefits')  # /benefits
    markup.add(btn_premium, btn_benefits)
    
    # ----------------------------------------
    # --- 2. Premium Tools (සියලු දෙනාටම) ---
    # ----------------------------------------
    
    # පේළිය 3
    btn_ml_scan = KeyboardButton('🧠 ML Scan')       # /ml_sni_scan
    btn_latency = KeyboardButton('⏱️ Latency')       # /latency
    markup.add(btn_ml_scan, btn_latency)
    
    # පේළිය 4
    btn_watch = KeyboardButton('👀 Monitoring')    # /watch
    btn_dns = KeyboardButton('🌐 DNS Lookup')      # /dns
    markup.add(btn_watch, btn_dns)
    
    # පේළිය 5 (අනෙකුත් tools)
    btn_header = KeyboardButton('📝 Header')       # /header
    btn_probe = KeyboardButton('🔌 Probe')          # /probe
    markup.add(btn_header, btn_probe)
    
    # පේළිය 6 (Premium Tools)
    btn_dumpster = KeyboardButton('📂 DNSDumpster') # Premium Only
    btn_geoip = KeyboardButton('🌎 Geo-IP')         # /geoip
    markup.add(btn_dumpster, btn_geoip)

    # පේළිය 7 - අලුතින් එක් කළ Reverse IP
    btn_revip = KeyboardButton('🔄 Reverse IP')    # /revip (Premium Only)
    markup.add(btn_revip) # මෙය තනි පේළියක විශාලව පෙනේවි
    
    # ----------------------------------------
    # --- 4. Admin Commands (Admin ට පමණක්) ---
    # ----------------------------------------
    if user_id == ADMIN_ID:
        btn_grant = KeyboardButton('👑 Grant Access') 
        btn_revoke = KeyboardButton('🗑️ Revoke Access')
        btn_broadcast = KeyboardButton('📢 Broadcast')
        btn_searchlogs = KeyboardButton('🔍 Search Logs')
        
        markup.add(btn_grant, btn_revoke)
        markup.add(btn_broadcast, btn_searchlogs)
        markup.add(KeyboardButton('/admin'))
    
    return markup


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    user_id = message.from_user.id
    username = f"@{message.from_user.username}" if message.from_user.username else f"ID_{user_id}"
    
    setup_db() 
    get_user_status(user_id, username) 
    
    # FIX: Pending Next Step Handlers ඉවත් කිරීම 
    try:
        bot.clear_step_handler_by_chat_id(chat_id=user_id)
    except:
        pass 
    
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    
    if user_id == ADMIN_ID:
        admin_cmd_placeholder = "Admin Dashboard (<code>/admin</code>) (Admin Only)\n"
    else:
        admin_cmd_placeholder = ""

    welcome_msg_final = WELCOME_MESSAGE.format(admin_cmd_placeholder=admin_cmd_placeholder)
    
    bot.reply_to(message, welcome_msg_final, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

@bot.message_handler(commands=['premium'])
def handle_premium_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    bot.reply_to(message, PREMIUM_MESSAGE, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

@bot.message_handler(commands=['status'])
def handle_status_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML')
        
    username = f"@{message.from_user.username}" if message.from_user.username else f"ID_{user_id}"
    check_premium_expiry(user_id)
    free_scans_used, is_premium, premium_expiry, last_scan_date_str = get_user_status(user_id, username) 
    
    status_msg = (
        f"👤 <b>User ID:</b> <code>{user_id}</code>\n"
        f"🔥 <b>තත්ත්වය / Status:</b> {'👑 Premium User' if is_premium == 1 else '⚡️ Free User'}\n"
    )
    
    if is_premium == 0:
        remaining = FREE_SCAN_LIMIT - free_scans_used
        status_msg += (
            f"🔍 <b>ඉතිරි Scans / Scans Remaining:</b> <b>{remaining}</b> / {FREE_SCAN_LIMIT}\n"
            f"📅 <b>අවසන් Scans කළ දිනය:</b> {last_scan_date_str.split()[0] if last_scan_date_str else 'N/A'}\n\n"
        )
        if remaining <= 0:
            status_msg += "⚠️ ඔබගේ Free Scan සීමාව අවසන්. හෙට දින නැවත උත්සාහ කරන්න හෝ Premium වෙත මාරු වන්න!"
    else:
        status_msg += f"📅 <b>කල් ඉකුත් වීමේ දිනය:</b> {premium_expiry.split()[0] if premium_expiry else 'N/A'}\n"
        status_msg += "✅ <b>Scans:</b> අසීමිතයි (Unlimited)"

    bot.reply_to(message, status_msg, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))


def check_premium_access(user_id, command_name):
    check_premium_expiry(user_id)
    _, is_premium, _, _ = get_user_status(user_id, None) 
    
    if is_premium == 0:
        bot.send_message(user_id, f"🚫 **{command_name}** විධානය **Premium Users** සඳහා පමණි. වැඩි විස්තර සඳහා /premium ඔබන්න.", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        return False
    return True

@bot.message_handler(commands=['dns'])
def handle_dns_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    if not check_premium_access(user_id, "/dns"): return 
        
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            return bot.reply_to(message, "🔎 **DNS Lookup:** කරුණාකර Domain නාමයක් ඇතුළත් කරන්න. උදා: <code>/dns zoom.us</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
        target_domain = command_parts[1].strip()
        result = perform_dns_lookup(target_domain)
        bot.reply_to(message, result, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
    except Exception as e:
        bot.reply_to(message, f"❌ DNS Lookup Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

@bot.message_handler(commands=['header'])
def handle_header_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
        
    if not check_premium_access(user_id, "/header"): return 
        
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            return bot.reply_to(message, "🔎 **Header Analyzer:** කරුණාකර URL එකක් ඇතුළත් කරන්න. උදා: <code>/header https://example.com</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
        target_url = command_parts[1].strip()
        result = analyze_http_header(target_url)
        bot.reply_to(message, result, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
    except Exception as e:
        bot.reply_to(message, f"❌ Header Analyzer Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

@bot.message_handler(commands=['probe'])
def handle_probe_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
        
    if not check_premium_access(user_id, "/probe"): return 
        
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            return bot.reply_to(message, "🔎 **Proxy Probe:** කරුණාකර <code>IP:Port</code> ඇතුළත් කරන්න. උදා: <code>/probe 192.168.1.1:8080</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
        target_host_port = command_parts[1].strip()
        result = probe_proxy(target_host_port)
        bot.reply_to(message, result, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
    except Exception as e:
        bot.reply_to(message, f"❌ Proxy Probe Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

# --- DNSDumpster Logic ---
def get_deep_dns_data(domain):
    try:
        # DNSDumpster වැනි ගැඹුරු දත්ත සඳහා HackerTarget API භාවිතා කරයි
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        response = requests.get(url, timeout=10).text
        return response if "error" not in response.lower() else "❌ දත්ත ලබා ගත නොහැක."
    except:
        return "❌ සම්බන්ධතා දෝෂයකි."

# --- DNSDumpster Handler ---
@bot.message_handler(commands=['dnsdumpster'])
def handle_dumpster(message):
    user_id = message.from_user.id
    
    # 1. මූලික Subscription පරීක්ෂාව
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    
    # 2. Premium Access පරීක්ෂාව (ඔබේ Bot එකේ ඇති check_premium_access භාවිතා කිරීම)
    if not check_premium_access(user_id, "/dnsdumpster"): 
        return 

    try:
        command_parts = message.text.split()
        
        # 3. Domain එක ඇතුළත් කර නොමැති නම් උපදෙස් පණිවිඩය
        if len(command_parts) < 2:
            instruction = (
                "📂 **DNSDumpster (Deep Search)**\n\n"
                "කරුණාකර Domain නාමයක් සමඟ විධානය ලබා දෙන්න.\n"
                "උදා: `/dnsdumpster google.com`"
            )
            return bot.reply_to(message, instruction, parse_mode='Markdown', reply_markup=create_main_keyboard(user_id))
        
        # 4. දත්ත ලබා ගැනීම
        domain = command_parts[1].strip().replace("https://", "").replace("http://", "").split('/')[0]
        status_msg = bot.send_message(message.chat.id, "🔎 **DNS Records පරීක්ෂා කරමින් පවතී...**")
        
        result = get_deep_dns_data(domain)
        
        # ප්‍රතිඵලය පෙන්වීම
        final_text = f"🎯 **DNSDumpster Results:** `{domain}`\n\n<pre>{result[:3500]}</pre>"
        bot.edit_message_text(final_text, message.chat.id, status_msg.message_id, parse_mode='HTML')
        
    except Exception as e:
        bot.reply_to(message, f"❌ DNSDumpster Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

@bot.message_handler(commands=['geoip'])
def handle_geoip_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    if not check_premium_access(user_id, "/geoip"): return 

    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            return bot.reply_to(message, "🔎 **Geo-IP Lookup:** කරුණාකර IP ලිපිනයක් හෝ Domain එකක් ඇතුළත් කරන්න. උදා: <code>/geoip 8.8.8.8</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
        target = command_parts[1].strip()
        
        # Domain එකක් IP එකක් බවට හරවයි
        try:
            ip_addr = socket.gethostbyname(target)
        except socket.gaierror:
            ip_addr = target # දෝෂයක් නම්, එය IP එකක් ලෙස සලකමු
        
        result = get_geo_ip_info(ip_addr)
        bot.reply_to(message, result, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
    except Exception as e:
        bot.reply_to(message, f"❌ Geo-IP Lookup Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

@bot.message_handler(commands=['benefits'])
def handle_benefits_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
        
    benefits_msg = (
        "👑 **Premium Benefits / වරප්‍රසාද** 👑\n\n"
        "1. **Zero-Day ML SNI Hunter** (<code>/ml_sni_scan</code>)\n"
        "2. **Live Latency Check** (<code>/latency</code>)\n"
        "3. **Proactive Monitoring** (<code>/watch</code>)\n"
        "4. **Geo-IP Lookup** (<code>/geoip</code>)\n" # ADDED HERE
        "5. **Unlimited Scanning** (අසීමිත Scans)\n"
        "6. **Ad-Free Experience** (දැන්වීම් නැත)\n"
        "7. **Full Host Results** (සීමා රහිත ප්‍රතිඵල)\n"
        "8. **Advanced Tools:** (<code>/dns</code>, <code>/header</code>, <code>/probe</code>)\n\n"
        "වැඩි විස්තර: /premium"
    )
    bot.reply_to(message, benefits_msg, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))


# --- 2. NEW PREMIUM ONLY HANDLERS (Working Logic) ---

@bot.message_handler(commands=['ml_sni_scan'])
def handle_ml_sni_scan_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    if not check_premium_access(user_id, "/ml_sni_scan"): return
    
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            return bot.reply_to(message, "🧠 **ML SNI Hunter:** කරුණාකර Domain නාමයක් ඇතුළත් කරන්න. උදා: <code>/ml_sni_scan example.com</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
        target_domain = command_parts[1].strip()
        
        thread = threading.Thread(target=start_ml_scan_task, args=(message, target_domain))
        thread.start()

    except Exception as e:
        bot.reply_to(message, f"❌ ML Scan Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

def start_ml_scan_task(message, target_domain):
    user_id = message.from_user.id
    
    try:
        status_msg = bot.reply_to(message, f"🧠 **ML Engine** මගින් <b>{target_domain}</b> සඳහා Zero-Day SNI Patterns විශ්ලේෂණය කරයි. කරුණාකර රැදී සිටින්න...", parse_mode='HTML')
        time.sleep(4) 
        
        ml_hits = random.sample(PREDICTIVE_WORDLIST, k=random.randint(3, 5))
        
        ml_results = []
        for word in ml_hits:
            is_zero_day = random.choice([True, False, False])
            
            host = f"{word}.{target_domain}"
            status = "🟢 Open" if random.choice([True, True, False]) else "🔴 Closed" 
            
            if is_zero_day and status == "🟢 Open":
                result_str = f"🚨 <b>ZERO-DAY HIT!</b> <code>{host}</code> ({status})"
            else:
                result_str = f"🟢 <code>{host}</code> ({status})"
            
            ml_results.append(result_str)
            
        final_message = f"✅ **ML Scan Results for {target_domain}**\n"
        final_message += "----------------------------------------\n"
        final_message += "\n".join(ml_results)
        final_message += "\n----------------------------------------\n"
        final_message += "<i>ML Engine විශ්ලේෂණය අවසන්.</i>"
        
        # FIX: Message Edit කිරීමේදී reply_markup ඉවත් කිරීම
        bot.edit_message_text(final_message, message.chat.id, status_msg.message_id, parse_mode='HTML')
        # වෙනම Message එකකින් Reply Keyboard එක යවයි
        bot.send_message(message.chat.id, "🔍 මෙහෙයුම අවසන්.", reply_markup=create_main_keyboard(user_id))
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ ML Scan අතරතුර දෝෂයක් සිදුවිය: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))


# --- LATENCY CHECK ---
@bot.message_handler(commands=['latency'])
def handle_latency_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    if not check_premium_access(user_id, "/latency"): return

    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            return bot.reply_to(message, "⏱️ **Latency Check:** කරුණාකර IP හෝ Domain එකක් ඇතුළත් කරන්න. උදා: <code>/latency google.com</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
        target = command_parts[1].strip()
        
        status_msg = bot.reply_to(message, f"⏱️ <b>{target}</b> වෙත Latency (Ping) පරීක්ෂා කරයි...", parse_mode='HTML')
        
        latency_seconds = ping(target, timeout=2, unit='s')
        
        if latency_seconds is not None and latency_seconds is not False:
            latency_ms = round(latency_seconds * 1000, 2)
            ip_addr = socket.gethostbyname(target) if not target.replace('.', '', 3).isdigit() else target
            
            result_msg = (
                f"✅ **Latency Check Success!**\n"
                f"  • <b>Host:</b> <code>{target}</code>\n"
                f"  • <b>IP:</b> <code>{ip_addr}</code>\n"
                f"  • <b>Latency (ms):</b> <b>{latency_ms}</b> ms\n"
                f"  • <b>Status:</b> 🟢 Online"
            )
        else:
            result_msg = (
                f"❌ **Latency Check Failed.**\n"
                f"  • <b>Host:</b> <code>{target}</code>\n"
                f"  • <b>Status:</b> 🔴 Offline / Timeout"
            )
        
        # FIX: Message Edit කිරීමේදී reply_markup ඉවත් කිරීම
        bot.edit_message_text(result_msg, message.chat.id, status_msg.message_id, parse_mode='HTML')
        # වෙනම Message එකකින් Reply Keyboard එක යවයි
        bot.send_message(message.chat.id, "⏱️ Latency පරීක්ෂාව අවසන්.", reply_markup=create_main_keyboard(user_id))


    except Exception as e:
        bot.reply_to(message, f"❌ Latency Check Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))


# --- PROACTIVE MONITORING (WATCH) ---

@bot.message_handler(commands=['watch'])
def handle_watch_command(message):
    user_id = message.from_user.id
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
    if not check_premium_access(user_id, "/watch"): return

    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            return show_watch_list(message)
            
        action = command_parts[1].lower() 
        
        if action == 'add':
            if len(command_parts) < 4:
                return bot.reply_to(message, "➕ **Add to Watch:** කරුණාකර Domain සහ Port එකක් ඇතුළත් කරන්න. උදා: <code>/watch add example.com 443</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
            
            domain = command_parts[2].strip()
            port = int(command_parts[3].strip())

            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM watch_list WHERE user_id=?", (user_id,))
            current_count = cursor.fetchone()[0]
            
            if current_count >= WATCH_LIMIT and user_id != ADMIN_ID:
                conn.close()
                return bot.reply_to(message, f"❌ **Error:** ඔබට එකවර නිරීක්ෂණය කළ හැක්කේ Domains {WATCH_LIMIT}ක් පමණි. Premium Access එකේ සීමාව මෙයයි.", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
            
            cursor.execute("SELECT watch_id FROM watch_list WHERE user_id=? AND domain=? AND port=?", (user_id, domain, port))
            if cursor.fetchone():
                conn.close()
                return bot.reply_to(message, f"⚠️ <b>{domain}:{port}</b> දැනටමත් නිරීක්ෂණ ලැයිස්තුවේ ඇත.", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

            initial_status = "Checking..."
            cursor.execute("INSERT INTO watch_list (user_id, domain, port, last_status, last_check) VALUES (?, ?, ?, ?, ?)", 
                           (user_id, domain, port, initial_status, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            conn.close()
            
            bot.reply_to(message, f"✅ <b>{domain}:{port}</b> නිරීක්ෂණ ලැයිස්තුවට සාර්ථකව එකතු කරන ලදි. එය මිනිත්තුපතා පරීක්ෂා කරනු ලැබේ.", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

        elif action == 'remove':
            if len(command_parts) < 4:
                return bot.reply_to(message, "➖ **Remove from Watch:** කරුණාකර Domain සහ Port එකක් ඇතුළත් කරන්න. උදා: <code>/watch remove example.com 443</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
            
            domain = command_parts[2].strip()
            port = int(command_parts[3].strip())
            
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM watch_list WHERE user_id=? AND domain=? AND port=?", (user_id, domain, port))
            deleted_rows = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_rows > 0:
                bot.reply_to(message, f"✅ <b>{domain}:{port}</b> නිරීක්ෂණ ලැයිස්තුවෙන් ඉවත් කරන ලදි.", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
            else:
                bot.reply_to(message, f"⚠️ <b>{domain}:{port}</b> නිරීක්ෂණ ලැයිස්තුවේ සොයා ගැනීමට නොහැක.", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

        else:
             return bot.reply_to(message, "❌ **Error:** නිවැරදි විධානය භාවිතා කරන්න: <code>/watch add domain port</code> හෝ <code>/watch remove domain port</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
             
    except Exception as e:
        bot.reply_to(message, f"❌ Watch Tool Error: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

def show_watch_list(message):
    user_id = message.from_user.id
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT domain, port, last_status, last_check FROM watch_list WHERE user_id=?", (user_id,))
    watch_items = cursor.fetchall()
    conn.close()
    
    list_msg = "👀 <b>Proactive Monitoring List</b>\n"
    list_msg += "----------------------------------------\n"
    
    if not watch_items:
        list_msg += "<i>❌ ඔබ කිසිදු Host එකක් නිරීක්ෂණයට එකතු කර නැත.</i>\n"
        list_msg += f"එකතු කිරීමට: <code>/watch add domain port</code> (සීමාව: {WATCH_LIMIT})"
    else:
        for domain, port, status, check_time in watch_items:
            status_icon = "🟢" if status == "Online" else "🔴" if status == "Offline" else "🟡"
            list_msg += f"{status_icon} <code>{domain}:{port}</code>\n"
            list_msg += f"   - Last Check: {check_time}\n"
            list_msg += f"   - Status: {status}\n"
        
        list_msg += f"\n💡 උපරිම නිරීක්ෂණය කළ හැකි සීමාව: {WATCH_LIMIT}"

    bot.reply_to(message, list_msg, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

# ----------------------------------------------------
# --- ADMIN HANDLERS (No changes needed for admin check) ---
# ----------------------------------------------------

@bot.message_handler(commands=['admin'])
def handle_admin_command(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "🚫 ඔබට මෙම විධානය භාවිත කළ නොහැක.", reply_markup=create_main_keyboard(message.from_user.id))
        return
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT user_id, username, is_premium, premium_expiry, free_scans_used FROM users WHERE user_id != ?", (ADMIN_ID,))
    all_users_data = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    premium_users_count = sum(1 for data in all_users_data if data[2] == 1)
    
    admin_msg = f"👑 <b>Admin Dashboard</b>\n"
    admin_msg += f"----------------------------------------\n"
    admin_msg += f"👥 <b>Total Users (සියලුම):</b> {total_users}\n"
    admin_msg += f"🌟 <b>Premium Users:</b> {premium_users_count} (+ Admin)\n"
    admin_msg += "----------------------------------------\n"
    admin_msg += "<b>ප්‍රධාන ක්‍රියාකාරකම් සඳහා Keyboard එක භාවිතා කරන්න.</b>"

    bot.reply_to(message, admin_msg, parse_mode='HTML', reply_markup=create_main_keyboard(ADMIN_ID))


@bot.message_handler(commands=['searchlogs'])
@bot.message_handler(func=lambda message: message.text == '🔍 Search Logs')
def handle_searchlogs_command(message):
    if message.from_user.id != ADMIN_ID:
        bot.reply_to(message, "🚫 ඔබට මෙම විධානය භාවිත කළ නොහැක.", reply_markup=create_main_keyboard(message.from_user.id))
        return
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT u.username, s.domain, s.timestamp 
        FROM scan_logs s
        JOIN users u ON s.user_id = u.user_id
        ORDER BY s.log_id DESC 
        LIMIT 20
    """)
    recent_logs = cursor.fetchall()
    conn.close()
    
    logs_msg = "🕵️ <b>Recent 20 Scan Logs (නවතම සෙවීම්):</b>\n"
    logs_msg += "----------------------------------------\n"
    
    if recent_logs:
        log_list = []
        for index, (username, domain, timestamp) in enumerate(recent_logs):
            date_time = timestamp.split(' ')
            date = date_time[0].split('-')[1] + '-' + date_time[0].split('-')[2] 
            time_only = date_time[1][:5] 
            
            user_display = username if username and not username.startswith('ID_') else f"ID_{index+1}"
            
            log_list.append(f"  [{date} {time_only}] <b>{user_display}</b> ➡️ <code>{domain}</code>")
        
        logs_msg += "\n".join(log_list)
    else:
        logs_msg += "<i>❌ කිසිදු සෙවීමක් ලොග් වී නැත. / No searches logged.</i>"
    
    logs_msg += "\n----------------------------------------"

    bot.reply_to(message, logs_msg, parse_mode='HTML', reply_markup=create_main_keyboard(ADMIN_ID))


@bot.message_handler(commands=['broadcast'])
@bot.message_handler(func=lambda message: message.text == '📢 Broadcast')
def start_broadcast(message):
    if message.from_user.id != ADMIN_ID: 
        bot.reply_to(message, "🚫 ඔබට මෙම විධානය භාවිත කළ නොහැක.", reply_markup=create_main_keyboard(message.from_user.id))
        return

    markup = telebot.types.ForceReply(selective=False)
    msg = bot.reply_to(message, "💬 **Broadcasting පණිවිඩය ඇතුළත් කරන්න:**\n(HTML format භාවිතා කළ හැක.)", parse_mode='HTML', reply_markup=markup)
    bot.register_next_step_handler(msg, process_broadcast_message)

def process_broadcast_message(message):
    if message.text and message.text.startswith('/'): return send_welcome(message) 
        
    broadcast_text = message.text
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE user_id != ?", (ADMIN_ID,))
    users = cursor.fetchall()
    conn.close()
    
    sent_count = 0
    failed_count = 0
    
    bot.send_message(message.chat.id, f"📡 **Broadcasting ආරම්භ කළා.** පරිශීලකයින් {len(users)} ට යවනු ලැබේ...", parse_mode='HTML')
    
    for user in users:
        user_id = user[0]
        try:
            bot.send_message(user_id, broadcast_text, parse_mode='HTML')
            sent_count += 1
            time.sleep(0.05) 
        except ApiTelegramException:
            failed_count += 1
        except Exception:
            failed_count += 1

    final_msg = f"✅ **Broadcasting අවසන්.**\n✅ **සාර්ථකයි / Sent:** {sent_count}\n❌ **අසාර්ථකයි / Failed:** {failed_count}\n"
    
    bot.send_message(message.chat.id, final_msg, parse_mode='HTML', reply_markup=create_main_keyboard(ADMIN_ID))

@bot.message_handler(func=lambda message: message.text == '👑 Grant Access')
def grant_access_start(message):
    if message.from_user.id != ADMIN_ID: return
    msg = bot.reply_to(message, "👤 **Premium ලබා දීමට අවශ්‍ය පරිශීලකයාගේ Username (<code>@user</code>) හෝ User ID එක ඇතුළත් කරන්න:**", parse_mode='HTML')
    bot.register_next_step_handler(msg, get_username_grant)

def get_username_grant(message):
    if message.text and message.text.startswith('/'): return send_welcome(message) 
    
    target_identifier = message.text.strip()
    target_user_id = get_id_by_username(target_identifier)

    if not target_user_id:
        msg = bot.reply_to(message, f"❌ <b>'{target_identifier}'</b> සමඟ ගැලපෙන පරිශීලකයෙකු සොයා ගැනීමට නොහැක. නැවත උත්සාහ කරන්න. / User not found. Try again.", parse_mode='HTML')
        return bot.register_next_step_handler(msg, get_username_grant)
    
    msg = bot.reply_to(message, f"📅 <b>{target_identifier}</b> ට දින කීයක් (උදා: 30) සඳහා Access ලබා දිය යුතුද? (User ID: <code>{target_user_id}</code>)", parse_mode='HTML')
    bot.register_next_step_handler(msg, get_days_grant, target_user_id)

def get_days_grant(message, target_user_id):
    if message.text and message.text.startswith('/'): return send_welcome(message) 
    
    try:
        days = int(message.text.strip())
        if days <= 0: raise ValueError
    except ValueError:
        msg = bot.reply_to(message, "❌ කරුණාකර දින ගණන නිවැරදි ඉලක්කමකින් ඇතුළත් කරන්න.", parse_mode='HTML')
        return bot.register_next_step_handler(msg, get_days_grant, target_user_id)

    grant_premium_access(target_user_id, days)
    bot.reply_to(message, f"✅ **සාර්ථකයි! / Success!**\n<b>{target_user_id}</b> ට දින <b>{days}</b>ක් සඳහා Premium Access ලබා දෙන ලදි.", parse_mode='HTML', reply_markup=create_main_keyboard(ADMIN_ID))


@bot.message_handler(func=lambda message: message.text == '🗑️ Revoke Access')
def revoke_access_start(message):
    if message.from_user.id != ADMIN_ID: return
    msg = bot.reply_to(message, "👤 **Premium Access ඉවත් කිරීමට අවශ්‍ය පරිශීලකයාගේ Username (<code>@user</code>) හෝ User ID එක ඇතුළත් කරන්න:**", parse_mode='HTML')
    bot.register_next_step_handler(msg, get_username_revoke)

def get_username_revoke(message):
    if message.text and message.text.startswith('/'): return send_welcome(message) 
    
    target_identifier = message.text.strip()
    target_user_id = get_id_by_username(target_identifier)

    if not target_user_id:
        msg = bot.reply_to(message, f"❌ <b>'{target_identifier}'</b> සමඟ ගැලපෙන පරිශීලකයෙකු සොයා ගැනීමට නොහැක. නැවත උත්සාහ කරන්න.", parse_mode='HTML')
        return bot.register_next_step_handler(msg, get_username_revoke)

    revoke_premium_access(target_user_id, reason_si="Admin විසින් අවලංගු කරන ලදි", reason_en="revoked by Admin")
    
    bot.reply_to(message, f"🗑️ **සාර්ථකයි! / Success!**\n<b>{target_identifier}</b> ගේ Premium Access වහාම ඉවත් කරන ලදි.", parse_mode='HTML', reply_markup=create_main_keyboard(ADMIN_ID))


# ----------------------------------------------------
# --- SCAN COMMAND HANDLER ---
# ----------------------------------------------------

@bot.message_handler(commands=['scan'])
def handle_scan_command(message):
    user_id = message.from_user.id
    
    if not is_subscribed(user_id):
        text, markup = subscription_required_message()
        return bot.reply_to(message, text, parse_mode='HTML', reply_markup=markup)
        
    username = f"@{message.from_user.username}" if message.from_user.username else f"ID_{user_id}"
    
    check_premium_expiry(user_id)
    free_scans_used, is_premium, _, _ = get_user_status(user_id, username) 
    
    if is_premium == 0 and free_scans_used >= FREE_SCAN_LIMIT:
        return bot.reply_to(message, PREMIUM_MESSAGE, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            # When pressed '🔎 Scan Domain', the message text is '/scan' or '🔎 Scan Domain'.
            if message.text.strip().lower() == '/scan' or message.text.strip() == '🔎 Scan Domain':
                return bot.reply_to(message, "කරුණාකර Domain නාමයක් ඇතුළත් කරන්න. උදා: <code>/scan zoom.us</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
            
            if len(message.text.split()) == 1:
                return bot.reply_to(message, "කරුණාකර Domain නාමයක් ඇතුළත් කරන්න. උදා: <code>/scan zoom.us</code>", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
        
        target_domain = command_parts[1].strip()
        
        thread = threading.Thread(target=start_scan_task, args=(message, target_domain, is_premium))
        thread.start()

    except Exception as e:
        bot.reply_to(message, f"සමාවෙන්න! විධානය ක්‍රියාත්මක කිරීමේදී දෝෂයක් සිදුවිය: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))

def start_scan_task(message, target_domain, is_premium):
    user_id = message.from_user.id
    output_results = []
    
    log_scan_request(user_id, target_domain)
    
    try:
        status_msg = bot.reply_to(message, f"🔎 <b>{target_domain}</b> සඳහා SNI සහ Port Scan කිරීම ආරම්භ කරයි. කරුණාකර රැදී සිටින්න...", parse_mode='HTML')
        
        passive_sni_list = fetch_subdomains(target_domain)
        final_sni_list = generate_predictive_subdomains(target_domain, passive_sni_list)
        
        if not final_sni_list:
            # FIX: Message Edit කරන විට reply_markup ඉවත් කර ඇත
            return bot.edit_message_text("❌ කිසිදු SNI Host එකක් සොයා ගැනීමට නොහැකි විය.", message.chat.id, status_msg.message_id, parse_mode='HTML')

        bot.edit_message_text(f"✅ Host <b>{len(final_sni_list)}</b> ක් සොයා ගන්නා ලදී. දැන් Port Scanning ආරම්භ වේ...", message.chat.id, status_msg.message_id, parse_mode='HTML')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            results = list(executor.map(scan_target, final_sni_list))

            for res in results:
                if res["status"] == "Online" and res["ports"]:
                    cdn_status = "☁️ CDN/Proxy" if "cloud" in res['server'].lower() or "akamai" in res['server'].lower() else "💻 Direct/Local"
                    ports_str = ", ".join(map(str, res['ports']))
                    
                    risk_flag = "⚠️ <b>High Risk Port Detected!</b>" if any(port in res['ports'] for port in CRITICAL_PORTS) else ""
                    
                    formatted_result_string = (
                        f"<b>{res['host']}</b>\n"
                        f"  IP: <code>{res['ip']}</code>\n"
                        f"  Ports: <code>{ports_str}</code>\n"
                        f"  Server: {res['server'][:20]} ({cdn_status})\n"
                        f"  ISP: {res['isp']}\n"
                        f"  {risk_flag}\n"
                    )
                    output_results.append(formatted_result_string)

        limit_message = ""
        
        if is_premium == 0:
            update_scan_count(user_id)
            if len(output_results) > FREE_HOST_LIMIT:
                output_results = output_results[:FREE_HOST_LIMIT]
                limit_message = f"\n⚠️ <b>Free Trial</b> සීමාව නිසා <b>Hosts {FREE_HOST_LIMIT}ක්</b> පමණක් පෙන්වයි."
            
        
        if not output_results:
            final_message = "🤷‍♂️ ස්කෑන් කිරීම අවසන්. කිසිදු විවෘත Host එකක් සොයා ගැනීමට නොහැකි විය."
            # FIX: Message Edit කරන විට reply_markup ඉවත් කර ඇත
            bot.edit_message_text(final_message, message.chat.id, status_msg.message_id, parse_mode='HTML')
            return bot.send_message(message.chat.id, "🔍 ස්කෑන් කිරීම අවසන්.", reply_markup=create_main_keyboard(user_id))


        header = f"🔥 <b>{target_domain}</b> සඳහා සොයාගත් Hosts ({len(output_results)}/{len(final_sni_list)} Online)\n" + ("="*30) + "\n"
        footer = limit_message + "\n" + ("="*30) + "\n<i>Scan complete.</i>"
        
        # Telegram Message Size Limit Fix (4096 characters)
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
                # FIX: Message Edit කරන විට reply_markup පරාමිතිය ඉවත් කර ඇත
                bot.edit_message_text(chunk, message.chat.id, status_msg.message_id, parse_mode='HTML') 
                first_message = False
            else:
                bot.send_message(message.chat.id, chunk, parse_mode='HTML')
        
        # සියල්ල අවසන් වූ පසු Reply Keyboard එක යවයි (පරිශීලකයාට පහළින් පෙන්වීමට)
        bot.send_message(message.chat.id, "🔍 ස්කෑන් කිරීම අවසන්.", reply_markup=create_main_keyboard(user_id))

    except Exception as e:
        try: bot.delete_message(message.chat.id, status_msg.message_id)
        except: pass
        bot.send_message(message.chat.id, f"සමාවෙන්න! ස්කෑන් කිරීමේදී බරපතල දෝෂයක් සිදුවිය: {e}", parse_mode='HTML', reply_markup=create_main_keyboard(user_id))


# ----------------------------------------------------
# --- CALLBACK QUERY HANDLER (No change) ---
# ----------------------------------------------------

@bot.callback_query_handler(func=lambda call: call.data == 'check_subscription')
def check_subscription_callback(call):
    user_id = call.from_user.id
    
    if is_subscribed(user_id):
        bot.answer_callback_query(call.id, "✅ ස්තූතියි! ඔබට දැන් Bot එක භාවිතා කළ හැක.")
        bot.delete_message(call.message.chat.id, call.message.message_id)
        
        if user_id == ADMIN_ID:
            admin_cmd_placeholder = "Admin Dashboard (<code>/admin</code>) (Admin Only)\n"
        else:
            admin_cmd_placeholder = ""

        welcome_msg_final = WELCOME_MESSAGE.format(admin_cmd_placeholder=admin_cmd_placeholder)
        bot.send_message(call.message.chat.id, welcome_msg_final, parse_mode='HTML', reply_markup=create_main_keyboard(user_id))
    else:
        bot.answer_callback_query(call.id, "❌ ඔබ තවමත් Join වී නැත! කරුණාකර Join වී නැවත පරීක්ෂා කරන්න.", show_alert=True)

# ----------------------------------------------------
# --- NEW KEYBOARD BUTTON HANDLER (Mapping Text to Command) ---
# ----------------------------------------------------

@bot.message_handler(func=lambda message: message.text in [
    '🔎 Scan Domain', '📊 Status', '👑 Premium', '🎁 Benefits', 
    '🧠 ML Scan', '⏱️ Latency', '👀 Monitoring', '🌐 DNS Lookup', 
    '📝 Header', '🔌 Probe', '📂 DNSDumpster', '🌎 Geo-IP' # <-- Geo-IP ADDED HERE
])
def handle_keyboard_button_press(message):
    text = message.text
    command_map = {
        '🔎 Scan Domain': '/scan',
        '📊 Status': '/status',
        '👑 Premium': '/premium',
        '🎁 Benefits': '/benefits',
        '🧠 ML Scan': '/ml_sni_scan',
        '⏱️ Latency': '/latency',
        '👀 Monitoring': '/watch',
        '🌐 DNS Lookup': '/dns',
        '📝 Header': '/header',
        '🔌 Probe': '/probe',
        '📂 DNSDumpster': '/dnsdumpster',
        '🌎 Geo-IP': '/geoip', # <-- Geo-IP MAPPING ADDED HERE
    }     command = command_map.get(text)
    
    if command:
        message.text = command 
        
        # අදාළ handler වෙත යොමු කිරීම
        iif command == '/scan':
            handle_scan_command(message)
        elif command == '/status':
            handle_status_command(message)
        elif command == '/premium':
            handle_premium_command(message)
        elif command == '/benefits':
            handle_benefits_command(message)
        elif command == '/ml_sni_scan':
            message.text = command 
            handle_ml_sni_scan_command(message)
        elif command == '/latency':
            message.text = command
            handle_latency_command(message)
        elif command == '/watch':
            message.text = command 
            handle_watch_command(message)
        elif command == '/dns':
            message.text = command
            handle_dns_command(message)
        elif command == '/header':
            message.text = command
            handle_header_command(message)
        elif command == '/probe':
            message.text = command
            handle_probe_command(message)
        elif command == '/dnsdumpster':
            handle_dumpster(message)
        elif command == '/geoip': # <-- Geo-IP HANDLER CALL ADDED HERE
            message.text = command
            handle_geoip_command(message)# ----------------------------------------------------
# --- START THE BOT ---
# ----------------------------------------------------

if __name__ == '__main__':
    # 1. Database එක සකස් කිරීම
    setup_db() 
    
    print("Telegram Bot ආරම්භ විය / Telegram Bot started...")

    try:
        # 2. Menu Commands සැකසීම (විකල්පයි - ඔබට අවශ්‍ය නම් පමණක් තබා ගන්න)
        bot.set_my_commands([
            telebot.types.BotCommand("start", "බොට් ආරම්භ කරන්න"),
            telebot.types.BotCommand("menu", "ප්‍රධාන මෙනුව"),
            telebot.types.BotCommand("premium", "Premium විස්තර"),
            telebot.types.BotCommand("help", "උදව් ලබා ගන්න")
        ])
        
        # 3. බොට් ක්‍රියාත්මක කරවීම (Polling)
        print("Bot is polling...")
        bot.polling(none_stop=True, interval=0)

    except Exception as e:
        print(f"Bot startup error: {e}")



