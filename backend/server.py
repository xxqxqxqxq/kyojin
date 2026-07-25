import os
import json
import time
import secrets
import hashlib
import hmac
from pathlib import Path
from functools import wraps
from collections import defaultdict

import aiohttp
from aiohttp import web, BasicAuth
from dotenv import load_dotenv

load_dotenv()

# ===== CONFIG =====
CONFIG_PATH = Path(__file__).parent / "config.json"
if CONFIG_PATH.exists():
    CONFIG = json.loads(CONFIG_PATH.read_text())
else:
    CONFIG = {}

def get_env(key, default=None):
    return os.environ.get(key, CONFIG.get(key, default))

BOT_TOKEN = get_env("BOT_TOKEN")
CLIENT_ID = get_env("CLIENT_ID")
CLIENT_SECRET = get_env("CLIENT_SECRET")
GUILD_ID = get_env("GUILD_ID")
VERIFY_ROLE_ID = get_env("VERIFY_ROLE_ID")
REDIRECT_URI = get_env("REDIRECT_URI", "http://localhost:5000/verify")
ADMIN_USERNAME = get_env("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = get_env("ADMIN_PASSWORD_HASH")
ADMIN_PASSWORD = get_env("ADMIN_PASSWORD")
SECRET_KEY = get_env("SECRET_KEY", secrets.token_hex(32))
HOST = get_env("HOST", "localhost")
PORT = int(get_env("PORT", 5000))

if ADMIN_PASSWORD and not ADMIN_PASSWORD_HASH:
    ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

# ===== SECURITY =====
TOKEN_URL = "https://discord.com/api/v10/oauth2/token"
USER_URL = "https://discord.com/api/v10/users/@me"
GUILD_MEMBER_URL = "https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}"
ROLE_URL = "https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}"

# Rate limiting
RATE_LIMITS = defaultdict(list)
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30

# Sessions
SESSIONS = {}
SESSION_EXPIRY = 3600

# ===== HELPERS =====
def rate_limit(ip):
    now = time.time()
    RATE_LIMITS[ip] = [t for t in RATE_LIMITS[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(RATE_LIMITS[ip]) >= RATE_LIMIT_MAX:
        return False
    RATE_LIMITS[ip].append(now)
    return True

def create_session(username):
    token = secrets.token_hex(32)
    SESSIONS[token] = {
        "username": username,
        "created": time.time(),
        "expires": time.time() + SESSION_EXPIRY
    }
    return token

def validate_session(token):
    if not token or token not in SESSIONS:
        return None
    session = SESSIONS[token]
    if time.time() > session["expires"]:
        del SESSIONS[token]
        return None
    return session

def require_auth(handler):
    @wraps(handler)
    async def wrapper(request):
        token = request.cookies.get("session")
        session = validate_session(token)
        if not session:
            return web.json_response({"error": "Unauthorized"}, status=401)
        request["session"] = session
        return await handler(request)
    return wrapper

def sanitize_input(value, max_length=100):
    if not isinstance(value, str):
        return None
    value = value.strip()[:max_length]
    return value if value else None

def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' https://cdn.discordapp.com data:; connect-src 'self'"
    return response

# ===== DISCORD OAUTH =====
async def exchange_code(code):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            TOKEN_URL, data=data,
            auth=BasicAuth(CLIENT_ID, CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        ) as r:
            if r.status == 200:
                return await r.json()
    return None

async def get_user(access_token):
    async with aiohttp.ClientSession() as session:
        async with session.get(USER_URL, headers={"Authorization": f"Bearer {access_token}"}) as r:
            if r.status == 200:
                return await r.json()
    return None

async def add_to_guild(access_token, user_id):
    async with aiohttp.ClientSession() as session:
        async with session.put(
            GUILD_MEMBER_URL.format(guild_id=GUILD_ID, user_id=user_id),
            json={"access_token": access_token},
            headers={"Authorization": f"Bot {BOT_TOKEN}", "Content-Type": "application/json"}
        ) as r:
            return r.status in (200, 201, 204)

async def give_role(user_id):
    async with aiohttp.ClientSession() as session:
        async with session.put(
            ROLE_URL.format(guild_id=GUILD_ID, user_id=user_id, role_id=VERIFY_ROLE_ID),
            headers={"Authorization": f"Bot {BOT_TOKEN}"}
        ) as r:
            return r.status in (200, 204)

# ===== ROUTES =====
async def handle_verify_page(request):
    response = web.FileResponse(Path(__file__).parent.parent / "index.html")
    return security_headers(response)

async def handle_login_page(request):
    response = web.FileResponse(Path(__file__).parent / "login.html")
    return security_headers(response)

async def handle_dashboard_page(request):
    response = web.FileResponse(Path(__file__).parent / "dashboard.html")
    return security_headers(response)

async def handle_static(request):
    filename = request.match_info["filename"]
    file_path = Path(__file__).parent / filename
    if not file_path.exists() or not file_path.is_file():
        return web.Response(status=404)
    if ".." in filename or "/" in filename:
        return web.Response(status=403)
    response = web.FileResponse(file_path)
    return security_headers(response)

async def handle_api_verify(request):
    ip = request.remote
    if not rate_limit(ip):
        return web.json_response({"success": False, "error": "Rate limited"}, status=429)

    code = request.query.get("code")
    code = sanitize_input(code, 200)
    if not code:
        return web.json_response({"success": False, "error": "Missing code"}, status=400)

    token_data = await exchange_code(code)
    if not token_data or "access_token" not in token_data:
        return web.json_response({"success": False, "error": "Invalid or expired code"})

    user = await get_user(token_data["access_token"])
    if not user:
        return web.json_response({"success": False, "error": "Failed to get user info"})

    user_id = user["id"]
    username = user["username"]
    discriminator = user.get("discriminator", "0")
    display = f"@{username}" if discriminator == "0" else f"@{username}#{discriminator}"

    if not await add_to_guild(token_data["access_token"], user_id):
        return web.json_response({"success": False, "error": "Failed to add you to the server"})

    if not await give_role(user_id):
        return web.json_response({"success": False, "error": "Failed to assign role"})

    return web.json_response({"success": True, "username": display})

async def handle_api_login(request):
    ip = request.remote
    if not rate_limit(ip):
        return web.json_response({"error": "Rate limited"}, status=429)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid request"}, status=400)

    username = sanitize_input(data.get("username"), 50)
    password = sanitize_input(data.get("password"), 100)

    if not username or not password:
        return web.json_response({"error": "Missing credentials"}, status=400)

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if not ADMIN_PASSWORD_HASH or password_hash != ADMIN_PASSWORD_HASH:
        time.sleep(0.5)
        return web.json_response({"error": "Invalid credentials"}), 401

    token = create_session(username)
    response = web.json_response({"success": True})
    response.set_cookie(
        "session", token,
        httponly=True,
        secure=False,
        samesite="Strict",
        max_age=SESSION_EXPIRY,
        path="/"
    )
    return security_headers(response)

async def handle_api_logout(request):
    token = request.cookies.get("session")
    if token and token in SESSIONS:
        del SESSIONS[token]
    response = web.json_response({"success": True})
    response.del_cookie("session")
    return response

async def handle_api_session(request):
    token = request.cookies.get("session")
    session = validate_session(token)
    if not session:
        return web.json_response({"authenticated": False})
    return web.json_response({"authenticated": True, "username": session["username"]})

async def handle_api_command(request):
    ip = request.remote
    if not rate_limit(ip):
        return web.json_response({"error": "Rate limited"}, status=429)

    token = request.cookies.get("session")
    session = validate_session(token)
    if not session:
        return web.json_response({"error": "Unauthorized"}, status=401)

    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid request"}, status=400)

    command = sanitize_input(data.get("command"), 500)
    if not command:
        return web.json_response({"error": "Missing command"}, status=400)

    blocked = ["rm ", "del ", "format", "shutdown", "eval", "exec", "__import__", "subprocess", "os.system"]
    if any(b in command.lower() for b in blocked):
        return web.json_response({"error": "Command blocked"}, status=403)

    return web.json_response({
        "output": f"Command received: {command}\nNote: Connect bot backend to execute commands.",
        "user": session["username"]
    })

# ===== APP =====
app = web.Application()

app.router.add_get("/", handle_verify_page)
app.router.add_get("/index.html", handle_verify_page)
app.router.add_get("/login", handle_login_page)
app.router.add_get("/login.html", handle_login_page)
app.router.add_get("/dashboard", handle_dashboard_page)
app.router.add_get("/dashboard.html", handle_dashboard_page)
app.router.add_get("/verify", handle_verify_page)
app.router.add_get("/api/verify", handle_api_verify)
app.router.add_post("/api/login", handle_api_login)
app.router.add_post("/api/logout", handle_api_logout)
app.router.add_get("/api/session", handle_api_session)
app.router.add_post("/api/command", handle_api_command)
app.router.add_get("/{filename}", handle_static)

if __name__ == "__main__":
    print(f"Starting server on {HOST}:{PORT}")
    web.run_app(app, host=HOST, port=PORT)
