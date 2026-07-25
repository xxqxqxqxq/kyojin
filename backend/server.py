import aiohttp
from aiohttp import web, BasicAuth
import json
from pathlib import Path

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())

TOKEN_URL = "https://discord.com/api/v10/oauth2/token"
USER_URL = "https://discord.com/api/v10/users/@me"
GUILD_MEMBER_URL = "https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}"
ROLE_URL = "https://discord.com/api/v10/guilds/{guild_id}/members/{user_id}/roles/{role_id}"


async def handle_verify(request: web.Request) -> web.Response:
    code = request.query.get("code")
    if not code:
        return web.json_response({"success": False, "error": "Missing code"}, status=400)

    async with aiohttp.ClientSession() as session:
        # Exchange code for token
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CONFIG["redirect_uri"],
        }
        async with session.post(
            TOKEN_URL,
            data=token_data,
            auth=BasicAuth(CONFIG["client_id"], CONFIG["client_secret"]),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as r:
            if r.status != 200:
                return web.json_response({"success": False, "error": "Invalid or expired code"})
            token_json = await r.json()

        access_token = token_json.get("access_token")
        if not access_token:
            return web.json_response({"success": False, "error": "Invalid or expired code"})

        # Get user info
        async with session.get(USER_URL, headers={"Authorization": f"Bearer {access_token}"}) as r:
            if r.status != 200:
                return web.json_response({"success": False, "error": "Failed to get user info"})
            user = await r.json()

        user_id = user["id"]
        username = user["username"]
        discriminator = user.get("discriminator", "0")
        display = f"@{username}" if discriminator == "0" else f"@{username}#{discriminator}"

        # Add to guild
        async with session.put(
            GUILD_MEMBER_URL.format(guild_id=CONFIG["guild_id"], user_id=user_id),
            json={"access_token": access_token},
            headers={"Authorization": f"Bot {CONFIG['bot_token']}", "Content-Type": "application/json"},
        ) as r:
            if r.status not in (200, 201, 204):
                return web.json_response({"success": False, "error": "Failed to add you to the server"})

        # Add role
        async with session.put(
            ROLE_URL.format(guild_id=CONFIG["guild_id"], user_id=user_id, role_id=CONFIG["verify_role_id"]),
            headers={"Authorization": f"Bot {CONFIG['bot_token']}"},
        ) as r:
            if r.status not in (200, 204):
                return web.json_response({"success": False, "error": "Failed to assign role"})

    return web.json_response({"success": True, "username": display})


async def index(request: web.Request) -> web.Response:
    return web.FileResponse(Path(__file__).parent.parent / "index.html")


app = web.Application()
app.router.add_get("/", index)
app.router.add_get("/api/verify", handle_verify)

if __name__ == "__main__":
    web.run_app(app, host="localhost", port=5000)
