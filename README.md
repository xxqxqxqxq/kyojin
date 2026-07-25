# Discord Verify Website

Secure OAuth verification page for a Discord bot.

## How It Works

1. User clicks Verify in Discord → redirected to GitHub Pages
2. Frontend sends the OAuth code to the backend API
3. Backend handles token exchange, guild add, and role assignment
4. Frontend shows verifying → verified/failed states

**No secrets are exposed in the frontend.**

## Setup

### Backend

```bash
cd backend
pip install -r requirements.txt
```

Edit `config.json`:
```json
{
  "bot_token": "YOUR_BOT_TOKEN",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "guild_id": "YOUR_GUILD_ID",
  "verify_role_id": "YOUR_ROLE_ID",
  "redirect_uri": "https://YOUR_GITHUB_PAGES_URL/"
}
```

Run the backend:
```bash
python server.py
```

### Frontend

1. Upload `index.html` to GitHub Pages
2. Set Discord OAuth redirect URI to your GitHub Pages URL
3. The frontend calls `/api/verify` on your backend

### Discord Developer Portal

1. Go to your app → OAuth2
2. Set redirect URI to your GitHub Pages URL
3. Scopes: `identify`, `guilds.join`

## Files

```
github/
├── index.html          # Frontend (upload to GitHub Pages)
├── .gitignore
├── README.md
└── backend/
    ├── server.py       # Backend API server
    ├── config.json     # Secrets (DO NOT commit)
    └── requirements.txt
```

## Security

- Bot token stays on the backend only
- `config.json` is gitignored
- Frontend only calls the API, never touches Discord directly
