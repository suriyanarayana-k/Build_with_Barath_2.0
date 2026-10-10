# CyberAccess dashboard

```bash
npm ci
npm run dev
```

Start the backend separately using `bola-benchmark/run_dev_server.py`. Open `http://localhost:5173/signup` for self-service API keys or `/` for dashboard login.

Vite proxies `/api` to `http://127.0.0.1:8000`. Set `BACKEND_PROXY_TARGET` in `.env` for another backend. Production builds use `VITE_API_BASE_URL`, defaulting to `/api`; Docker nginx proxies that path to the backend. A separately hosted static frontend needs the backend's public HTTPS URL at build time.

The dashboard uses the logged-in user's token. No admin password is bundled. Polling starts after login and stops on signup or logout. Requests time out after 10 seconds and expired sessions return to login.

The repository root imports this same frontend, so `npm run dev` works from either directory. See [the project README](../README.md) for configuration and integration.
