# Deployment Guide for AEGIS

This guide details all available production deployment paths for **AEGIS** (Frontend Landing Page, Terminal Dashboard, FastAPI REST API, and SQLite Persistence).

---

## Option 1: 1-Click Deployment on Vercel (Frontend & Demo)

Deploy the dark-mode landing page and interactive mock attack dashboard globally on Vercel's Edge CDN with zero configuration.

### Steps:
1. Push your repository to GitHub.
2. Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
3. Import your AEGIS repository.
4. Set **Root Directory** to `dashboard`.
5. Deploy! (The configured `dashboard/vercel.json` handles build outputs and client-side routing automatically).

Or deploy via terminal:
```bash
cd dashboard
npx vercel
```

---

## Option 2: Full-Stack Docker Container (1-Command Deployment)

We configured a production multi-stage `Dockerfile` and `docker-compose.yml` that builds the React frontend and serves both the API and the web app from a single unified server.

### Run with Docker Compose:
```bash
docker compose up -d --build
```

### Access:
* **Web App (Landing Page & Dashboard)**: `http://localhost:8000/`
* **FastAPI Swagger API**: `http://localhost:8000/docs`
* **Health Check**: `http://localhost:8000/health`

---

## Option 3: Cloud Platforms (Render, Railway, Fly.io)

Deploy both the backend and frontend on cloud platforms using Docker.

### Render.com / Railway / Fly.io:
1. Connect your GitHub repository.
2. Select **"Docker"** as the runtime environment (it will automatically detect the root `Dockerfile`).
3. Set environment variable:
   * `API_PORT=8000` (or platform default `$PORT`)
4. Deploy!

---

## Option 4: Deploying on a Linux VPS (Ubuntu / Debian / AWS EC2)

For production deployment on an Ubuntu VPS with Nginx and Systemd:

### 1. Build the frontend:
```bash
cd dashboard
npm install
npm run build
cd ..
```

### 2. Set up Python virtualenv:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m scripts.seed_demo_attacks
```

### 3. Create Systemd Service (`/etc/systemd/system/aegis.service`):
```ini
[Unit]
Description=AEGIS Intrusion Detection Grid & API
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/aegis
ExecStart=/var/www/aegis/venv/bin/python -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

### 4. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aegis
```

### 5. Configure Nginx Reverse Proxy:
```nginx
server {
    listen 80;
    server_name aegis.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
