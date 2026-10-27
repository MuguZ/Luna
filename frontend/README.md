# SREEMA Frontend

React + TypeScript + Vite dashboard scaffold.

## Run on CachyOS/Linux

Install Node.js LTS and pnpm if they are not already installed. From this directory:

```bash
pnpm install
pnpm dev
```

Open `http://127.0.0.1:5173`.

The dashboard checks the FastAPI health endpoint at `http://127.0.0.1:8000/health`. Start the backend separately. To change the API location, create a local `.env` file with:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000
```

The current dashboard is a scaffold; investigation and alert counts are intentionally empty until the APIs exist.
