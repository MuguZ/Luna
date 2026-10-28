# Frontend

React 18, TypeScript, Vite, and Lucide React dashboard. The upload workflow parses JSON locally in the browser and sends valid event data only to the configured Luna API. See the root [README](../README.md) for data retention details and full setup.

```bash
npm ci
npm run dev
```

Set `VITE_API_BASE_URL` in `frontend/.env.local` only when the backend is not at `http://127.0.0.1:8000`. Production validation/build:

```bash
npm run build
```
