# SREEMA API

## Run on CachyOS/Linux

From the repository root:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install pytest httpx
uvicorn app.main:app --reload
```

In another terminal, run tests:

```bash
cd backend
source .venv/bin/activate
pytest
```

Health endpoint: `GET http://127.0.0.1:8000/health`

Interactive API docs: `http://127.0.0.1:8000/docs`
