# AI Attack Investigator

AI2 course project, Faculty of Computers and Information, Mansoura University.

A web app that analyses a website's access logs with classical machine learning:
it detects attacks, finds the attack stage, scores the risk, predicts the
attacker's next step, and suggests a fix and a blocking rule.

> **Ethics:** attacks run only against our own isolated Juice Shop lab
> (bound to 127.0.0.1). Never point any script at a real or third-party site.

## Structure

```
lab/        Docker lab: Juice Shop behind Nginx (access logs in lab/logs/)
backend/    FastAPI app (POST /analyze)
frontend/   Upload page and results table
ml/         Feature extraction and models (features.py)
models/     Trained model files (models/detector.joblib, not committed)
tests/      Backend tests (pytest)
data/       Datasets (raw/ and processed/, not committed)
notebooks/  Experiments
docs/       Plan and notes
```

## Setup (Windows)

1. Install WSL2: open PowerShell as administrator, run `wsl --install`, restart.
2. Install Docker Desktop and make sure it is running.
3. Install Python 3.11, then from the repo folder:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run the lab

```powershell
cd lab
docker compose up -d
```

Open http://127.0.0.1:8080 . Every request is logged to `lab/logs/access.log`.
Stop it with `docker compose down`.

## Run the backend

The backend is a FastAPI app. It reads a web server access log and marks every
request as `attack` or `normal`. Install the requirements first (see Setup).

### 1. Get the model

The server needs `models/detector.joblib`. This file is not in git.

- Train it: `python -m ml.train_detector` (needs the training data in
  `data/processed/`), or
- Ask Safi for the file and put it in `models/`.

Without the model the server starts, but `/analyze` returns HTTP 503.

### 2. Start the server

From the repo folder, with the virtual environment active:

```powershell
.venv\Scripts\activate
uvicorn backend.app.main:app --reload
```

- http://127.0.0.1:8000 : upload page
- http://127.0.0.1:8000/health : should show `"model_loaded": true`
- http://127.0.0.1:8000/docs : try the API in the browser

If you add or change `models/detector.joblib`, stop the server (Ctrl+C) and
start it again. The model is loaded once at startup.

### 3. Analyze a log

```powershell
curl.exe -X POST http://127.0.0.1:8000/analyze -F "file=@sample_access.log"
```

In PowerShell use `curl.exe`. Plain `curl` is a different command.

### 4. What the response means

| Field | Meaning |
|---|---|
| `filename` | Name of the uploaded file |
| `format` | Log format that was detected |
| `has_body` | `true` if the log contains request bodies |
| `lines` | Non-empty lines in the file (`parsed` + `skipped`) |
| `parsed` | Lines that were read as requests |
| `skipped` | Lines that could not be read |
| `attacks` / `normal` | Number of requests in each class |
| `results` | One entry per request, in file order |

Each entry in `results` has: `ip`, `time`, `timestamp` (ISO 8601), `method`,
`path` (with query string), `status`, `size`, `user_agent`, `body`, plus:

- `attack_prob`: the model's probability that the request is an attack (0 to 1)
- `label`: `attack` if `attack_prob >= 0.5`, otherwise `normal`

Values of secret fields (`password`, `pwd`, `token`, `apikey`, `card`, `cvv`,
...) in `body` and in the query string of `path` are replaced with `***`.
The model sees the original text. Only the response is masked.

### 5. Errors

| Code | When | What to do |
|---|---|---|
| 400 | The file is empty | Upload a log with at least one line |
| 400 | The log format is unknown | Use one of the supported formats below |
| 413 | The file is larger than 50 MB | Upload a smaller log or split it |
| 503 | The model file is missing | See "Get the model", then restart the server |

### 6. Supported log formats

- `combined`: Nginx/Apache combined. Can also carry the request body as an
  extra last field, or X-Forwarded-For.
- `vhost`: Apache vhost_combined
- `common`: Nginx/Apache common
- `w3c`: IIS / W3C extended logs (with a `#Fields:` header)
- `alb`: AWS load balancer logs
- `json`: one JSON object per line (Nginx, Caddy, Google Cloud, ...)

The format is detected automatically. Files can be UTF-8 or UTF-16.

Limitation: if a log has no request bodies, attacks inside POST bodies cannot
be seen.

### 7. Run the tests

```powershell
python -m pytest tests/
```

The tests use a fake model, so they run without `models/detector.joblib`.
They need `pytest` and `httpx`.

## Team

- Mostafa Safi Mostafa Soliman
- Mostafa El-Hassanein El-Hassanein El-Shaarawy
- Mariam Mohamed Mansour

Instructor: Dr. Sara El-Metwally · TA: Eng. Asmaa Nagib