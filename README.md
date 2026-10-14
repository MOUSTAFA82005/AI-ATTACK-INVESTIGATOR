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

## Run the app

```powershell
uvicorn backend.app.main:app --reload
```

Open http://127.0.0.1:8000 and upload a log file.

## Team

- Mostafa Safi Mostafa Soliman
- Mostafa El-Hassanein El-Hassanein El-Shaarawy

Instructor: Dr. Sara El-Metwally · TA: Eng. Asmaa Nagib
