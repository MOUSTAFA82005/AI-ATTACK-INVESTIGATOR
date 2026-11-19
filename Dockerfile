# Hosted demo image (Hugging Face Spaces, Docker SDK). Runs the same app as on a laptop.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AAI_BEHIND_PROXY=1 \
    AAI_DB=/data/app.db

RUN useradd -m -u 1000 app && mkdir -p /data && chown app /data
WORKDIR /home/app/site

COPY deploy/requirements.txt deploy/requirements.txt
RUN pip install --no-cache-dir -r deploy/requirements.txt

# Code and the frozen v10 models only: no data, results, notebooks or old model versions.
COPY --chown=app backend backend
COPY --chown=app ml ml
COPY --chown=app frontend frontend
COPY --chown=app models/detector.joblib models/attack_type.joblib models/context.joblib \
     models/stage.joblib models/block_rules.joblib models/next_step.json models/

USER app
EXPOSE 7860
# AAI_BEHIND_PROXY=1: the Space sits behind one HTTPS proxy (real client address, Secure cookie).
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "7860", "--no-server-header"]
