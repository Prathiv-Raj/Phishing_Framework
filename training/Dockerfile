FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY static ./static

ENV PORT=9090 \
    TRAINING_DB_PATH=/data/training/training_status.db

RUN mkdir -p /data/training

EXPOSE 9090

CMD ["gunicorn", "--bind", "0.0.0.0:9090", "--workers", "2", "--timeout", "120", "app:app"]
