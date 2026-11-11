FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd -g 10001 ixsoar \
    && useradd -u 10001 -g 10001 -d /app ixsoar

COPY ix_collector ./ix_collector

USER 10001:10001

ENTRYPOINT ["python", "-m", "ix_collector.app"]`