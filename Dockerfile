FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt && useradd --uid 10001 --create-home siem
COPY --chown=10001:10001 *.py ./
COPY --chown=10001:10001 ops ./ops
COPY --chown=10001:10001 static ./static
RUN mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/ready', timeout=3)"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--timeout-graceful-shutdown", "40", "--limit-concurrency", "100"]
