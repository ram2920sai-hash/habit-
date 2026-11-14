FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 NEXO_DATA_DIR=/app/data
WORKDIR /app
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt && useradd --uid 10001 --create-home nexo && mkdir /app/data && chown nexo:nexo /app/data
COPY --chown=nexo:nexo server.py database.py ./
COPY --chown=nexo:nexo certs ./certs
COPY --chown=nexo:nexo static ./static
USER nexo
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000} --no-proxy-headers"]
