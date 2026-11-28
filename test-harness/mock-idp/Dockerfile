FROM python:3.12-slim

RUN pip install --no-cache-dir "cryptography>=42"

WORKDIR /app
COPY app.py .

EXPOSE 8443
CMD ["python", "-u", "app.py"]
