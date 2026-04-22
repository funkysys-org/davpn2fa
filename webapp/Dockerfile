FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    easy-rsa \
    libpam-google-authenticator \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Match the symlink used by the openvpn container
RUN ln -sf /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
