FROM python:3.12-slim

LABEL maintainer="Yuvraj Todankar <yuvraj@cybevion.com>"
LABEL description="VulnLab — Intentionally Vulnerable Web App for Security Training"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create upload directory
RUN mkdir -p /tmp/vulnlab_uploads

EXPOSE 5000

ENV FLASK_ENV=development
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
