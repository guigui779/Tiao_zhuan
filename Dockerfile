FROM python:3.11-slim
WORKDIR /app
COPY . .
CMD ["python", "manage_domains.py", "serve-admin"]
