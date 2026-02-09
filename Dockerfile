FROM python:3.11-slim

ARG VERSION=dev
ENV VERSION=$VERSION

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Initialize database on first run
RUN python -c "from app import init_db; init_db()"

EXPOSE 5090

CMD ["python", "app.py"]
