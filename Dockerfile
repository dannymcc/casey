FROM python:3.11-slim

ARG VERSION=dev
ENV VERSION=$VERSION

RUN adduser --disabled-password --gecos '' appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data && chown -R appuser:appuser /app

USER appuser

EXPOSE 5090

CMD ["gunicorn", "--bind", "0.0.0.0:5090", "--workers", "4", "--timeout", "30", "--access-logfile", "-", "app:app"]
