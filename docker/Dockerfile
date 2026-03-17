FROM python:3.12-slim

WORKDIR /app

# System dependencies for WeasyPrint (PDF) + fontconfig
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
    libcairo2 libffi-dev fontconfig \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Install Sarabun Thai fonts for WeasyPrint PDF
RUN mkdir -p /usr/local/share/fonts/sarabun \
    && cp static/fonts/sarabun/*.ttf /usr/local/share/fonts/sarabun/ \
    && fc-cache -fv

EXPOSE 8000

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]
