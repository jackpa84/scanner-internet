FROM python:3.10-slim AS builder

WORKDIR /app

RUN pip install poetry

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

FROM python:3.10-slim

ARG TARGETARCH

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

RUN apt-get update \
    && apt-get install -y --no-install-recommends masscan nmap wget unzip dnsutils curl \
    && NUCLEI_VERSION=$(wget -qO- "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" \
       | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_${TARGETARCH}.zip" \
       -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -ut -silent \
    && SUBFINDER_VERSION=$(wget -qO- "https://api.github.com/repos/projectdiscovery/subfinder/releases/latest" \
       | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    && wget -q "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_${TARGETARCH}.zip" \
       -O /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip \
    && HTTPX_VERSION=$(wget -qO- "https://api.github.com/repos/projectdiscovery/httpx/releases/latest" \
       | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    && wget -q "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_${TARGETARCH}.zip" \
       -O /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip \
    && apt-get purge -y wget unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY tools/bug-scraper.py /opt/Bug_Scraper/bug-scraper.py

COPY app/ ./app/

ENV MONGODB_URI=mongodb://user:password@db:27017/scanner_db?authSource=admin
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]
