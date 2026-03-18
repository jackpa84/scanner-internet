FROM python:3.10-slim AS builder

WORKDIR /app

RUN pip install --no-cache-dir poetry arjun

RUN apt-get update && apt-get install -y --no-install-recommends gcc python3-dev && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --without dev

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
    # --- katana (web crawler) ---
    && KATANA_VERSION=$(wget -qO- "https://api.github.com/repos/projectdiscovery/katana/releases/latest" \
       | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    && wget -q "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VERSION#v}_linux_${TARGETARCH}.zip" \
       -O /tmp/katana.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/katana \
    && rm /tmp/katana.zip \
    # --- dnsx (DNS toolkit) ---
    && DNSX_VERSION=$(wget -qO- "https://api.github.com/repos/projectdiscovery/dnsx/releases/latest" \
       | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    && wget -q "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VERSION}/dnsx_${DNSX_VERSION#v}_linux_${TARGETARCH}.zip" \
       -O /tmp/dnsx.zip \
    && unzip -o /tmp/dnsx.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/dnsx \
    && rm /tmp/dnsx.zip \
    # --- gau (GetAllUrls) ---
    && GAU_VERSION=$(wget -qO- "https://api.github.com/repos/lc/gau/releases/latest" \
       | grep '"tag_name"' | head -1 | cut -d'"' -f4) \
    && wget -q "https://github.com/lc/gau/releases/download/${GAU_VERSION}/gau_${GAU_VERSION#v}_linux_${TARGETARCH}.tar.gz" \
       -O /tmp/gau.tar.gz \
    && tar -xzf /tmp/gau.tar.gz -C /usr/local/bin/ gau \
    && chmod +x /usr/local/bin/gau \
    && rm /tmp/gau.tar.gz \
    && apt-get purge -y wget unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache

COPY tools/bug-scraper.py /opt/Bug_Scraper/bug-scraper.py

COPY app/ ./app/

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONOPTIMIZE=2

EXPOSE 5000

# Atualiza templates nuclei no startup (evita OOM no build)
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]
