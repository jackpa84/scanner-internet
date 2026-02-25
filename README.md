# Scanner de Internet

Este projeto realiza varreduras aleatórias de IPs públicos, consulta o serviço gratuito InternetDB (Shodan) para obter portas abertas e vulnerabilidades, e armazena **apenas os resultados OK** (com portas ou vulnerabilidades) em MongoDB. Há **6 instâncias de varredura** em paralelo. Para IPs com portas comuns, tenta identificar serviços de roteadores (HTTP, HTTPS, SSH, Telnet) e exibe as informações em um dashboard web.

## Funcionalidades

- Geração aleatória de IPs públicos.
- Consulta ao InternetDB (https://internetdb.shodan.io) para cada IP.
- **Somente grava no banco quando o Shodan retorna OK** (dados com portas ou vulnerabilidades).
- **6 workers de varredura** rodando em paralelo.
- Armazenamento em **MongoDB**.
- Detecção adicional de serviços em portas comuns de roteadores (80, 443, 8080, 8443, 22, 23) com captura de banners/títulos.
- Dashboard web com estatísticas e listagem dos últimos 100 IPs encontrados, com detalhes dos serviços de roteador.

## Tecnologias

- **Backend:** Python 3.10, Poetry, FastAPI, Uvicorn, PyMongo, MongoDB, Docker
- **Frontend:** Next.js 14 (App Router), Tailwind CSS, TypeScript, Chart.js

## Como executar

### Backend (API + scanner)

1. Certifique-se de ter Docker e Docker Compose instalados.
2. No diretório raiz:

   ```bash
   docker-compose up --build
   ```

   A API fica em `http://localhost:5000`.

### Frontend (Next.js + Tailwind)

1. Node.js 18+ e npm instalados.
2. No diretório `frontend`:

   ```bash
   cd frontend && npm install && npm run dev
   ```

   Acesse [http://localhost:3000](http://localhost:3000). Configure `NEXT_PUBLIC_API_URL=http://localhost:5000` em `frontend/.env.local` se a API estiver em outra URL. O FastAPI já envia CORS para `http://localhost:3000` em desenvolvimento.
