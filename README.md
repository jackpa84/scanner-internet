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

### MongoDB (em outro host)

O banco **não** roda no Docker deste projeto; fica em **outro host** (servidor, nuvem, etc.). No `.env` da raiz do projeto configure:

```env
MONGODB_URI=mongodb://USUARIO:SENHA@IP_OU_HOSTNAME:27017/admin?authSource=admin
```

Substitua `USUARIO`, `SENHA` e `IP_OU_HOSTNAME` pelo usuário/senha do MongoDB e pelo IP ou hostname da máquina onde o MongoDB está. No host do MongoDB, libere a **porta 27017** no firewall para o IP de onde o app (Docker ou máquina) vai conectar.

### Redis (armazenamento primário)

O **Redis** é o storage principal para todos os dados operacionais (scan results, vulnerabilidades, programas bounty, targets, changes, stats). O MongoDB é **opcional** — usado apenas para persistir relatórios finais para envio ao HackerOne.

O Redis roda via Docker com:
- **512 MB** de memória
- **Persistência AOF** (append-only file) para sobreviver a restarts
- Volume `redis_data` para persistir dados em disco

Variáveis:
- `REDIS_URL`: URL do Redis (no compose: `redis://redis:6379/0`).

### Backend (API + scanner)

1. Certifique-se de ter Docker e Docker Compose instalados.
2. No diretório raiz:

   ```bash
   docker-compose up --build
   ```

   A API fica em `http://localhost:5001`. O Redis sobe primeiro (healthcheck), depois o app. O MongoDB é tentado com timeout de 5s — se estiver offline, o app opera 100% com Redis.

### Frontend (Next.js + Tailwind)

1. Node.js 18+ e npm instalados.
2. No diretório `frontend`:

   ```bash
   cd frontend && npm install && npm run dev
   ```

   Acesse [http://localhost:3000](http://localhost:3000). Configure `NEXT_PUBLIC_API_URL=http://localhost:5001` em `frontend/.env.local` se a API estiver em outra URL. O FastAPI já envia CORS para o front em desenvolvimento.

## Como usar para ganhar dinheiro com HackerOne

1. **Ver escopo no HackerOne** — Na página do programa (Scope), anote ativos In scope + Eligible.
2. **Cadastrar programa** — No app, **Programas** → **+ Novo Programa** (nome, HackerOne, URL do programa, in_scope) ou **Importar CSV**.
3. **Descobrir alvos** — Clique em **Recon**; espere terminar e expanda o programa para ver **targets** e a coluna **Checks**.
4. **Priorizar** — Use o **Plano de Caça** (top 5 por risco) e o filtro **somente HIGH**; opcional: **Exportar top-targets**.
5. **Validar** — **Abrir** o target, reproduzir o bug sem sair do escopo.
6. **Enviar** — **Template** (revisar) e **Enviar ao H1** quando o botão habilitar (exige ao menos 1 finding com título e evidência).
7. **Receber** — No HackerOne: triagem, aceite e pagamento conforme a tabela Rewards do programa.

Configure `HACKERONE_API_USERNAME` e `HACKERONE_API_TOKEN` no `.env` (raiz do projeto) para enviar reports direto pelo botão **Enviar ao H1**.

## Coletar informações de jobs/reports pela API HackerOne

Com as mesmas credenciais (`HACKERONE_API_USERNAME` e `HACKERONE_API_TOKEN` no `.env`), a API do projeto expõe endpoints que repassam dados da [Hacker One Hacker API](https://api.hackerone.com/getting-started-hacker-api):

| Endpoint (backend) | Descrição |
|-------------------|-----------|
| `GET /api/hackerone/reports` | Lista os **reports** (submissões) do hacker. Paginação: `page_size`, `page_before`, `page_after`. |
| `GET /api/hackerone/earnings` | Lista os **earnings** (bounties recebidos). Mesma paginação. |
| `GET /api/hackerone/programs` | Lista os **programas** disponíveis para o hacker. Mesma paginação. |
| `GET /api/hackerone/me` | Testa credenciais e retorna quantidade de programas. |

**Exemplos (curl):**

```bash
# Seus reports (últimos 25)
curl -s -u "$HACKERONE_API_USERNAME:$HACKERONE_API_TOKEN" "http://localhost:5001/api/hackerone/reports?page_size=25"

# Seus earnings (bounties)
curl -s -u "$HACKERONE_API_USERNAME:$HACKERONE_API_TOKEN" "http://localhost:5001/api/hackerone/earnings?page_size=50"
```

As respostas seguem o padrão [JSON:API](https://jsonapi.org/) da HackerOne: `data` (lista de objetos) e `links.next` / `links.prev` com cursores para paginação.

**No frontend** (após login), use as funções em `frontend/lib/api.ts`:

- `fetchHackerOneReports({ page_size: 25 })` — reports
- `fetchHackerOneEarnings({ page_size: 50 })` — earnings
- `fetchHackerOnePrograms({ page_size: 100 })` — programas

Limites da HackerOne: leitura 600 req/min; escrita 25 req/20s. Em caso de 429, aguarde e reduza a frequência de chamadas.

## Troubleshooting

### 1. `MongoDB unreachable: ... timed out`

O app não consegue conectar ao MongoDB configurado no `.env` (`MONGODB_URI`). O banco fica em **outro host**, não no Docker do projeto.

**Causas comuns:**

- No **host do MongoDB:** serviço parado, IP/hostname errado no `MONGODB_URI`, ou **firewall/Security Group** não libera a porta **27017** para o IP de onde o app conecta (o IP do seu PC ou do servidor onde o Docker roda).
- Na rede de onde o app roda: provedor ou firewall bloqueia saída na porta 27017.

**Como corrigir:**

1. **No host do MongoDB:**  
   - Confirme que o MongoDB está rodando e escutando em `0.0.0.0:27017` (ou no IP correto).  
   - Libere a porta **27017** no firewall (ou no Security Group, se for nuvem) para o **IP de origem** de onde o `scanner_app` faz a conexão (ex.: IP do seu roteador ou do servidor onde o Docker está).

2. **No `.env`:**  
   Use o IP ou hostname do outro host e credenciais corretas:
   ```env
   MONGODB_URI=mongodb://usuario:senha@IP_DO_HOST_MONGO:27017/admin?authSource=admin
   ```
   Em senhas com `@`, use `%40` no lugar (ex.: `senha@123` → `senha%40123`).

3. **Testar conectividade:**  
   No mesmo ambiente de onde o app roda (PC ou servidor):
   ```bash
   nc -zv IP_DO_HOST_MONGO 27017
   ```
   ou
   ```bash
   docker exec scanner_app python -c "import socket; s=socket.create_connection(('IP_DO_HOST_MONGO', 27017), 5); s.close(); print('OK')"
   ```
   Se falhar, o bloqueio está na rede ou no firewall do host do MongoDB.

---

### 2. `[FEED] ... erro: ... Connection ... timed out` (Emerging Threats, Azure, Spamhaus, etc.)

O container tenta baixar listas de IPs de sites externos (rules.emergingthreats.net, microsoft.com, spamhaus.org, etc.) e a conexão expira.

**Causas comuns:**

- Container **sem saída para a internet** (rede isolada, proxy corporativo, firewall).
- Firewall ou proxy **bloqueando** esses domínios.
- Instabilidade temporária de rede ou dos serviços.

**Como corrigir:**

1. **Garantir internet no container:**  
   Teste de dentro do container:
   ```bash
   docker exec scanner_app curl -sI https://rules.emergingthreats.net
   ```
   Se falhar, ajuste rede/DNS/proxy do Docker ou da máquina.

2. **Desativar os feeds externos:**  
   Se não precisar dessas listas (ex.: só usar bounty/dados locais), desative os feeds no `.env`:
   ```env
   FEED_ENABLED=false
   ```
   O app sobe sem tentar baixar Azure, Spamhaus, Emerging Threats, etc. O scanner continua rodando; a fila de IPs pode ficar vazia ou ser alimentada só por outras fontes (ex.: bounty).

3. **Ignorar os erros:**  
   Esses erros são apenas avisos; o app não cai. Se a internet for instável, os feeds falham e voltam a tentar no próximo ciclo (ex.: a cada 30 min).
