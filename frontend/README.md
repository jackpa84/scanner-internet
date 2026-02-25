# Dashboard — Next.js + Tailwind

Frontend do Scanner de Internet em Next.js 14 (App Router) com Tailwind CSS e tema escuro.

## Pré-requisitos

- Node.js 18+ e npm (ou pnpm/yarn)
- Backend FastAPI rodando (ex.: `http://localhost:5000`)

## Instalação e execução

```bash
cd frontend
npm install
npm run dev
```

Acesse [http://localhost:3000](http://localhost:3000).

## Variáveis de ambiente

Crie `.env.local` na pasta `frontend`:

```env
# URL da API FastAPI (padrão: http://localhost:5000)
NEXT_PUBLIC_API_URL=http://localhost:5000
```

## Build para produção

```bash
npm run build
npm start
```

## CORS

O backend FastAPI deve permitir a origem do frontend. Em desenvolvimento o FastAPI já aceita `http://localhost:3000`. Em produção, defina `FRONTEND_ORIGIN` no ambiente do Flask (ex.: `https://seu-dominio.com`).
