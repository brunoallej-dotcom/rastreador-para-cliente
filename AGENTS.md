# AGENTS.md — Rastreador para Cliente

Instruções para qualquer agente de código (Claude Code, Codex, Cursor…) e para humanos. As
regras específicas do Claude Code estão em `CLAUDE.md`, que importa este arquivo.

## O projeto

Portal onde cada cliente acompanha as fases da própria entrega, e os 4 CEOs acompanham todos os
clientes e avançam fases com um "Ok". **Fase atual: só backend e banco de dados.**

| Documento | Papel |
|-----------|-------|
| [`docs/specs/client-delivery-tracker.md`](docs/specs/client-delivery-tracker.md) | Spec: requisitos (RF, RNF, SEC), design, modelo de dados, critérios de aceite (AC) |
| [`contracts/openapi.v1.yaml`](contracts/openapi.v1.yaml) | Contrato da API: **fonte da verdade** dos endpoints |
| [`docs/plan/implementation-waves.md`](docs/plan/implementation-waves.md) | Roadmap por ondas (fonte da verdade do status) |
| [`docs/security/threat-model.md`](docs/security/threat-model.md) | STRIDE + OWASP Top 10:2025 + API Top 10:2023 |
| [`docs/adr/`](docs/adr/) | Decisões arquiteturais (formato Nygard) |
| [`NOTES.md`](NOTES.md) | Status atual, pendências e log de sessões |

**Estado em 2026-11-15:** especificação concluída; ainda **não há código**. Os comandos abaixo
nascem na Onda 0.

## Stack

Next.js 16+ (App Router, Route Handlers, runtime Node.js) · TypeScript strict · Supabase
(Postgres + Auth, `sa-east-1`) · Vercel (`gru1`) · Zod · `@supabase/ssr` · pino · Vitest · pgTAP ·
Redocly · pnpm. Tailwind entra com o frontend.

## Estrutura

```
contracts/openapi.v1.yaml          contrato da API
docs/{specs,plan,adr,security}/    documentação (pt-BR); docs/how-to/ etc. quando houver conteúdo
supabase/
  config.toml                      Auth endurecido (sem signup, JWT 15 min, TOTP)
  migrations/                      imutáveis depois de mergeadas na main
  tests/                           pgTAP (RLS, funções, invariantes)
  seed.sql                         só dados locais
scripts/                           operações manuais (ex.: create-ceo.ts)
src/
  app/api/v1/**/route.ts           adaptadores finos: só reexportam o handler do módulo
  modules/
    identity/                      autenticação, sessão, senha, MFA, logins de cliente
    tracking/                      clientes, processos, fases, aprovações, linha do tempo
      domain/ application/ infrastructure/ presentation/ index.ts
  shared/
    http/                          withRoute (pipeline seguro), problem+json, paginação, rate limit
    db/                            clients Supabase server-only + database.types.ts (gerado)
    observability/                 logger (pino), request id
    config/                        env validado por Zod
    kernel/                        Result, erros base, Clock
tests/
  api/                             testes HTTP por endpoint (*.api.test.ts)
  helpers/                         fixtures, http, contract, mfa… (um arquivo por onda)
```

Testes unitários ficam ao lado do código (`*.test.ts`); integração usa `*.int.test.ts`.

## Comandos (criados na Onda 0)

| Comando | O que faz |
|---------|-----------|
| `pnpm install --frozen-lockfile` | Instala as dependências |
| `pnpm dev` | Servidor Next.js local |
| `pnpm lint` / `pnpm format` / `pnpm format:check` | ESLint (inclui fronteiras de módulo) / Prettier |
| `pnpm typecheck` | `tsc --noEmit` |
| `pnpm test` | Testes unitários (sem I/O) |
| `pnpm test:int` | Integração (requer `pnpm db:start`) |
| `pnpm test:api` | Testes HTTP dos handlers contra o Supabase local |
| `pnpm db:start` / `pnpm db:stop` / `pnpm db:status` | Supabase local (Docker) |
| `pnpm db:reset` | Recria o banco **local** (migrations + seed) |
| `pnpm db:test` / `pnpm db:lint` | pgTAP / `supabase db lint` |
| `pnpm db:types` | Gera `src/shared/db/database.types.ts` |
| `pnpm db:new <nome>` | Nova migration com timestamp |
| `pnpm contract:lint` | Lint do contrato OpenAPI (Redocly) |
| `pnpm verify` | lint + typecheck + test + contract:lint + db:test |
| `pnpm ceo:create --email … --name …` | Cria conta de CEO (operação manual; usa a secret key do ambiente alvo) |

## Fluxo de trabalho

1. **Spec antes de código.** Comportamento novo ou alterado → atualize a spec primeiro.
2. **Contrato antes do handler.** Endpoint novo ou alterado → `contracts/openapi.v1.yaml` primeiro.
   Mudança aditiva: bump minor de `info.version`. Mudança incompatível: `/api/v2` + nota de
   compatibilidade.
3. **Uma onda por branch e PR:** `feat/wave-<n>-<slug>`, Conventional Commits em inglês, squash merge.
4. **Ordem dentro do slice:** spec → contrato → domain → application → infrastructure →
   presentation → testes.
5. **Fechar a onda** só com os critérios de aceite verificados por comando; então marque ✅ no
   plano **e** no `NOTES.md`.
6. Decisão arquitetural nova → ADR em `docs/adr/` (numeração sequencial).

## Arquitetura (regras)

- `domain/` não importa nada de fora dele, exceto `shared/kernel`. Sem I/O.
- `application/`: um arquivo por caso de uso; depende de ports declarados em `domain/`; devolve
  `Result<T, DomainError>`.
- `infrastructure/` implementa os ports; valida com Zod tudo o que vem do Supabase.
- Módulos só se falam pelo `index.ts`. `identity` pode usar `tracking/index.ts`; **`tracking`
  nunca importa `identity`**.
- `route.ts` só reexporta handler (`export { handler as POST } from '@/modules/...'`) e declara
  `runtime = 'nodejs'`. Não importa `@supabase/*` nem `@/shared/db`.
- Sem container de DI compartilhado: cada handler monta as próprias dependências.
- Leituras do painel do cliente usam um query service separado do repositório do agregado.

## Segurança (inegociável)

Referência completa: spec §2.3 (SEC-01 a SEC-20) e threat model.

- **Deny by default:** toda rota usa `withRoute(policy, …)` com política explícita e igual ao
  `x-auth-policy` do contrato. Públicas: só `GET /health` e `POST /auth/login`.
- **Ordem fixa:** transporte (Origin, Content-Type, tamanho) → rate limit → autenticação →
  autorização → validação → caso de uso.
- **Tenant vem da sessão**, nunca de path, query ou body. Recurso de outro tenant → **404**.
- **Sem SQL no app.** Só `supabase.from(...)` e `supabase.rpc(...)`. Proibido interpolar input em
  `.or()`, `.filter()` e `.textSearch()`. Zod `.strict()` em todo objeto de entrada.
- **Banco:** RLS em toda tabela de `public`; policies só `FOR SELECT`; nenhum `GRANT` para
  `anon`; nenhum `INSERT/UPDATE/DELETE` para `authenticated`; escrita só por função
  `SECURITY DEFINER` com `SET search_path = ''`, nomes qualificados, checagem de papel e tenant e
  `REVOKE EXECUTE … FROM PUBLIC, anon`.
- **Autorização** nunca lê `user_metadata`; o papel vem de `profiles` (criado a partir de
  `app_metadata`).
- **Segredos:** nenhuma variável do Supabase usa o prefixo público do Next.js. A secret key é
  lida só em `src/shared/db/admin-client.ts` (`import 'server-only'`) e em `scripts/`. Nunca leia
  nem edite `.env`/`.env.local`; só `.env.example` (placeholders) é versionado.
- **Servidor valida JWT** com `getClaims()`/`getUser()`; `auth.getSession()` é proibido no servidor.
- **Erros:** `application/problem+json` com `code` do catálogo; sem stack, SQL ou mensagem do
  Supabase. Exceção em checagem de segurança → nega (fail closed).
- **Logs:** pino JSON com `requestId`; proibido `console.*` em `src/`; sem PII (e-mail, senha,
  tokens, cookies).
- Nenhum endpoint cria ou promove CEO.

## Banco de dados

- Migration nova: `pnpm db:new <nome_snake_case>`. **Nunca edite migration já mergeada na main**;
  corrija com uma nova.
- Toda tabela, policy ou função nova vem com teste pgTAP no mesmo PR: cross-tenant, `anon`,
  sessão `aal1` para funções de CEO e escrita direta negada.
- SQL: keywords em MAIÚSCULAS, identificadores em `snake_case`, sem `SELECT *` (exceto
  `RETURNING *` em `%ROWTYPE`), `ORDER BY` sempre que houver `LIMIT`, índices com comentário do
  caso de uso.
- Depois de mudar o schema: `pnpm db:reset && pnpm db:test && pnpm db:lint && pnpm db:types`.

## Testes

- Pirâmide: muito unit (`domain/`, `application/` ≥ 80% de cobertura), integração onde há I/O,
  API por endpoint, pgTAP para todo objeto de banco.
- **Testes de aceite levam o ID no nome:** `it('AC-17: concurrent approvals …')`. Os goal commands
  das ondas contam por esses IDs.
- Todo teste de API valida a resposta contra o contrato (`expectToMatchContract`).
- Determinísticos: sem `sleep`, sem rede externa, UUIDs fixos em fixtures, banco resetado.
- Fakes in-memory em vez de mocks do domínio; mocks só nas bordas.

## Código

- TypeScript `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`; sem `any` sem
  justificativa comentada.
- Código, identificadores e commits em **inglês**; documentação em **pt-BR**.
- Imports absolutos com `@/`. Early return. Constantes nomeadas (sem números mágicos).
- `TODO` só com referência: `// TODO(@user, #123): …`.

## Nunca

- Commitar segredos ou ler arquivos `.env` reais.
- Criar endpoint fora do contrato ou com política diferente do `x-auth-policy`.
- Usar a secret key para contornar RLS em leitura ou escrita de negócio.
- Desligar RLS, criar policy de escrita ou dar privilégio de escrita a `authenticated`.
- Editar migration mergeada.
- `git push --force` em branch compartilhada; deploy fora do pipeline.
- Rodar comando contra o Supabase **remoto** (`db push`, `db reset --linked`, `config push`) sem
  pedido explícito do usuário.
