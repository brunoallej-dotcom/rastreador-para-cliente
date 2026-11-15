# NOTES — Rastreador para Cliente

Diário do projeto: status atual, pendências e log de sessões. Atualize ao fim de cada sessão.

## Status atual

- **Fase:** especificação concluída (2026-11-15). Implementação não iniciada.
- **Paralelismo:** o plano define quais ondas rodam em subagente (Sonnet 5.5, esforço xhigh,
  worktree) e os pré-requisitos, resolvidos nas ondas 0 e 1. Ver "Sequência de execução" e
  "Pré-requisitos do paralelismo com subagentes" em `docs/plan/implementation-waves.md`.
- **Próxima onda:** 0 — Fundação (`/run-wave 0`).
- **Fonte da verdade do roadmap:** [`docs/plan/implementation-waves.md`](docs/plan/implementation-waves.md).
  Esta tabela espelha a coluna Status de lá.

| Onda | Entrega | Depende de | Paralela com | Status |
|------|---------|------------|--------------|--------|
| 0 | Fundação: scaffold, tooling, CI, Supabase CLI, env, kernel | — | — | ⬜ |
| 1 | Plataforma HTTP: `withRoute`, erros, logs, headers, paginação, health, validador de contrato | 0 | 2 | ⬜ |
| 2 | Banco: schema, RLS, funções de identidade, auditoria, rate limit, pgTAP | 0 | 1 | ⬜ |
| 3 | Identidade: login, logout, sessão, rate limit real | 1, 2 | — | ⬜ |
| 4 | Identidade: troca de senha obrigatória + script `ceo:create` | 3 | 5, 6 | ⬜ |
| 5 | Identidade: MFA TOTP obrigatório para CEOs | 3 | 4 | ⬜ |
| 6 | Rastreamento: clientes (CRUD de CEO) | 5 | 4 | ⬜ |
| 7 | Identidade: logins de cliente (provisionar, listar, desativar, resetar senha) | 4, 6 | 8 | ⬜ |
| 8 | Rastreamento: processos e fases (criar, listar, detalhar, renomear e cancelar, template) | 6 | 7 | ⬜ |
| 9 | Rastreamento: aprovação de fase ("Ok") + linha do tempo | 8 | 10 | ⬜ |
| 10 | Painel do cliente: leitura dos próprios processos | 8 | 9 | ⬜ |
| 11 | Hardening e go-live | 7, 9, 10 | — | ⬜ |

Legenda: ⬜ não iniciada · 🟡 em andamento · ✅ concluída

## Pendências do usuário

| Pendência | Bloqueia |
|-----------|----------|
| Revisar e aceitar os ADRs 0001–0005 (`docs/adr/`) | fechamento da Onda 0 |
| Q-01: nomes das fases padrão (spec §8) | seed do template na Onda 2 (há placeholder) |
| Instalar pnpm (`corepack enable`) e Docker (Supabase local) | Onda 0 |
| Ativar branch protection na `main` (o repositório remoto já existe) e restringir o merge a squash | CI da Onda 0 |
| Criar projetos Supabase **dev/staging** e **prod** em `sa-east-1` (prod no plano Pro) | Onda 3 (staging); Onda 11 (prod) |
| Para o MCP: `export SUPABASE_PROJECT_REF=<ref do projeto DEV>` antes de abrir o Claude Code e autenticar em `/mcp` | uso do MCP |
| Alinhar os nomes em `.env.local` com `.env.example` (nenhuma chave Supabase com prefixo público do Next.js) | Onda 3 |
| Q-07 (retenção) e Q-12 (domínio) | Onda 11 |

## Observações

- `venv/` (Python) existe na raiz, mas não é usado por este projeto (ignorado pelo git).
- O guardrail de segredos do ambiente bloqueia ler `.env.*`; o conteúdo de `.env.local` não foi
  inspecionado.

## Log de sessões

### 2026-11-15 — Especificação e estrutura do agente

- Spec SDD: `docs/specs/client-delivery-tracker.md` (RF-01..15, RNF-01..08, SEC-01..20,
  AC-01..31, E-01..30, Q-01..12).
- Contrato `contracts/openapi.v1.yaml` (OpenAPI 3.1, 24 operações, `x-auth-policy` e
  `x-rate-limit` por operação).
- Threat model (STRIDE + OWASP Top 10:2025 + API Top 10:2023), ADRs 0001–0005 (`proposed`) e
  plano de 12 ondas.
- `.claude/`: agents `rls-auditor` e `contract-guardian`; skills `run-wave`, `new-endpoint`,
  `new-migration` e `tenant-isolation-tests`; hooks `session-context`, `guard-writes`,
  `post-edit-checks` e `stop-gates`, registrados em `settings.json`.
- `.mcp.json` (Supabase read-only, por projeto), `.env.example` (só placeholders) e entradas novas
  no `.gitignore`.
- Validação: 178 checagens estruturais e de comportamento dos hooks passaram; contrato validado
  com `@redocly/cli@2.72.1 lint` (regras recomendadas): válido, sem avisos.

### 2026-11-15 — Estratégia de paralelismo com subagentes

- Spec, contrato, plano e configuração do Claude Code mergeados na `main` (PR #1).
- Análise de quais ondas podem rodar em subagente e quais são obrigatoriamente sequenciais. O
  grafo do plano se manteve: 12 ondas em 8 passos, caminho crítico 0 → 2 → 3 → 5 → 6 → 8 → 9 → 11.
- Plano atualizado (PR #2):
  - sequência de execução e quem executa cada onda (2, 3, 5 e 9 na sessão principal; 1, 4, 6,
    7, 8 e 10 em subagente);
  - pré-requisitos na Onda 0 (hooks em worktree e `stop-gates.mjs` em `SubagentStop`, env de
    teste via `supabase status`, dependências pré-instaladas, regra do ESLint para `route.ts`);
  - pré-requisitos na Onda 1 (catálogo `ErrorCode` completo, handler monta as próprias
    dependências, `rateLimit` por rota);
  - gates de banco em fila (um único Supabase local) e restrição a agentes fora do Claude Code.
- Não verificado: os hooks podem pular as checagens em worktree, porque `lib.mjs` prefere
  `CLAUDE_PROJECT_DIR`. O critério de aceite da Onda 0 cobre esse caso.
- Fora do plano por ora: mover `tests/helpers/mfa.ts` para a Onda 3 (deixaria 4, 5 e 6
  paralelas).
