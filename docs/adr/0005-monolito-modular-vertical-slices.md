# ADR 0005 — Monolito modular com vertical slices e camadas DDD

- **Status:** accepted
- **Data:** 2026-11-15

## Contexto

O sistema é pequeno e tem um único time e um único deploy. Mesmo assim, há dois assuntos com
regras e riscos diferentes: **identidade** (autenticação, senha, MFA, contas) e **rastreamento**
(clientes, processos, fases, aprovações). Misturá-los em pastas por camada técnica (`services/`,
`controllers/`) tende a acoplar tudo e dificulta revisar segurança por feature.

## Decisão

- **Monolito modular** em `src/modules/`, com dois bounded contexts: `identity` e `tracking`.
- Cada módulo tem `domain/`, `application/` (um arquivo por caso de uso), `infrastructure/` e
  `presentation/` (schemas Zod, mappers de DTO e handlers), além de um **`index.ts` como API
  pública**.
- `src/app/api/v1/**/route.ts` são adaptadores finos que só reexportam handlers; não importam
  `@supabase/*` nem `@/shared/db`.
- `src/shared/` concentra a infraestrutura transversal: `http` (pipeline `withRoute`), `db`,
  `observability`, `config` e `kernel`.
- Fronteiras aplicadas pelo ESLint (`no-restricted-imports` ou `eslint-plugin-boundaries`):
  - `domain` não importa de fora (exceto `shared/kernel`);
  - um módulo só importa outro pelo `index.ts`;
  - `identity` conhece `clientId` apenas como id opaco.
- Leituras do painel do cliente usam um **query service** separado do repositório do agregado
  (CQRS leve), para que ondas paralelas não editem os mesmos arquivos.

## Consequências

- **Positivas:** revisão de segurança por slice; ondas paralelas sem conflito (ver
  `docs/plan/implementation-waves.md`); extração futura possível sem reescrita.
- **Negativas:** mais arquivos e alguma cerimônia para um sistema pequeno; mitigado pelas skills
  `new-endpoint` e `new-migration`.
