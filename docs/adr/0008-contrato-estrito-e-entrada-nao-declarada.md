# ADR 0008 — Contrato como teto de respostas: entrada não declarada é ignorada

- **Status:** proposed
- **Data:** 2026-11-16

## Contexto

O `contract-guardian` apontou, na Onda 1, que o pipeline podia produzir respostas que o contrato
não documenta: 400/413/415 para corpo enviado a rotas sem corpo (`logout`, `enrollTotp`,
`resetClientUserPassword`), 400 para query desconhecida em rotas sem query (`getHealth`) e 503 de
falha do limitador em operações que não listam 503. O validador de contrato dos testes
(`expectToMatchContract`) reprova status não documentado. O usuário decidiu **não** alterar o
contrato `1.0.0-draft.1`.

## Decisão

- Rota sem schema de corpo **não lê** o corpo: nada de 400/413/415 por um corpo que ela não usa.
  A checagem de `Origin` (403, documentado) continua em todo método não seguro.
- Rota sem schema de query ignora parâmetros desconhecidos. Rotas com schema seguem `.strict()`.
- O grupo de rate limit `health` usa um limitador em memória por instância: um banco fora do ar
  não transforma o liveness probe num 503 não documentado.
- Falhas de infraestrutura (limitador ou Supabase indisponíveis, E-21/E-22) continuam negando com
  503, como manda a spec, mesmo onde o contrato não lista 503; esses casos não passam pelo
  validador de contrato nos testes.
- Grupos de rate limit são nomeados (`login`, `totp-enroll`, `totp-verify`, `password-change`,
  `client-user-admin`, `writes`, `reads`, `health`), com `limit`/`windowSeconds` iguais ao
  `x-rate-limit` de cada operação.

## Consequências

- **Positivas:** o contrato continua sendo o teto das respostas por entrada do cliente; nenhuma
  mudança de contrato nesta fase.
- **Negativas:** o cliente não recebe erro ao mandar corpo ou query que a rota não usa (é
  silenciosamente ignorado). O 503 de infraestrutura segue fora do contrato em parte das
  operações; uma futura versão minor do contrato pode documentá-lo (decisão do usuário).
