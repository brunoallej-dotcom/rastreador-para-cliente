# ADR 0004 — Rate limiting com contadores no Postgres

- **Status:** accepted
- **Data:** 2026-11-15

## Contexto

O login, a verificação de TOTP e as operações sensíveis precisam de rate limit. Funções
serverless não compartilham memória, então o contador precisa de um armazenamento externo.
Há também uma armadilha: como o BFF chama o Supabase Auth, o limite por IP do Supabase enxerga
o **IP da Vercel**. Um atacante poderia esgotá-lo e bloquear o login de todos os usuários.

Opções:

1. **Upstash Redis** (`@upstash/ratelimit`): padrão na Vercel, mas é mais um fornecedor, mais uma
   chave e mais um operador de dados.
2. **Vercel WAF/Firewall:** útil como camada extra, mas configurado pelo painel (fora do IaC) e
   sem chave por conta.
3. **Contadores no Postgres do próprio Supabase:** sem novo fornecedor; latência de um salto
   dentro de São Paulo; volume baixo.

## Decisão

- Implementar a interface `RateLimiter` em `src/shared/http/rate-limit/` com um adaptador
  Postgres: tabela `private.rate_limit_counters` (janela fixa) e função
  `public.rate_limit_hit(bucket, window_seconds, max)`, executável **somente** por `service_role`.
- As chaves são HMAC-SHA256 (`RATE_LIMIT_KEY_SECRET`) de IP, e-mail normalizado ou id de usuário;
  o banco não guarda PII em claro.
- O IP vem do helper da plataforma (`ipAddress()` de `@vercel/functions`).
- Os limites ficam em §3.9 da spec, sempre mais restritivos que os do Supabase Auth.
- Falha do limitador → 503 (fail closed).
- Limpeza diária de janelas antigas com `pg_cron` (Onda 11).
- A Vercel Firewall pode ser ligada depois como camada extra; não é a barreira principal.

## Consequências

- **Positivas:** nenhum fornecedor novo; dados no Brasil; troca simples por Upstash se o volume
  crescer (mesma interface).
- **Negativas:** uma escrita no banco por requisição limitada; aceitável na escala-alvo
  (RNF-03). Reavaliar se o p95 de RNF-02 for violado.
