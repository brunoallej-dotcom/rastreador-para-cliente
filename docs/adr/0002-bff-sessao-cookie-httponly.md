# ADR 0002 — Next.js como BFF, com sessão em cookie HttpOnly

- **Status:** accepted
- **Data:** 2026-11-15

## Contexto

O padrão mais comum com Supabase é o browser falar direto com o Supabase (anon/publishable key
e sessão legível por JavaScript). Aqui isso traria três problemas:

1. O token de sessão ficaria acessível a JavaScript, exposto a XSS.
2. Não haveria um ponto único para rate limit, checagem de Origin, erros padronizados e logs de
   autenticação.
3. As regras de negócio (pendências de senha e de MFA) ficariam espalhadas entre frontend e banco.

## Decisão

- O **browser fala apenas com `/api/v1`** (mesma origem). O frontend futuro nunca instancia um
  client Supabase.
- A sessão vive em cookie **`__Host-rt-session`** gerenciado por `@supabase/ssr` no servidor, com
  `HttpOnly; Secure; SameSite=Lax; Path=/` forçados ao gravar.
- As variáveis do Supabase **não** usam prefixo `NEXT_PUBLIC_`; nenhuma chave vai para o bundle.
- O servidor valida o JWT com `getClaims()` (chaves assimétricas, JWKS) ou `getUser()`, e nunca
  confia em `getSession()`. Em seguida chama `current_principal()`, que exige sessão viva em
  `auth.sessions` e perfil ativo, o que torna logout e desativação imediatos.
- Proteção contra CSRF: SameSite=Lax + `Origin` obrigatório nos métodos não seguros + corpo
  `application/json`.
- O access token expira em 15 min, com renovação transparente no pipeline.

## Consequências

- **Positivas:** nenhum token exposto a JavaScript; rate limit e auditoria centralizados;
  frontend simples; sem CORS.
- **Negativas:** toda leitura passa pela função serverless (latência extra de um salto, mitigada
  por estar no mesmo país); é preciso cuidar da renovação de cookies em Route Handlers.
- **Observação:** o usuário ainda pode extrair o próprio JWT do browser e chamar o PostgREST
  diretamente. Por isso o RLS e as funções do banco aplicam as mesmas regras (ADR 0003).
