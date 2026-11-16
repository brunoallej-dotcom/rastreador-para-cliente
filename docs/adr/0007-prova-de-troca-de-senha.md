# ADR 0007 — Prova de troca de senha por linha de base do hash

- **Status:** accepted
- **Data:** 2026-11-16

## Contexto

A troca de senha obrigatória (AC-05, SEC-10) é limpa por `public.mark_password_changed()`, que o
BFF chama depois de `auth.updateUser({ password })`. A função é executável por `authenticated`,
e o próprio usuário pode chamá-la direto pelo PostgREST com o JWT do cookie e a publishable key
(que não é segredo). Sem prova de que a senha mudou, o usuário contornaria para sempre a troca
obrigatória e manteria a senha temporária que o CEO viu e repassou por fora do sistema. O
`rls-auditor` reproduziu o ataque.

## Decisão

- `private.password_baselines` guarda o SHA-256 de `auth.users.encrypted_password` (o hash
  bcrypt, nunca a senha) gravado na criação do usuário (trigger de `auth.users`) e no reset
  (`require_password_change`).
- `mark_password_changed()` só limpa a pendência se o hash atual for diferente da linha de base
  (senão `P0001`/`PASSWORD_UNCHANGED`) e então renova a linha de base. Para CEO com TOTP
  verificado, exige `aal2` (`POST /auth/password` não libera `VERIFY_MFA`).
- Requisito para quem cria contas: o usuário nasce **já com a senha temporária** na mesma chamada
  `auth.admin.createUser` (provisionamento e `ceo:create`); no reset, a senha nova vai para o Auth
  antes de `require_password_change`.

## Consequências

- **Positivas:** a pendência só some quando o Auth de fato gravou uma senha nova; a regra vale
  mesmo para quem fala com o PostgREST sem passar pelo BFF.
- **Negativas:** acoplamento ao formato de `auth.users.encrypted_password` (coluna interna do
  Supabase Auth). Os testes pgTAP (`002`, `005`) quebram se esse formato mudar, sinalizando a
  quebra. Criar usuário sem senha e defini-la depois anularia a prova; a spec §3.4 proíbe isso.
