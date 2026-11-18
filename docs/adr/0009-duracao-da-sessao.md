# ADR 0009 — Duração da sessão: credenciais efêmeras

- **Status:** accepted
- **Data:** 2026-11-16

## Contexto

A sessão do usuário é um cookie `__Host-rt-session` que guarda o access token (15 min) e o refresh
token (ADR 0002). O padrão do `@supabase/ssr` dá 400 dias de vida ao cookie, e o padrão do Supabase
Auth não limita a duração de uma sessão nem a inatividade: enquanto o refresh token for rotacionado,
a sessão não acaba. Foi o que a Onda 3 entregou na primeira versão, e a revisão apontou o risco:
um cookie roubado, um dispositivo esquecido ou um login de CEO deixado aberto continuaria válido por
mais de um ano.

O painel mostra o andamento da entrega de cada cliente e dá aos CEOs o poder de avançar fases.
Os acessos acontecem em horário comercial e as sessões são curtas por natureza. O custo de pedir
um novo login depois de um dia de trabalho ou de uma pausa longa é baixo.

Uma descoberta de implementação pesou na decisão: ao gravar a sessão, o `@supabase/ssr` sobrescreve
a opção `cookieOptions.maxAge` pelo próprio padrão de 400 dias. O tempo de vida do cookie não se
configura só pelas opções do client.

## Decisão

Credenciais efêmeras, com dois limites no servidor e um no navegador:

- `[auth.sessions] timebox = "12h"`: o Supabase Auth encerra a sessão 12 horas depois do login,
  mesmo que ela esteja em uso.
- `[auth.sessions] inactivity_timeout = "4h"`: o Supabase Auth encerra a sessão depois de 4 horas
  sem renovação do token.
- O cookie de sessão vive no máximo 12 horas (`SESSION_COOKIE_MAX_AGE_SECONDS`, 43.200 s), o mesmo
  teto da sessão, para o navegador não guardar o cookie de uma sessão que o servidor já encerrou.
  O teto é aplicado no `setAll` do client de requisição (`src/shared/db/server-client.ts`), no último
  passo antes do cookie jar, porque o `@supabase/ssr` ignora a opção `maxAge` ao gravar a sessão.
  O jar do pipeline repassa o `maxAge` e continua forçando `HttpOnly; Secure; SameSite=Lax; Path=/`.
- O banco repete os dois limites, porque o `timebox` e o `inactivity_timeout` do Auth só valem
  onde estiverem configurados (no projeto hospedado, só depois da Onda 11): `private.session_is_alive()`
  exige `created_at` há menos de 12 h e a última atividade há menos de 4 h. A última atividade é a
  mais recente de três marcas: `refreshed_at` (`timestamp` sem fuso, em UTC, que o GoTrue nem sempre
  grava), o `created_at` do refresh token mais novo da sessão (cada renovação rotaciona o token) e
  o `created_at` da sessão. Uma sessão vencida deixa de
  ter principal em `current_principal()`, a RLS nega tudo e a API responde 401, mesmo com um JWT
  ainda válido. Os valores de 12 h e 4 h existem em quatro lugares e mudam juntos: `config.toml`,
  `SESSION_COOKIE_MAX_AGE_SECONDS`, a migration `session_time_limits_in_db` e este ADR.
- Quando o limite vence, a próxima requisição recebe 401 e o usuário faz login de novo. Não há
  "lembrar de mim".
- No Supabase hospedado, `timebox` e `inactivity_timeout` exigem o plano Pro. Desde o
  [ADR 0018](0018-planos-gratuitos-supabase-free-e-repositorio-publico.md) (2026-11-17), a produção
  fica no plano Free: lá os dois limites valem pelo banco (`private.session_is_alive()`) e pelo teto
  do cookie, e o Auth hospedado não os aplica. No `config.toml` local os valores continuam.

Resíduo aceito: fazer login com um cookie de sessão válido sobrescreve o cookie, mas não revoga a
sessão anterior. Ela deixa de valer pelo `timebox` (no máximo 12 h) ou pela inatividade (4 h).
Revogar a sessão anterior no login exigiria identificá-la antes de autenticar de novo e uma chamada
a mais ao Auth em todo login; não vale o custo enquanto o `timebox` limita a janela.

## Consequências

- **Positivas:** um cookie ou um refresh token roubado vale no máximo 12 horas, e 4 horas se
  ninguém o usar; o navegador não guarda credencial vencida; o teto vale também na renovação do
  token, porque o cap está no `setAll`.
- **Negativas:** o usuário refaz o login ao menos uma vez por dia de trabalho, e um CEO que passa
  4 horas sem usar o painel refaz o login e o MFA. Se o incômodo for grande, os valores são
  configuração (`config.toml` e uma constante), sem mudança de arquitetura.
- A lógica de logout, de desativação de conta e de reset de senha não muda: continuam apagando as
  sessões no banco, e o 401 é imediato.
