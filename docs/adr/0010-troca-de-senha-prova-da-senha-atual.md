# ADR 0010 — Troca de senha: a senha atual é provada por re-autenticação

- **Status:** accepted
- **Data:** 2026-11-16

## Contexto

`POST /auth/password` exige a senha atual (SEC-10, AC-06). O Supabase Auth só aplica essa regra no
`updateUser` quando o projeto liga `security_update_password_require_current_password`, e essa
chave é do projeto hospedado (Management API): não existe em `config.toml`, o Supabase local não a
liga e a `current_password` enviada ao `updateUser` é ignorada (verificado na Onda 4: uma senha atual
errada é aceita). Provar a senha atual é, portanto, trabalho do app.

A outra chave que parece servir, `[auth.email] secure_password_change` (F-13), não prova a senha
atual: ela exige um nonce de reautenticação (e-mail ou SMS, `reauthenticate()`) só quando a sessão
foi criada há mais de 24 horas. Com `timebox = 12h` (ADR 0009) nenhuma sessão chega a essa idade, e o
app não tem fluxo de nonce.

O Auth não tem um endpoint "verificar senha". O único jeito de testar uma senha sem alterar nada é
`signInWithPassword`, que abre uma sessão nova.

## Decisão

1. **A senha atual é provada por um sign-in descartável.** O gateway lê o e-mail das claims
   verificadas do token da sessão (nunca do corpo), entra com ele e a senha informada num client
   próprio (chave publicável, sem storage, sem cookies, sem refresh: `createReauthClient`) e
   encerra a sessão aberta (`signOut` com escopo `local`) antes de qualquer outra coisa. Nada dessa
   sessão chega à resposta. Não é um segundo client no sentido do E-10: nasce sem sessão e nunca
   compartilha um refresh token com o client da requisição.
2. **Ordem fixa** (`change-password.ts`): política da nova senha (E-12) e "igual à atual" (E-13), que
   são puras e não dependem de a senha atual estar certa; prova da senha atual; `updateUser` na
   sessão do usuário (que mantém a sessão da requisição e, no Auth, derruba as outras); e
   `mark_password_changed()`, que prova a troca ao banco (ADR 0007), limpa `CHANGE_PASSWORD` e
   revoga as demais sessões de novo, agora por ID.
3. **Senha atual errada:** 422 `INVALID_CURRENT_PASSWORD`, o código que o contrato documenta. Quem
   chama já está autenticado e o e-mail vem da sessão, então não há enumeração de contas (SEC-12 é
   do login anônimo) e não há piso de tempo. Qualquer outra resposta do Auth (5xx, 429, código
   desconhecido, chave rejeitada) é 503: um serviço quebrado não pode parecer senha errada.
4. **Custo e limites.** Toda requisição gasta o `password-change` do usuário (5 / 15 min), as
   recusadas também, de modo que a rota não adivinha a senha atual mais rápido que isso. O sign-in de
   prova é uma chamada ao Auth como qualquer login, então gasta o orçamento global de logins (F-02)
   antes de chamar, e só quando uma checagem pura não recusou antes.
5. **O `current_password` vai junto ao `updateUser`.** Hoje é ignorado; quando o projeto hospedado
   ligar `security_update_password_require_current_password` (Onda 11), o Auth confere a senha
   também, e `current_password_mismatch` e `current_password_required` já viram
   `INVALID_CURRENT_PASSWORD`.
6. **`secure_password_change = true`.** Para sessões de até 24 h (todas as do app) o comportamento é
   idêntico ao de antes (condição lida no código do GoTrue: sessão ausente ou criada há mais de 24 h).
   Ligar custa nada e fecha um caminho: enquanto o `timebox` não estiver no projeto hospedado (Onda
   11), uma sessão do Auth pode passar de 24 h, o banco a recusa nas rotas do app (`session_is_alive`),
   mas não recusa um `PUT /auth/v1/user` direto com o token dela; com a chave ligada o Auth pede o
   nonce e o ataque precisa do e-mail. No Supabase local o container do Auth só lê a chave quando é
   recriado (`supabase stop` e `supabase start`); nenhum teste depende dela.
7. **Troca que falha no meio.** O `updateUser` não se desfaz. Se `mark_password_changed()` falha por
   indisponibilidade, é tentada uma segunda vez; se falha de novo, a resposta é 503 com o texto "repita
   usando a nova senha como senha atual" e o log registra `auth.password_change.incomplete`
   (nível `error`). A sessão da requisição continua viva, e repetir a troca com a senha nova como
   atual conclui o fluxo (teste de API).
8. **Estado incerto depois de uma falha sem resposta.** O mesmo vale quando a resposta se perde:
   (a) um `updateUser` que dá timeout, falha de transporte ou 5xx pode ter gravado a senha antes de a
   resposta se perder; responde 503 (`PasswordChangeUncertainError`) com a orientação dos dois
   estados, "repita; se a senha atual for recusada, repita usando a nova senha como atual", e o log
   registra `auth.password_change.uncertain` (nível `error`). Uma resposta definitiva do Auth, mesmo
   inesperada, não é incerteza e segue como é. (b) Se a primeira chamada de `mark_password_changed()`
   gravou e só a resposta se perdeu, a segunda recebe `PASSWORD_UNCHANGED`; **no retry, e só nele**,
   isso é sucesso: o `updateUser` já gravou a senha nova, então a linha de base só pode igualar o hash
   atual se uma chamada anterior gravou (ela renova a linha de base, limpa a pendência e revoga as
   outras sessões). Na primeira tentativa a mesma resposta continua sendo a recusa de sempre (E-13).

## Consequências

- **Positivas:** a senha atual é conferida pelo servidor, com ou sem a chave do projeto hospedado;
  a pendência só some com senha realmente nova (ADR 0007); o cookie da resposta é o da sessão
  do usuário, sem nada do sign-in de prova.
- **Negativas:** uma troca faz até quatro idas ao Auth (claims, sign-in, sign-out, update) mais a RPC;
  o sign-in de prova aparece no log de auditoria do Auth como um login; uma falha ao encerrar a sessão
  de prova deixa uma sessão que ninguém consegue usar até o `updateUser` ou o
  `mark_password_changed()` apagá-la (log `auth.password_change.probe_session_not_revoked`).
- **Resíduos aceitos:**
  - Quem tem o token de acesso de uma sessão com menos de 24 h e a chave publicável (que não é
    segredo) pode trocar a senha direto no Auth, **sem** a senha atual, enquanto
    `security_update_password_require_current_password` não estiver ligado no projeto hospedado.
    O token só existe no cookie `HttpOnly` e no servidor (ADR 0002), vale 15 minutos e a troca derruba as
    outras sessões do usuário. **Onda 11:** ligar a chave pela Management API.
  - Adivinhação da senha atual: 5 por 15 minutos por usuário na troca, somados aos 10 por 15 minutos
    por conta do login (contadores separados).
  - A troca que falha no meio (item 7) deixa a senha nova e a pendência de pé até o usuário repetir.
  - O estado incerto do `updateUser` (item 8) depende de o usuário seguir a orientação: ele pode
    ter trocado a senha sem saber. Os 5 pedidos por 15 minutos bastam para repetir e concluir.
  - Uma sessão de prova órfã: se o sign-in de prova deu certo no Auth mas a resposta se perdeu
    (timeout), a sessão existe e ninguém tem o token dela. Também fica órfã se o `signOut` do item 1
    falha. Ela some quando o `updateUser` e o `mark_password_changed()` apagam as outras sessões do
    usuário (se a troca conclui), ou pelo `timebox` de 12 h e pelos 4 h de inatividade (o banco já a
    nega em `session_is_alive()`); só o `pg_cron` da Onda 11 (F-40, candidato a) a removeria antes.
  - Duas trocas concorrentes da mesma conta, a sessão clonada que sobrevive à troca e o ruído do
    sign-in de prova no log do Auth: aceitos, ver F-45, F-46 e F-47 no threat model.
