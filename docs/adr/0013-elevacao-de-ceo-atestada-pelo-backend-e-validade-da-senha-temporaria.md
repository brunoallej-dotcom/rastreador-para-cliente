# ADR 0013 — Elevação de CEO atestada pelo backend e validade de 72 h da senha temporária

- **Status:** accepted (decidido pelo usuário em 2026-11-16, e revisado no mesmo dia depois de rls-auditor, threat-modeler e code-reviewer: F-64 a F-72, §C; complementa o [ADR 0006](0006-privilegios-minimos-do-service-role.md) e o [ADR 0011](0011-contrato-draft-2-fator-da-sessao-e-503.md))
- **Data:** 2026-11-16

## Contexto

Os limites de força bruta e de replay do login e do TOTP (10 / 15 min por conta, teto global,
5 / 5 min e 20 por dia no verify, queima do código usado) vivem no BFF. Quem tem a senha de um CEO e
a publishable key chama o Auth direto (`/auth/v1/token` e `/auth/v1/factors/{id}/verify`), onde só
valem os limites por IP do Auth, e o Auth não tem proteção contra replay (supabase/auth#2882). Até
aqui `private.is_ceo()` aceitava qualquer sessão `aal2` com um fator TOTP verificado: a sessão
obtida direto no Auth era CEO pelo PostgREST (F-50). Havia ainda três fraquezas ligadas:

- o oráculo: chutar o TOTP direto no Auth, achar um código válido e reapresentá-lo ao backend
  dentro da janela (~90 s);
- o verify sem `factorId` (ADR 0011) resolve o fator pela **lista do Auth**, que quem tem a senha
  também escreve: um candidato plantado deixa o verify ambíguo (F-60) e um fator verificado
  plantado vira "o fator do CEO" (F-61);
- a senha temporária valia até ser trocada, sem prazo (F-41).

O controle principal do F-50 continua sendo a publishable key tratada como segredo (Onda 11, F-50
(c)). Este ADR é a defesa em profundidade que a decisão de 2026-11-16 pediu para a Onda 6.1.

## Decisão

### A. Atestado por sessão

1. **Uma sessão só vale como CEO se o backend a atestou.** `private.is_ceo()` passa a exigir, além
   do papel, da sessão viva e do perfil ativo, um registro em `private.mfa_session_attestations`
   para `(auth.jwt() ->> 'session_id', auth.uid())` cujo fator TOTP ainda esteja `verified`. Isso
   substitui o F-24 (que olhava "algum fator verificado"): o atestado já nomeia **o** fator, e
   remover o fator apaga o atestado (`ON DELETE CASCADE`). Toda função e toda policy de CEO (Ondas
   2, 5 e 6) passa por `is_ceo()`; um grep nas migrations confirma que nenhuma outra lê o claim
   `aal`. `private.session_is_attested()` é a única definição de "aal2 de verdade" e é usada por
   `is_ceo()`, `current_principal()` e `mark_password_changed()`.
2. **`current_principal()` devolve `aal1` para uma `aal2` sem atestado.** O app calcula a pendência
   `VERIFY_MFA` exatamente como para `aal1`, sem mudar o TypeScript do pipeline: `GET /auth/session`
   e `/admin/*` se comportam igual.
3. **Quatro registros privados** (RLS ligado, sem policy, sem privilégio algum para `anon`,
   `authenticated` e `service_role`; só as funções `SECURITY DEFINER` os tocam):
   - `mfa_backend_factors`: o fator que o `POST /auth/mfa/totp/enroll` criou (usuário, sessão que
     cadastrou, hora) e, depois, a ativação pelo backend (hora e challenge);
   - `mfa_first_activations`: a marca de que o usuário já ativou um fator pelo backend (§C, F-64);
   - `mfa_backend_challenges`: cada challenge que o backend criou, gravado **antes** de o Auth
     verificá-lo, com o estado do fator naquele instante (`factor_was_verified`) e uma cópia do
     instante da verificação (§C, F-71);
   - `mfa_session_attestations`: um atestado por `session_id` (FK `ON DELETE CASCADE` para
     `auth.sessions`), amarrado a usuário, fator e challenge do backend; `challenge_id` é `UNIQUE`.
4. **Quatro funções `SECURITY DEFINER` com `search_path` vazio, `EXECUTE` só para o `service_role`**
   (e `REVOKE` de `PUBLIC`, `anon` e `authenticated`), chamadas pelo client admin da infraestrutura
   de identidade (ADR 0006), nunca para leitura ou escrita de negócio:
   `consume_totp_code` (queima do código, §C, F-65), `register_backend_totp_factor` (depois do
   enroll), `record_backend_mfa_challenge` (entre o `challenge` e o `verify` do Auth) e
   `attest_mfa_session` (depois de um verify que o Auth aceitou). O facade do client admin ganhou um
   método tipado por função, sem `rpc` genérico, e valida o payload de cada resposta com Zod.
5. **`attest_mfa_session` revalida tudo em SQL e não confia em id nenhum do app:** o usuário é um
   CEO ativo; a sessão existe, é dele e está em `aal2` na tabela do Auth; o fator é dele, é TOTP, está
   `verified` e é um fator que o backend cadastrou; o challenge é desse fator, foi verificado há menos
   de 120 s e é um challenge do backend. Depois, duas checagens próprias:
   - **Oráculo (F-50 b).** Recusa se, nos últimos 120 s (a mesma janela do `consume_totp_code`; o Auth
     aceita um código por no máximo ~90 s), o fator tem **qualquer challenge verificado que o backend
     não criou**. Os challenges do próprio backend (inclusive o de um login legítimo concorrente em
     outro dispositivo) nunca contam. O IP nunca entra na conta: o IP de saída da Vercel é
     compartilhado.
   - **Ativação pelo backend (F-61).** O fator só é "ativado pelo backend" se um challenge dele,
     registrado quando o fator ainda não estava verificado, foi verificado, e **nenhum** challenge
     verificado de fora do backend jamais existiu para ele. A ativação é **derivada**, não gravada
     por quem chama: um atestado que falhou por indisponibilidade depois de o Auth já ter ativado o
     fator se recupera no próximo verify (a derivação acha o challenge que ativou), sem trancar o CEO.
     O atestado diz ao app quando foi ele que ativou (`attested_activated`), e é isso, não a
     pendência `ENROLL_MFA`, que faz o app derrubar as outras sessões (F-20, F-72).
   - **Mais três conferências (F-67).** A sessão tem de ter sido elevada por **este** fator
     (`auth.sessions.factor_id`, que o Auth grava no verify); um challenge atesta uma sessão só; e o
     challenge que o backend registra tem de ser novo (menos de 60 s) e ainda não verificado.
6. **Recusa.** `attest_mfa_session` devolve o motivo (não levanta exceção: a exceção desfaria o que
   vem a seguir) e, na mesma transação, grava o evento de auditoria `auth.mfa_attestation_refused`
   (sem ator; o motivo, o id do fator, a `severity` e se revogou, sem PII). Quando o motivo é um
   **sinal de ataque** (`oracle`, `factor_not_backend`, `factor_not_activated_by_backend`,
   `challenge_not_backend`, `challenge_not_found`, `challenge_reused`, `session_factor_mismatch`,
   `factor_reenrolled`), **apaga todas as sessões do usuário** (a senha e um código válido vazaram, ou
   um fator ou challenge que o backend não criou apareceu); os motivos de corrida ou inconsistência
   (`session_not_found`, `session_not_aal2`, `not_ceo`, `challenge_stale`, `factor_not_found`,
   `factor_not_totp`, `factor_not_verified`, `challenge_not_verified`) recusam sem revogar, e a
   auditoria os marca `warning` (F-66): quem os provoca não precisa de um código válido, e derrubar as
   sessões do CEO por uma corrida seria uma negação de serviço barata. A revogação é por
   `DELETE FROM auth.sessions`, como já fazem `set_account_disabled` e `require_password_change`: o
   `signOut` global da Auth Admin API exige o JWT do usuário e não há revogação por id. O app responde o
   mesmo 422 `INVALID_MFA_CODE` de um código errado e loga `auth.mfa.attestation_refused` (nome
   estável, motivo, ids, sem PII), em nível `error` para os sinais de ataque e `warn` para os demais.
   - **Não vira negação de serviço contra o CEO.** A recusa por oráculo exige um challenge
     **verificado** fora do backend, e o Auth só verifica um challenge com um código certo: quem
     chuta e erra deixa challenges não verificados, que não contam. Quem acerta um código direto no
     Auth já conseguiu o que a recusa limita, e seu efeito (derrubar as sessões do CEO e travar o
     verify por 120 s) é menor do que o do acerto. As recusas de F-61 exigem um fator verificado que
     o atacante controla, o que só acontece antes de o CEO ativar o primeiro fator.
7. **Falha fecha.** Se a queima do código, o registro do challenge, o do fator ou o atestado não
   puderem ser gravados (banco ou Auth fora do ar, resposta incompreensível), a resposta é 503 (ou
   500) e a sessão fica sem atestado: pendência `VERIFY_MFA`. O código **não** é tentado no Auth se o
   challenge não pôde ser registrado. O 503 depois da queima diz, no `detail`, que o código foi
   usado e que o CEO deve esperar o próximo (E-37): repetir o mesmo código é um replay recusado.
8. **Resolução do fator só entre os do backend (F-60).** `public.list_backend_totp_factors()`
   (executável por `authenticated`, devolve só os fatores do próprio usuário) diz quais fatores o
   backend cadastrou. O verify sem `factorId` considera só esses: um candidato plantado direto no
   Auth não é o candidato e nunca causa `factor_ambiguous`. Um fator TOTP que o backend não cadastrou
   é contado (`foreignFactorCount`) e gera o evento `auth.mfa.foreign_factor`, em nível `error`: o app
   nunca cria um.
9. **O enroll registra o fator** (`register_backend_totp_factor`, com o id da sessão que cadastrou,
   lido dos claims verificados do token) antes de devolver o segredo. Se o registro falhar, o CEO
   repete o enroll: o fator sem registro é um candidato comum, removido pelo próximo enroll.

### B. Validade da senha temporária (F-41)

10. `private.current_active_user_id()` devolve `NULL` para o perfil com `must_change_password` cuja
    linha de base da senha temporária (`private.password_baselines`, gravada na criação e no reset
    da Onda 2) é mais velha que **72 h**. O prazo é `private.temporary_password_validity()`, uma
    constante nomeada e comentada. Sem linha de base, o perfil temporário também fica sem principal
    (falha fechada). 72 h exatas já vencem.
11. O login com a senha vencida cai no caminho da conta desativada: o principal vem vazio, a sessão é
    revogada e a resposta é o 401 genérico, com o mesmo piso de tempo. O reset por um CEO
    (`require_password_change`, Onda 2) grava uma linha de base nova e o prazo recomeça;
    `mark_password_changed()` encerra o estado temporário.

## Consequências

- **Positivas:** uma `aal2` obtida direto no Auth não dá poder de CEO nem pelo backend nem pelo
  PostgREST; o oráculo de "chutar no Auth e reapresentar ao backend" é fechado; F-60 e F-61 perdem a
  causa (o candidato é resolvido pelo registro do backend, não pela lista do Auth); a senha
  temporária deixa de valer para sempre.
- **Negativas:**
  - o verify faz mais idas ao banco (listar os fatores do backend, registrar o challenge, atestar) e
    uma leitura de claims;
  - cada CEO-gated depende de uma consulta a mais (o atestado e o fator) na avaliação de `is_ceo()`,
    uma vez por comando;
  - o `service_role` ganha `EXECUTE` em quatro funções (a secret key continua sem escrever em
    `profiles`, `audit_events` nem nos registros: só as funções escrevem);
  - uma recusa por oráculo derruba as sessões do CEO e o impede de verificar por 120 s;
  - um CEO que deixa a senha temporária vencer fica sem acesso até um reset. Para clientes o reset é
    da Onda 7; para CEO é um script da Onda 11 (E-25). Até lá, quem opera apaga e recria a conta
    (`ceo:create`) ou, **no mesmo ato**, grava uma senha temporária NOVA pela Auth Admin API e a linha
    de base dela. Regravar só a linha de base reabriria por 72 h a senha antiga, que já foi vista por
    quem a entregou (F-70);
  - depois do primeiro fator ativado, um CEO que perde o fator (um dispositivo perdido, E-25) não
    cadastra outro sem o operador: a marca `mfa_first_activations` só sai pelo runbook de reset de MFA
    (Onda 11), por SQL, e nenhuma função da API a apaga (§C, F-64).
- **Resíduos registrados (threat model §7 e §8):**
  - **F-23** (refresh token anterior ao verify, dentro do intervalo de reuso): o atestado é por
    `session_id`, e o `session_id` não muda no verify, então esse token também recebe a sessão `aal2`
    atestada. O resíduo é o mesmo de antes, não um buraco novo;
  - quem já tem a senha ainda descobre senhas válidas pelo `/auth/v1/token` direto, sem os limites do
    BFF: é o F-50 (c), tratado na Onda 11;
  - os modos de falha do caminho admin (banco fora do ar, secret key inválida, resposta que o app não
    entende) falham fechados, e a sessão fica `VERIFY_MFA`. O alerta de uma recusa vem do
    `audit_events` (`auth.mfa_attestation_refused`), não só do log do app: um timeout depois do COMMIT
    devolve 503 e a linha do log se perde, a auditoria não (requisito de alerta da Onda 11, F-68);
  - o F-64 tem uma janela que a marca não cobre: entre um atestado que falhou (503) depois de o Auth
    ter ativado o fator e o retry do CEO, quem tiver um código válido direto no Auth (F-50, F-65)
    e apagar esse fator antes de a primeira ativação ser gravada cadastra o dele. Exige um código
    achado no Auth e uma indisponibilidade no mesmo momento;
  - o oráculo conta challenges verificados que o Auth guarda; observado no Auth local que as linhas
    (verificadas e não verificadas) ficam depois do verify. Se uma versão futura do Auth passar a
    apagá-las em menos de 120 s, a checagem enfraquece sem avisar. O teste de API do E-33 cobre o
    comportamento atual.
- **Verificado no Auth local (Onda 6.1):** `auth.sessions.aal` vira `aal2` na mesma linha (mesmo
  `id`) quando o verify passa, e `auth.sessions.factor_id` guarda o fator; o claim `session_id` do
  JWT é o `auth.sessions.id` e sobrevive ao refresh, que mantém `aal2`;
  `auth.mfa_challenges` guarda `id`, `factor_id`, `created_at`, `verified_at` e `ip_address`, as
  linhas ficam depois do verify (também as de código errado, sem `verified_at`), e o mesmo código aceito
  duas vezes deixa dois challenges verificados; verificar um fator plantado apaga os candidatos não
  verificados do CEO; e verificar o MFA de uma sessão apaga as **outras sessões do usuário que ainda
  estão em `aal1`** (as `aal2` ficam). Por isso o teste do E-33 reapresenta o código com a sessão do
  próprio atacante: a sessão `aal1` de outro dispositivo do CEO já teria sido apagada pelo Auth quando o
  atacante verificou direto.

### C. Revisão de 2026-11-16 (rls-auditor, threat-modeler, code-reviewer): F-64 a F-72

O desenho da §A foi revisto no mesmo dia, com a migration ainda sem merge (editada no lugar). O que
mudou, com o achado de cada mudança:

- **F-64 (alto): apagar o fator e cadastrar outro.** Com uma `aal2` achada no Auth, o atacante faz
  `DELETE /factors/{id}` no fator verificado do CEO (o Auth local deixa: pede `aal2`, que ele tem). O
  `CASCADE` apagava o registro e os atestados, o CEO voltava a `ENROLL_MFA`, e o atacante cadastrava e
  ativava o fator dele pelo backend, passava no oráculo (que olha um fator só) e era atestado; o F-20
  ainda derrubava o CEO de verdade, sem alerta. Agora `private.mfa_first_activations` (`user_id`
  PK → `auth.users ON DELETE CASCADE`, **sem FK para o fator**, sem privilégio para ninguém) é gravada
  na primeira ativação pelo backend. Com ela, `register_backend_totp_factor` e `attest_mfa_session`
  recusam um fator novo (`factor_reenrolled`: auditoria, todas as sessões apagadas, evento
  `auth.mfa.reenrollment_refused` no log). O enroll responde o 409 de sempre. Só o runbook de reset de
  MFA (E-25, Onda 11) apaga a linha.
- **F-65 (médio): `consume_totp_code` era um oráculo pelo PostgREST** (migration da Onda 5, executável
  por `authenticated`): com uma sessão só de senha, mandar os 10^6 digests, sem limite; um `false`
  revela o código que o CEO acabou de usar (o Auth ainda o aceita ~90 s) e cada `true` queima um
  código dele. A migration nova **apaga** essa função e cria `consume_totp_code(p_user_id,
  p_factor_id, p_code_digest)` só para o `service_role`; o app a chama pelo facade admin, depois dos
  limites da rota. O comportamento (F-21) e os testes ficam.
- **F-66: revogar só nos sinais de ataque.** Ver o item 6 da §A.
- **F-67: guardas do registro e do atestado.** Ver o item 5 da §A. Confirmado no Auth local:
  `auth.sessions.factor_id` é gravado no verify, também no de uma segunda sessão do mesmo fator.
- **F-68: o alerta vem do `audit_events`.** A auditoria da recusa sobrevive a um 503 depois do COMMIT;
  a linha do log do app não. Requisito de alerta da Onda 11 (threat model).
- **F-69: fatores que antecedem o registro.** A migration tem um bloco `DO` que **para** se algum CEO
  tiver fator TOTP verificado fora do registro. Hoje não há ambiente hospedado; quando houver, isso
  força uma decisão explícita do operador (zerar o fator ou registrar a ativação à mão).
- **F-70: a recuperação da senha temporária vencida** não é "regravar a linha de base" (ver as
  Consequências).
- **F-71: o Auth pode apagar challenges.** Verificado: o código do Auth que se pôde ler não apaga
  challenges por idade (só o challenge expirado que está sendo verificado, os de WebAuthn consumidos e,
  ao cadastrar, fatores não verificados sem challenge e vencidos por `FactorExpiryDuration`); a
  hipótese de uma limpeza de 24 h **não se confirmou** na fonte nem no Auth local (uma linha verificada
  continuava lá 281 s depois), e não dá para descartar uma limpeza do lado hospedado. Por isso a prova
  não depende de o Auth guardar linhas: `mfa_backend_challenges` não tem FK nem `CASCADE` para
  `auth.mfa_challenges`, e o atestado copia o instante da verificação para o registro do backend. A
  ativação é derivada dessa cópia quando o Auth já não tem o challenge. (A checagem do **oráculo** olha
  os 120 s mais recentes de `auth.mfa_challenges`, que o Auth tem de guardar por esse tempo.)
- **F-72: a revogação do F-20 perdia-se no retry.** `activated` vinha da pendência `ENROLL_MFA`; depois
  de um atestado que falhou com o Auth já tendo ativado o fator, o retry não a tinha e a derivação
  ativava o fator sem derrubar as outras sessões. Agora o atestado devolve `attested_activated` quando
  ele ativa, e a revogação segue isso.
