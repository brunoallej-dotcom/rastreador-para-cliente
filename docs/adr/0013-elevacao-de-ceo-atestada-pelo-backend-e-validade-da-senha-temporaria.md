# ADR 0013 — Elevação de CEO atestada pelo backend e validade de 72 h da senha temporária

- **Status:** accepted (decidido pelo usuário em 2026-11-16; complementa o [ADR 0006](0006-privilegios-minimos-do-service-role.md) e o [ADR 0011](0011-contrato-draft-2-fator-da-sessao-e-503.md))
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
3. **Três registros privados** (RLS ligado, sem policy, sem privilégio algum para `anon`,
   `authenticated` e `service_role`; só as funções `SECURITY DEFINER` os tocam):
   - `mfa_backend_factors`: o fator que o `POST /auth/mfa/totp/enroll` criou (usuário, sessão que
     cadastrou, hora) e, depois, a ativação pelo backend (hora e challenge);
   - `mfa_backend_challenges`: cada challenge que o backend criou, gravado **antes** de o Auth
     verificá-lo, com o estado do fator naquele instante (`factor_was_verified`);
   - `mfa_session_attestations`: um atestado por `session_id` (FK `ON DELETE CASCADE` para
     `auth.sessions`), amarrado a usuário, fator e challenge do backend.
4. **Três funções `SECURITY DEFINER` com `search_path` vazio, `EXECUTE` só para o `service_role`**
   (e `REVOKE` de `PUBLIC`, `anon` e `authenticated`), chamadas pelo client admin da infraestrutura
   de identidade (ADR 0006), nunca para leitura ou escrita de negócio:
   `register_backend_totp_factor` (depois do enroll), `record_backend_mfa_challenge` (entre o
   `challenge` e o `verify` do Auth) e `attest_mfa_session` (depois de um verify que o Auth
   aceitou). O facade do client admin ganhou um método tipado por função, sem `rpc` genérico.
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
6. **Recusa.** `attest_mfa_session` devolve o motivo (não levanta exceção: a exceção desfaria o que
   vem a seguir) e, na mesma transação, **apaga todas as sessões do usuário** (a senha e um código
   válido vazaram, ou o estado do Auth não bate com o do backend) e grava o evento de auditoria
   `auth.mfa_attestation_refused` (sem ator, só o motivo e o id do fator, sem PII). A revogação é por
   `DELETE FROM auth.sessions`, como já fazem `set_account_disabled` e `require_password_change`: o
   `signOut` global da Auth Admin API exige o JWT do usuário e não há revogação por id. O app responde o
   mesmo 422 `INVALID_MFA_CODE` de um código errado, loga `auth.mfa.attestation_refused` em nível
   `error` (nome estável, motivo, ids, sem PII) e não toca mais nada.
   - **Não vira negação de serviço contra o CEO.** A recusa por oráculo exige um challenge
     **verificado** fora do backend, e o Auth só verifica um challenge com um código certo: quem
     chuta e erra deixa challenges não verificados, que não contam. Quem acerta um código direto no
     Auth já conseguiu o que a recusa limita, e seu efeito (derrubar as sessões do CEO e travar o
     verify por 120 s) é menor do que o do acerto. As recusas de F-61 exigem um fator verificado que
     o atacante controla, o que só acontece antes de o CEO ativar o primeiro fator.
7. **Falha fecha.** Se o registro do challenge, o do fator ou o atestado não puderem ser gravados
   (banco ou Auth fora do ar, resposta incompreensível), a resposta é 503 (ou 500) e a sessão fica sem
   atestado: pendência `VERIFY_MFA`. O código **não** é tentado no Auth se o challenge não pôde ser
   registrado. O CEO verifica de novo com o código seguinte.
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
  - o `service_role` ganha `EXECUTE` em três funções (a secret key continua sem escrever em
    `profiles`, `audit_events` nem nos registros: só as funções escrevem);
  - uma recusa por oráculo derruba as sessões do CEO e o impede de verificar por 120 s;
  - um CEO que deixa a senha temporária vencer fica sem acesso até um reset. Para clientes o reset é
    da Onda 7; para CEO é um script da Onda 11 (E-25). Até lá, quem opera apaga e recria a conta
    (`ceo:create`) ou regrava a linha de base no banco.
- **Resíduos registrados (threat model §7 e §8):**
  - **F-23** (refresh token anterior ao verify, dentro do intervalo de reuso): o atestado é por
    `session_id`, e o `session_id` não muda no verify, então esse token também recebe a sessão `aal2`
    atestada. O resíduo é o mesmo de antes, não um buraco novo;
  - quem já tem a senha ainda descobre senhas válidas pelo `/auth/v1/token` direto, sem os limites do
    BFF: é o F-50 (c), tratado na Onda 11;
  - os modos de falha do caminho admin (banco fora do ar, secret key inválida, resposta que o app não
    entende) falham fechados, e a sessão fica `VERIFY_MFA`;
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
