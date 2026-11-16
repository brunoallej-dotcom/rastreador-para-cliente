# ADR 0011 — Contrato `1.0.0-draft.2`: fator TOTP resolvido pela sessão e 503 documentado

- **Status:** proposed (altera em parte o [ADR 0008](0008-contrato-estrito-e-entrada-nao-declarada.md))
- **Data:** 2026-11-16

## Contexto

O ADR 0008 manteve o contrato `1.0.0-draft.1` intacto e fez o código se encaixar nele. Duas
consequências ficaram caras:

1. `TotpVerifyRequest.factorId` era obrigatório e nenhuma resposta o devolve depois do `enroll`. Um
   CEO que entra num dispositivo novo (`VERIFY_MFA` pendente) não tinha como saber o id e, portanto,
   não conseguia verificar o código: era o bloqueio registrado no §8 do threat model.
2. O 503 de falha de infraestrutura (limitador, banco, Auth indisponíveis) existia no código de toda
   operação autenticada, mas o contrato o listava só em quatro operações. O ADR 0008 aceitou isso e
   tirou esses casos do validador de contrato dos testes; também ficaram sem descrição o 503 de
   `changePassword`, o `Set-Cookie` do seu 204, o limite de 72 **bytes** de `currentPassword`, os
   `minLength`/`maxLength` de `newPassword` (que prometiam um 400, quando a política responde 422
   `WEAK_PASSWORD`, E-12) e os orçamentos programáticos (teto global de logins, teto diário do
   TOTP, orçamento de sessão por IP) que o código gasta e o contrato não mencionava.

Em 2026-11-16 o usuário aprovou um bump minor do contrato para resolver isso.

## Decisão

1. **Versão `1.0.0-draft.2`**, minor: tudo é aditivo ou documenta comportamento que já existia, e
   `factorId` continua aceito com o mesmo significado. A nota de compatibilidade está em
   `info.description`.
2. **`factorId` opcional e `deprecated`.** Sem ele, o caso de uso `verify-totp` lista os fatores TOTP
   com a **sessão do próprio usuário** (`MfaGateway.listTotpFactors`, o mesmo client da requisição;
   nenhum client admin, nenhuma secret key) e escolhe, no espelho do que o `enroll` garante (um fator
   só: verificado, ou um candidato não verificado):
   - exatamente um fator verificado → ele (login em outro dispositivo);
   - nenhum verificado e exatamente um não verificado → ele (primeiro uso, logo depois do `enroll`);
   - nenhum fator TOTP, ou mais de um no mesmo estado → 422 `INVALID_MFA_CODE`, a mesma resposta de
     código errado. O log distingue (`factor_not_found`, `factor_ambiguous`). **O código nunca é
     tentado em mais de um fator:** isso multiplicaria as tentativas por código e queimaria códigos
     de fatores que o usuário não escolheu. O app nunca produz o caso ambíguo (o `enroll` mantém um
     fator só); quem o provocar direto no Auth envia o `factorId`, que continua valendo.
   - Com `factorId`, nada muda: ele precisa ser fator do próprio usuário (a checagem de dono é do
     `consume_totp_code` e do Auth), e fator alheio, inexistente ou removido é o mesmo 422.
   - `consume_totp_code` (anti-replay) passa a ser chaveado pelo **id resolvido**, e os limites de 5 /
     5 min e de 20 por dia são cobrados antes da resolução, como antes: omitir o campo não dá
     tentativa extra. A identidade vem da credencial, nunca de parâmetro.
3. **503 em toda operação autenticada**, pelo componente de resposta compartilhado `ServiceUnavailable`
   (já existia; ganhou a descrição "falha fechada"). Reverte a cláusula do ADR 0008 que deixava o 503
   de infraestrutura fora do contrato e dos testes: o helper dos testes de `changePassword` deixa de
   isentá-lo. O resto do ADR 0008 (corpo e query não declarados são ignorados, `health` com limitador
   em memória, grupos de rate limit nomeados) continua valendo.
4. **`x-rate-limit` lista os orçamentos programáticos** com `programmatic: true` e o `group` do
   contador: o teto global de logins (`login`, em `login` e `changePassword`), o teto diário do TOTP
   (`totp-verify-daily`, em `verifyTotp`) e o de sessão por IP (`session-upstream`, em
   `sessionCookie`, porque é cobrado de qualquer operação autenticada e, estourado, responde 401).
   A política de rota (`withRoute`) continua igual às entradas **sem** a marca; as com a marca são
   conferidas contra as constantes do código por um teste.
5. **`changePassword` descreve o que faz:** `newPassword` sem `minLength`/`maxLength` (a política é
   422, não 400); `currentPassword` com `maxLength: 72` (caracteres, só o excesso óbvio) e o limite
   real de 72 bytes UTF-8 descrito, com 400 `VALIDATION_ERROR` acima dele, que é o que o código já
   respondia (mantido: é validação de forma, como no login); `Set-Cookie` opcional no 204 (só quando o
   token da sessão foi renovado); 503 com a orientação do estado incerto (ADR 0010).

## Consequências

- **Positivas:** um CEO verifica em qualquer dispositivo; o contrato descreve toda resposta
  autenticada que o servidor pode dar, e o validador de contrato dos testes passa a cobrir o 503;
  os orçamentos que o cliente pode estourar estão no contrato.
- **Negativas:** o verify sem `factorId` faz uma ida a mais ao Auth (a listagem), dentro dos limites
  já cobrados. Um cliente validador que lê `maxLength: 72` como caracteres aceita no schema uma
  `currentPassword` de mais de 72 bytes e leva 400 do servidor (está descrito no schema).
- **Resíduo registrado:** no cenário de sequestro do primeiro cadastro (F-20), o CEO que verifica sem
  `factorId` cai no fator candidato do atacante e deixa `invalid_code` no log, e não
  `factor_not_found`; o traço do sequestro continua em `auth.mfa.enrolled` (`replacedFactors`) e
  `auth.mfa.verified` (`activated`). A remoção do campo é uma mudança incompatível: fica para
  `/api/v2`.
