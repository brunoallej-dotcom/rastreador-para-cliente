# ADR 0016 — Endurecimento do banco da Onda 10.1: secret key fora do rastreamento, senha definitiva no RLS e intenção auditada antes do Auth

- **Status:** accepted (revoga o item "DML de fixtures" do [ADR 0006](0006-privilegios-minimos-do-service-role.md))
- **Data:** 2026-11-17

## Contexto

As revisões das Ondas 7 a 10 deixaram quatro pontos que só o banco fecha (threat model F-81, F-83, F-92 b e
F-93):

1. A secret key (`service_role`) ainda tinha todos os privilégios em `clients`, `processes`, `process_stages` e
   `stage_approvals`, só para as fixtures dos testes. Como ela tem `BYPASSRLS`, uma linha feita à mão quebrava I1 a
   I5 sem auditoria, e um `SELECT` lia todos os clientes. O ADR 0006 deixou isso aberto "enquanto não houvesse um
   canal de banco só para testes"; a Onda 6.1 criou esse canal (`tests/helpers/db.ts`, `psql` no contêiner).
2. Um login de cliente com a senha temporária pendente lia os próprios processos pelo PostgREST, sem passar pela
   recusa do BFF. E o atestado de um CEO com a senha pendente só era impossível por causa do `allowPending` das
   rotas, uma camada só.
3. O app escreve no Auth Admin API (banir, desbanir, trocar a senha, apagar a conta), que não passa por função do
   banco: se o passo do banco falhava depois, só o log mostrava o que foi tentado.
4. A auditoria do provisionamento tinha lacunas (a releitura que forçava a compensação, a conta apagada que
   deixava um `account.provisioned` sem fim, a conta órfã entregue por reset sem o evento).

## Decisão

- **O `service_role` não tem privilégio algum nas quatro tabelas** (`REVOKE ALL`, o `SELECT` e `TRIGGER`,
  `REFERENCES` e `MAINTAIN` incluídos), e o privilégio padrão do dono das migrations em `public` (tabelas e
  sequências) não concede nada a ele. Nada na aplicação usa a chave nelas. As fixtures e as leituras de teste dessas
  tabelas saem do `psql` do contêiner, com entradas validadas (UUID, instante de uma forma só, número pequeno, ou
  texto como o hex dos seus bytes UTF-8). `profiles`, `audit_events` e `default_stage_template` ficam como estavam
  (F-112).
- **Só uma conta com a senha definitiva lê dados de negócio e age como CEO.** `private.current_client_id()` e
  `private.is_ceo()` exigem `NOT must_change_password`. `current_active_user_id()` não muda (o principal do usuário
  pendente existe: o `GET /auth/session`, a troca de senha e o logout dependem dele), e o nome do cliente que a
  sessão mostra vem de `current_client_summary()`, uma função sem argumento com a projeção mínima, para o login
  pendente não ler nem a tabela `clients`.
- **A intenção de cada escrita no Auth sobre um login que existe é gravada antes, em transação própria, e sem ela o
  Auth não é tocado.** `begin_client_login_admin(client_id, user_id, action)` confere `is_ceo()`, o dono e o papel
  e aceita só `ban`, `unban` e `set_password`. A compensação do provisionamento segue a mesma regra com
  `record_account_provision_reverted`: grava antes de apagar e não apaga se não gravou. `record_account_provisioned`
  devolve a linha do login, e o reset de uma conta órfã registra o `account.provisioned` que faltava.
- **Os arquivos pgTAP contam só as próprias linhas** (as fixtures, e as da própria transação por `now()`), para
  `pnpm db:test` passar depois de `pnpm test:api` sem `db:reset`.

## Consequências

- **Positivas:** a secret key não escreve nem lê dado de negócio; o banco diz o que o BFF já dizia (senha pendente
  não lê, não é CEO); uma escrita no Auth deixa rastro mesmo quando o passo do banco falha depois; a compensação do
  provisionamento tem começo, meio e fim na trilha.
- **Negativas:** (a) um CEO que volta a ter a senha temporária (reset de operador) perde o acesso de CEO até trocar
  a senha, e com o fator já cadastrado o BFF não deixa nem verificar nem trocar (F-110, requisito da Onda 11);
  (b) quando a intenção não grava, o ban da desativação não é posto (o banco já bloqueia o login, o log diz
  `not_audited`) e a conta de um provisionamento que falhou fica como órfã em vez de ser apagada sem rastro;
  (c) cada fixture de teste que escreve essas tabelas custa uma ida ao contêiner; (d) a intenção é o que o app ia
  fazer, não prova de que o Auth o fez.
- **Alternativas recusadas:** manter o `SELECT` do `service_role` "por conveniência dos testes" (a chave com
  `BYPASSRLS` lê todos os clientes sem ninguém precisar); deixar `clients` legível ao login pendente (a regra
  ficaria com uma exceção que o próximo helper copiaria); só documentar que o atestado do CEO pendente é
  inalcançável (uma camada só); gravar a intenção depois da escrita no Auth (a falha do passo seguinte é justamente o
  caso que se queria ver); gravar a intenção "se der" e escrever no Auth de qualquer jeito (o rastro seria opcional,
  como era o log).
