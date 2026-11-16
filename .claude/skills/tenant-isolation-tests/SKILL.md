---
name: tenant-isolation-tests
description: Escreve os testes obrigatórios de isolamento entre clientes e de autorização por papel — pgTAP no banco (RLS, privilégios, funções de CEO, aal2, append-only) e testes de API (404 cross-tenant, 403 por papel ou pendência). Use ao criar ou alterar tabela, policy, função, query service ou endpoint que acesse dados de um cliente, ou quando o usuário pedir "teste cross-tenant" ou "prova que um cliente não vê o outro".
argument-hint: "<área ou objeto> (ex.: processes, approve_current_stage, GET /me/processes/{id})"
---

Alvo: $ARGUMENTS

Isolamento entre clientes é o requisito nº 1 do produto (SEC-03, SEC-04, SEC-05). Todo objeto
novo que toca dados de cliente ganha os testes abaixo **no mesmo PR**.

## Banco (pgTAP, `supabase/tests/<area>.test.sql`)

Helpers da Onda 2 (`supabase/tests/000_helpers.sql`):
- `tests.create_user(p_id uuid, p_role text, p_client_id uuid DEFAULT NULL)` cria o usuário em
  `auth.users` (com `raw_app_meta_data`), deixa o trigger criar o perfil e registra uma sessão
  em `auth.sessions`;
- `tests.authenticate_as(p_user_id uuid, p_aal text DEFAULT 'aal1', p_attested boolean DEFAULT true,
  p_session_id uuid DEFAULT NULL)` aplica `role = authenticated` e `request.jwt.claims` com `sub`,
  `aal` e `session_id`. Com `aal2` e `p_attested` (o padrão) ele ATESTA a sessão pelo caminho real
  (`public.attest_mfa_session`, Onda 6.1): é o CEO que o backend elevou. Com `p_attested => false` o
  claim `aal2` fica sem atestado, que é o que se obtém direto no Auth e **não vale como CEO**;
- `tests.clear_authentication()` volta ao papel original.

Use **UUIDs fixos** (determinismo) e nomeie cada assert com o ID de aceite.

```sql
BEGIN;
SELECT plan(8);

-- arrange (como postgres) ---------------------------------------------------
INSERT INTO public.clients (id, name) VALUES
  ('00000000-0000-4000-8000-00000000000a', 'Cliente A'),
  ('00000000-0000-4000-8000-00000000000b', 'Cliente B');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000a1', 'client', '00000000-0000-4000-8000-00000000000a');
SELECT tests.create_user('00000000-0000-4000-8000-0000000000c1', 'ceo');
-- … processos de A e de B inseridos como postgres …

-- cliente A ----------------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000a1');
SELECT is_empty(
  $$ SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000b' $$,
  'AC-09: cliente A não lê processos de B'
);
SELECT isnt_empty(
  $$ SELECT id FROM public.processes WHERE client_id = '00000000-0000-4000-8000-00000000000a' $$,
  'AC-09: cliente A lê os próprios processos'
);
SELECT throws_ok(
  $$ INSERT INTO public.processes (client_id, title) VALUES ('00000000-0000-4000-8000-00000000000a', 'x') $$,
  '42501', NULL, 'AC-09: cliente não escreve direto em processes'
);
SELECT throws_ok(
  $$ SELECT public.approve_current_stage('00000000-0000-4000-8000-0000000000f1', '00000000-0000-4000-8000-0000000000f2') $$,
  '42501', 'FORBIDDEN', 'AC-08: cliente não executa função de CEO'
);
SELECT tests.clear_authentication();

-- CEO sem MFA (aal1) --------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal1');
SELECT is_empty($$ SELECT id FROM public.processes $$, 'AC-08: CEO aal1 não lê nada');
SELECT tests.clear_authentication();

-- CEO com MFA (aal2) --------------------------------------------------------------
SELECT tests.authenticate_as('00000000-0000-4000-8000-0000000000c1', 'aal2');
SELECT isnt_empty($$ SELECT id FROM public.processes $$, 'CEO aal2 lê todos os clientes');
SELECT tests.clear_authentication();

-- anon ----------------------------------------------------------------------------
SET LOCAL ROLE anon;
SELECT throws_ok($$ SELECT id FROM public.processes $$, '42501', NULL, 'AC-10: anon sem privilégio');
RESET ROLE;

-- funções SECURITY DEFINER (AC-25) ------------------------------------------------
SELECT is_empty(
  $$ SELECT p.proname
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname IN ('public', 'private') AND p.prosecdef
        AND NOT coalesce(p.proconfig @> ARRAY['search_path=""'], false) $$,
  'AC-25: toda SECURITY DEFINER tem search_path vazio'
);

SELECT * FROM finish();
ROLLBACK;
```

Checklist do banco para cada objeto:
- [ ] cliente A não lê B (conjunto vazio) e lê os próprios dados;
- [ ] escrita direta por `authenticated` → `42501`;
- [ ] função de CEO chamada por cliente → `42501` / `FORBIDDEN`;
- [ ] CEO `aal1` → negado; CEO `aal2` atestado → permitido;
- [ ] **CEO `aal2` SEM atestado (`tests.authenticate_as(…, 'aal2', false)`) → negado, para TODO objeto
      de CEO novo** (função e policy): é o teste negativo que impede um objeto novo de aceitar um
      `aal2` obtido direto no Auth (F-50 b, ADR 0013). Nenhuma função lê o claim `aal` do JWT: use
      `private.is_ceo()` (o `001_privileges` reprova qualquer outra leitura);
- [ ] `anon` → `42501`;
- [ ] usuário desativado ou sessão apagada → negado;
- [ ] para funções: `proconfig` com `search_path=""` e `has_function_privilege('anon', …)` falso.

Confira o literal de `proconfig` no Postgres local (`SELECT proconfig FROM pg_proc …`) antes de
fixar o assert.

## API (`tests/api/<area>.api.test.ts`)

```ts
it('AC-09: client A gets 404 for a process of client B, identical to a missing id', async () => {
  // arrange
  const a = await fixtures.clientUser({ client: 'A' });
  const b = await fixtures.clientUser({ client: 'B' });
  const processOfB = await fixtures.process({ clientId: b.clientId });
  const session = await loginAs(a);

  // act
  const crossTenant = await invoke(getMyProcess, { session, params: { processId: processOfB.id } });
  const missing = await invoke(getMyProcess, { session, params: { processId: randomUuid() } });

  // assert
  expect(crossTenant.status).toBe(404);
  expect(withoutRequestId(await crossTenant.json())).toEqual(withoutRequestId(await missing.json()));
});
```

Checklist da API para cada endpoint:
- [ ] 404 cross-tenant com corpo idêntico ao de um id inexistente;
- [ ] tentativa de injetar tenant (`clientId` no body ou na query de `/me/*`) → 400 (`.strict()`);
- [ ] papel errado → 403 `FORBIDDEN` (cliente em `/admin/*`, CEO em `/me/*`);
- [ ] pendência não permitida → 403 com o `code` da pendência;
- [ ] resposta de `/me/*` validada contra o contrato (`additionalProperties: false` pega campo interno vazado).
