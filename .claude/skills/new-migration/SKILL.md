---
name: new-migration
description: Cria uma migration Supabase/Postgres seguindo as regras de segurança do projeto (RLS, policies só SELECT, escrita só por funções SECURITY DEFINER com search_path vazio, REVOKE de PUBLIC, auditoria na mesma transação) junto com o teste pgTAP correspondente. Use quando for criar ou alterar tabela, policy, função, trigger, índice ou grant em supabase/.
argument-hint: "<nome_em_snake_case> [descrição]"
---

Migration: $ARGUMENTS

## Antes de escrever

1. Confira na spec (§4 e §3.7) se o objeto já está descrito. Se não estiver, atualize a spec
   primeiro.
2. **Nunca edite uma migration que já está na `main`** (o hook `guard-writes` bloqueia). Para
   corrigir, crie uma nova.
3. Crie o arquivo com `pnpm db:new <nome>` (timestamp correto). Não invente o nome à mão.

## Regras (o hook `post-edit-checks` verifica as marcadas com ✓)

- ✓ Toda `CREATE TABLE public.*` vem com `ALTER TABLE … ENABLE ROW LEVEL SECURITY`.
- ✓ Policies só `FOR SELECT … TO authenticated` (policy sem `FOR` vale como `ALL` e é recusada).
- ✓ Nenhum `GRANT … TO anon`; nenhum `INSERT/UPDATE/DELETE/TRUNCATE/ALL` para `authenticated`.
- ✓ `SECURITY DEFINER` sempre com `SET search_path = ''`, e nomes qualificados no corpo.
- ✓ Toda função tem `REVOKE EXECUTE ON FUNCTION … FROM PUBLIC, anon` (exceto as de trigger).
- ✓ Sem SQL dinâmica por concatenação (`EXECUTE … || …`); se inevitável, `format('%I', …)` +
  `EXECUTE … USING`.
- Funções de escrita: primeiro `private.is_ceo()` (ou checagem do próprio usuário), depois a
  validação de input espelhando o Zod, `SELECT … FOR UPDATE`, a mudança e a auditoria na mesma
  transação.
- Tenant e ator vêm de `auth.uid()`, nunca de parâmetro.
- Auditoria: use `private.record_audit_event(papel, ação, tipo, recurso, cliente, processo)`;
  nunca `INSERT` direto em `audit_events` (nem a secret key tem esse privilégio).
- Privilégios: os defaults (Onda 2) já tiram tudo de `anon`, `authenticated` e, em funções, de
  `service_role`; conceda explicitamente só o necessário (`GRANT SELECT … TO authenticated`,
  `GRANT EXECUTE … TO authenticated`). Tabela nova: `REVOKE ALL … FROM anon, authenticated,
  service_role` e depois só o `GRANT SELECT … TO authenticated` (a secret key não tem privilégio
  algum em tabela de negócio, ADR 0016; o padrão do dono das migrations já não concede nada a ela,
  mas o `REVOKE` explícito não custa e o pgTAP 019 confere). Toda relação de `public` é do `postgres`:
  o privilégio padrão revogado é o dele.
- Texto visível (nomes, títulos): mesma regra dos CHECKs existentes, copie a classe exatamente de
  `supabase/migrations/20261115223625_identity_core.sql` (controle + formatação Unicode, E-30),
  sempre com escapes `\uXXXX`/`\UXXXXXXXX`, nunca caracteres invisíveis literais.
- Erros: `RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN'` para autorização;
  `ERRCODE = 'P0001'` com `MESSAGE` do catálogo (`NOT_FOUND`, `STALE_STAGE`,
  `PROCESS_NOT_ACTIVE`, `CLIENT_ARCHIVED`, `INVALID_INPUT`) para regra de negócio.
- Estilo: keywords em MAIÚSCULAS, `snake_case`, colunas explícitas, comentário em todo índice
  explicando o caso de uso.

## Modelo

```sql
-- Spec: docs/specs/client-delivery-tracker.md §4 — <o que esta migration faz>

-- Tabela -------------------------------------------------------------------
CREATE TABLE public.example (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id  uuid NOT NULL REFERENCES public.clients (id) ON DELETE RESTRICT,
  name       text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 120),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.example ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.example FROM anon, authenticated;
GRANT SELECT ON public.example TO authenticated;

-- Índice: lista de exemplos por cliente (aba do cliente no painel de CEO)
CREATE INDEX example_client_id_idx ON public.example (client_id);

-- Policies (somente leitura) ----------------------------------------------------
CREATE POLICY example_select_own_tenant ON public.example
  FOR SELECT TO authenticated
  USING (client_id = (SELECT private.current_client_id()));

CREATE POLICY example_select_ceo ON public.example
  FOR SELECT TO authenticated
  USING ((SELECT private.is_ceo()));

-- Função de escrita (único caminho de escrita) ----------------------------------
CREATE OR REPLACE FUNCTION public.create_example(p_client_id uuid, p_name text)
RETURNS public.example
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_row public.example;
BEGIN
  IF NOT private.is_ceo() THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_name IS NULL OR char_length(btrim(p_name)) NOT BETWEEN 1 AND 120 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  PERFORM 1 FROM public.clients c WHERE c.id = p_client_id AND c.archived_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  INSERT INTO public.example (client_id, name)
  VALUES (p_client_id, btrim(p_name))
  RETURNING * INTO v_row;

  INSERT INTO public.audit_events (actor_id, actor_role, action, resource_type, resource_id, client_id, request_id)
  VALUES (auth.uid(), 'ceo', 'example.created', 'example', v_row.id, v_row.client_id, private.request_id());

  RETURN v_row;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.create_example(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_example(uuid, text) TO authenticated;
```

## Teste obrigatório no mesmo PR

Crie ou atualize `supabase/tests/<area>.test.sql` usando a skill `tenant-isolation-tests`:
cross-tenant, `anon`, escrita direta negada, função de CEO negada para cliente e para `aal1`,
`proconfig`/privilégios da função e o caminho feliz. O hook `stop-gates` lembra se faltar.

**Todo objeto de CEO novo (função, policy) precisa de um teste negativo com `p_attested => false`**
(`tests.authenticate_as(<ceo>, 'aal2', false)`): um CEO com o claim `aal2` mas sem o atestado do
backend (Onda 6.1, ADR 0013) é negado, com o positivo de controle logo depois (a mesma sessão, atestada,
passa). Sem isso um objeto novo pode aceitar uma `aal2` obtida direto no Auth sem ninguém notar. A
checagem de CEO é sempre `private.is_ceo()`; ler o claim `aal` do JWT numa função reprova o
`supabase/tests/001_privileges.test.sql`.

## Depois de escrever

```bash
pnpm db:reset && pnpm db:test && pnpm db:lint && pnpm db:types
```

Em seguida, rode o agent `rls-auditor` e corrija achados CRÍTICO e ALTO antes do PR. Se o modelo
mudou, atualize a spec (§4) no mesmo PR.
