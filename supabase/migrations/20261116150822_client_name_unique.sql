-- Spec: docs/specs/client-delivery-tracker.md §3.7, §3.7.1, §4.3, E-40 a E-46 — nome de cliente único
-- entre os não arquivados (F-51, decisão (a) do usuário em 2026-11-16; threat model T-33).
--
-- Antes: dois `create_client` com o mesmo nome criavam dois clientes, e um retry depois de um 503
-- (o COMMIT já tinha acontecido) duplicava o cliente. Os dois erros facilitam escolher o tenant errado
-- ao provisionar um login (Onda 7). Agora o banco recusa o segundo nome: `CLIENT_NAME_TAKEN`
-- (`P0001`), que o app mapeia para 409 `CONFLICT`.
--
-- A chave do nome: `lower(normalize(name, NFKC))`, sem as marcas de variação invisíveis e com cada
-- sequência de espaços reduzida a um só.
-- - `normalize(.., NFKC)` junta as formas de compatibilidade ("Ａｃｍｅ" de largura total, ligaduras,
--   sobrescritos, NBSP e U+3000 internos viram espaço). Os nomes já estão em NFC por
--   `private.visible_text`; o NFKC da chave é mais forte e só vale para comparar: o nome guardado e
--   mostrado continua o que o CEO digitou (em NFC).
-- - `lower` ignora maiúsculas e minúsculas. O Postgres 17 não tem `casefold()` (chega no 18): "ß" e
--   "ss", ou "ς" e "σ", seguem distintos, e letras de outro alfabeto parecidas com as latinas (o "А"
--   cirílico) também (residual do T-33).
-- - `regexp_replace(.., U&'[\034F\180B-\180F\FE00-\FE0F\+0E0100-\+0E01EF]', '')` tira o que o NFKC
--   mantém e `visible_text` aceita, e que não se vê: U+034F (junção de grafemas), os seletores de
--   variação do mongol (U+180B a U+180D e U+180F), VS1 a VS16 (U+FE00 a U+FE0F) e VS17 a VS256
--   (U+E0100 a U+E01EF). "Acme" e "Ac" + U+034F + "me" têm a mesma chave. Só a chave perde essas
--   marcas: o nome guardado as mantém (o seletor de emoji, U+FE0F, é legítimo num nome).
-- - `regexp_replace(.., U&'[ \1680]+', ' ')` junta os espaços repetidos, que o HTML mostra como um só.
--   Depois do NFKC só sobram o U+0020 e o U+1680; as pontas já vêm aparadas e tabulação, quebra de
--   linha e demais controles são recusados por `visible_text`. Vem depois da retirada das marcas, para
--   "a", U+0020, U+034F, U+0020, "b" virar "a b".
-- As funções da expressão (`lower`, `normalize`, `regexp_replace`) são IMMUTABLE; o Postgres recusaria
-- o índice se não fossem. O resultado depende do locale do banco (o `lower` de "É" e de "Α" só dobra
-- se o locale for Unicode: o pgTAP 014 confere) e das tabelas Unicode do `normalize` e do `lower`, que
-- mudam com a versão do ICU ou com um upgrade maior do Postgres. Depois de qualquer um dos dois, rode
-- `REINDEX INDEX public.clients_active_name_key`: um índice com a chave antiga deixaria passar, ou
-- recusaria, nomes que a chave nova trata de outro jeito. A Onda 11 confere o locale do banco
-- hospedado antes de aplicar esta migration.
--
-- Se algum banco já tem dois clientes ativos com o mesmo nome, o CREATE UNIQUE INDEX falha e a
-- migration inteira volta: arquive ou renomeie um deles (pelo app) e aplique de novo. Nem o seed local
-- nem as fixtures dos testes têm nomes repetidos.

-- Índice único parcial: nome de cliente único entre os ativos. Caso de uso: `create_client`, e
-- `update_client` ao renomear ou desarquivar; a violação vira 409 `CONFLICT` (E-40 a E-45). Arquivar
-- tira a linha do índice e libera o nome.
CREATE UNIQUE INDEX clients_active_name_key ON public.clients (
  (regexp_replace(
     regexp_replace(
       lower(normalize(name, NFKC)),
       U&'[\034F\180B-\180F\FE00-\FE0F\+0E0100-\+0E01EF]', '', 'g'),
     U&'[ \1680]+', ' ', 'g'))
) WHERE archived_at IS NULL;
COMMENT ON INDEX public.clients_active_name_key IS
  'Caso de uso: nome de cliente único entre os não arquivados (create_client, update_client ao renomear ou desarquivar; 409 CONFLICT, F-51). Chave: lower(normalize(name, NFKC)) sem marcas de variação invisíveis e com espaços repetidos reduzidos a um.';

-- Cria o cliente. Evento `client.created`. Nome já usado por um cliente não arquivado:
-- `CLIENT_NAME_TAKEN`, sem evento (a transação inteira falha).
--
-- A exclusão é do índice, não de uma consulta prévia: duas chamadas concorrentes com o mesmo nome não
-- passam as duas (a segunda espera a primeira e leva a violação). O handler só traduz a violação do
-- NOSSO índice, pelo esquema, pela tabela e pelo nome do constraint; qualquer outra violação sobe como
-- está (23505 bruto). A mensagem original
-- ("Key (...)=(<nome normalizado>) already exists") não sai: o erro novo não carrega o nome nem o id do
-- outro cliente.
CREATE OR REPLACE FUNCTION public.create_client(p_name text)
RETURNS public.clients
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_name       text;
  v_row        public.clients;
  v_schema     text;
  v_table      text;
  v_constraint text;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  v_name := private.visible_text(p_name, 160);
  IF v_name IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;

  BEGIN
    INSERT INTO public.clients (name)
    VALUES (v_name)
    RETURNING * INTO v_row;
  EXCEPTION WHEN unique_violation THEN
    GET STACKED DIAGNOSTICS v_schema = SCHEMA_NAME, v_table = TABLE_NAME, v_constraint = CONSTRAINT_NAME;
    IF v_schema IS DISTINCT FROM 'public'
       OR v_table IS DISTINCT FROM 'clients'
       OR v_constraint IS DISTINCT FROM 'clients_active_name_key' THEN
      RAISE;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'CLIENT_NAME_TAKEN';
  END;

  PERFORM private.record_audit_event('ceo', 'client.created', 'client', v_row.id, v_row.id, NULL);

  RETURN v_row;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.create_client(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_client(text) TO authenticated;

-- Renomeia, arquiva ou desarquiva. NULL em `p_name` ou `p_archived` = "não mexe"; os dois NULL é
-- entrada inválida. Só audita e só toca `updated_at` quando algo muda de fato (como
-- `set_account_disabled`): renomear para o mesmo nome (depois da normalização) ou arquivar um
-- cliente já arquivado devolve a linha como está, e uma chamada assim nunca dá `CLIENT_NAME_TAKEN`.
-- `p_archived = true` mantém o `archived_at` original de um cliente que já estava arquivado. Arquivar
-- não desativa os logins (Q-08).
-- `FOR NO KEY UPDATE`: serializa com as outras escritas do cliente e com o gatilho de perfil
-- (`FOR UPDATE`), mas não trava quem só referencia o cliente por FK (processos, perfis).
--
-- Nome único (F-51): o conflito vale pelo estado FINAL da linha, que é o que o índice vê. Renomear e
-- arquivar na mesma chamada não disputa o nome (o cliente sai do índice); desarquivar disputa o nome
-- que o cliente tem naquele momento (ou o novo, se vier junto); renomear para outra grafia do próprio
-- nome (maiúsculas, espaços) não conflita com a própria linha. A violação do índice vira
-- `CLIENT_NAME_TAKEN` e a transação inteira falha, então nenhum dos dois eventos de auditoria é
-- gravado (eles vêm depois do UPDATE).
-- Dois renames que se cruzam ao mesmo tempo (A para o nome de B, B para o nome de A) esperam um pelo
-- índice do outro: o Postgres detecta o deadlock e derruba uma das transações (40P01). Isso não é
-- capturado aqui; sobe como está, e o app o mapeia para 503 (a transação voltou inteira, sem
-- auditoria, e repetir é seguro). A outra termina em `CLIENT_NAME_TAKEN`.
CREATE OR REPLACE FUNCTION public.update_client(
  p_client_id uuid,
  p_name      text DEFAULT NULL,
  p_archived  boolean DEFAULT NULL
)
RETURNS public.clients
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_name            text;
  v_row             public.clients;
  v_renamed         boolean;
  v_archive_changed boolean;
  v_schema          text;
  v_table           text;
  v_constraint      text;
BEGIN
  IF private.is_ceo() IS NOT TRUE THEN
    RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'FORBIDDEN';
  END IF;

  IF p_name IS NULL AND p_archived IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
  END IF;
  IF p_name IS NOT NULL THEN
    v_name := private.visible_text(p_name, 160);
    IF v_name IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'INVALID_INPUT';
    END IF;
  END IF;

  SELECT c.id, c.name, c.archived_at, c.created_at, c.updated_at
    INTO v_row
    FROM public.clients c
   WHERE c.id = p_client_id
     FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'NOT_FOUND';
  END IF;

  v_renamed := v_name IS NOT NULL AND v_name IS DISTINCT FROM v_row.name;
  v_archive_changed := p_archived IS NOT NULL AND p_archived IS DISTINCT FROM (v_row.archived_at IS NOT NULL);

  IF NOT v_renamed AND NOT v_archive_changed THEN
    RETURN v_row;
  END IF;

  BEGIN
    UPDATE public.clients c
       SET name = CASE WHEN v_renamed THEN v_name ELSE c.name END,
           archived_at = CASE
                           WHEN NOT v_archive_changed THEN c.archived_at
                           WHEN p_archived THEN now()
                         END,
           updated_at = now()
     WHERE c.id = p_client_id
    RETURNING * INTO v_row;
  EXCEPTION WHEN unique_violation THEN
    GET STACKED DIAGNOSTICS v_schema = SCHEMA_NAME, v_table = TABLE_NAME, v_constraint = CONSTRAINT_NAME;
    IF v_schema IS DISTINCT FROM 'public'
       OR v_table IS DISTINCT FROM 'clients'
       OR v_constraint IS DISTINCT FROM 'clients_active_name_key' THEN
      RAISE;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'CLIENT_NAME_TAKEN';
  END;

  IF v_renamed THEN
    PERFORM private.record_audit_event(
      'ceo', 'client.updated', 'client', v_row.id, v_row.id, NULL, '{"fields":["name"]}'::jsonb
    );
  END IF;
  IF v_archive_changed THEN
    PERFORM private.record_audit_event(
      'ceo',
      CASE WHEN p_archived THEN 'client.archived' ELSE 'client.unarchived' END,
      'client', v_row.id, v_row.id, NULL
    );
  END IF;

  RETURN v_row;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.update_client(uuid, text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.update_client(uuid, text, boolean) TO authenticated;
