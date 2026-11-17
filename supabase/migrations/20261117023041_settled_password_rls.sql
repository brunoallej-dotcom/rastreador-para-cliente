-- Spec: docs/specs/client-delivery-tracker.md §3.5, §3.5.1; threat model T-42, F-83 (Onda 10.1) — só
-- um usuário com a senha definitiva lê dados de negócio pelo RLS, e só um CEO com a senha definitiva
-- executa o que `is_ceo()` guarda.
--
-- O problema. `private.current_active_user_id()` aceita um login com a senha temporária pendente
-- (`profiles.must_change_password = true`, dentro das 72 h), e tem de aceitar: é ele que dá principal
-- ao `GET /auth/session`, à troca de senha (`mark_password_changed`) e ao logout. Mas `current_client_id()`
-- e `is_ceo()` se apoiavam nele sem olhar a pendência, então um cliente com a senha temporária lia os
-- próprios processos e fases direto pelo PostgREST, com o próprio JWT, sem passar pelo BFF que recusa
-- `/me/*` com `CHANGE_PASSWORD` pendente (403 `PASSWORD_CHANGE_REQUIRED`, E-81).
--
-- A decisão (a regra vale no banco, não só na camada de cima):
--   * `current_client_id()`, o tenant que as policies de `clients` (`clients_select_own_tenant`),
--     `processes` e `process_stages` usam, passa a exigir `NOT must_change_password`. Os chamadores foram
--     conferidos: só essas três policies a usam (nenhuma função de conta, e nenhum caminho de pendência).
--     `current_active_user_id()` NÃO muda: o principal do usuário pendente continua existindo.
--   * `is_ceo()` passa a exigir o mesmo. O atestado de um CEO com a senha pendente já era inalcançável
--     pelo produto (enroll e verify têm `allowPending` sem `CHANGE_PASSWORD`, então o BFF os recusa), mas
--     o banco não dizia isso: `attest_mfa_session` e `register_backend_totp_factor` não olham a
--     pendência. Com o predicado, uma sessão atestada de um CEO que volta a ter a senha temporária (um
--     reset de operador, ver F-41) não dá acesso de CEO até a troca, que `mark_password_changed` faz com
--     `session_is_attested()` diretamente, sem `is_ceo()`, então a troca e o atestado não dependem dele.
--     Nada que `is_ceo()` guarda é usado durante o cadastro do fator (as duas funções do atestado são do
--     `service_role` e não chamam `is_ceo()`).
--   * A leitura da própria linha de `clients`, que o `GET /auth/session` e o login mostram ao cliente
--     pendente (`SessionClient`: id e nome), sai da tabela e passa a uma função com a projeção mínima,
--     `current_client_summary()`: o login pendente não lê tabela de negócio alguma pelo PostgREST, mas a
--     sessão dele continua mostrando o nome do cliente. O app troca a leitura de `clients` por ela
--     (`getClientSummary`).
--
-- O que um login pendente ainda lê, de propósito: o próprio perfil (`profiles_select_self`, por
-- `current_active_user_id()`), `current_principal()` e `current_client_summary()`. Nada de outro
-- tenant e nenhuma linha de `clients`, `processes`, `process_stages` ou `stage_approvals`.

-- Tenant da sessão: só de um login plenamente ativo ---------------------------------------------------
-- Nulo para CEO, sessão morta, perfil desativado, senha temporária vencida (72 h) ou ainda pendente.
CREATE OR REPLACE FUNCTION private.current_client_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT p.client_id
    FROM public.profiles p
   WHERE p.id = private.current_active_user_id()
     AND p.role = 'client'
     AND NOT p.must_change_password;
$$;
REVOKE EXECUTE ON FUNCTION private.current_client_id() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.current_client_id() TO authenticated;

-- CEO: papel `ceo`, sessão viva, perfil ativo, senha definitiva e sessão ATESTADA (SEC-11) -------------------
-- Igual à da Onda 6.1, mais `NOT must_change_password`. Toda função de CEO e toda policy de CEO passam por
-- aqui, então um CEO que ainda tem a senha temporária não lê nem escreve nada de negócio.
CREATE OR REPLACE FUNCTION private.is_ceo()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT private.session_is_attested()
     AND EXISTS (
       SELECT 1
         FROM public.profiles p
        WHERE p.id = private.current_active_user_id()
          AND p.role = 'ceo'
          AND NOT p.must_change_password
     );
$$;
REVOKE EXECUTE ON FUNCTION private.is_ceo() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.is_ceo() TO authenticated;

-- O cliente do próprio login, com a projeção que a sessão mostra ---------------------------------------------
-- Vale também com a senha temporária pendente (é por `current_active_user_id()`, como o principal): o
-- login, o `GET /auth/session` e a troca de senha mostram o nome do cliente a quem acabou de entrar.
-- Devolve só `id` e `name` (o `SessionClient` do contrato), do cliente DO PRÓPRIO perfil: sem parâmetro,
-- então nenhum id vindo de fora escolhe a linha. Nenhuma linha para CEO, sessão morta, perfil desativado
-- ou senha temporária vencida.
CREATE FUNCTION public.current_client_summary()
RETURNS TABLE (
  id   uuid,
  name text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT c.id, c.name
    FROM public.profiles p
    JOIN public.clients c ON c.id = p.client_id
   WHERE p.id = private.current_active_user_id()
     AND p.role = 'client';
$$;
REVOKE EXECUTE ON FUNCTION public.current_client_summary() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.current_client_summary() TO authenticated;
