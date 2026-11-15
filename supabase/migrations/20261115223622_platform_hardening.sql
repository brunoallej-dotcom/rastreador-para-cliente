-- Spec: docs/specs/client-delivery-tracker.md §2.3 (SEC-04, SEC-20), §4 — superfície mínima e
-- privilégios padrão. Nenhum objeto criado depois desta migration nasce acessível a anon ou
-- authenticated: cada migration concede explicitamente o que precisa.

-- Superfície mínima (SEC-20) ---------------------------------------------------
DROP EXTENSION IF EXISTS pg_graphql;

-- Privilégios padrão dos objetos criados pelo papel das migrations (postgres) --------
-- O padrão do Supabase concede tudo a anon e authenticated em public.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM anon, authenticated;
-- Funções: EXECUTE só para o papel necessário, concedido explicitamente (§3.7), inclusive service_role.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Schema privado (não exposto pelo PostgREST) --------------------------------------
-- authenticated precisa de USAGE para as policies chamarem os helpers de RLS.
CREATE SCHEMA private;
REVOKE ALL ON SCHEMA private FROM PUBLIC, anon;
GRANT USAGE ON SCHEMA private TO authenticated;

-- Enums (§4) ---------------------------------------------------------------------
CREATE TYPE public.app_role AS ENUM ('ceo', 'client');
CREATE TYPE public.process_status AS ENUM ('active', 'completed', 'cancelled');
CREATE TYPE public.stage_status AS ENUM ('pending', 'in_progress', 'completed');
