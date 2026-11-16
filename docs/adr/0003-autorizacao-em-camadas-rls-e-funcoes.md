# ADR 0003 — Autorização em três camadas: pipeline, funções `SECURITY DEFINER` e RLS

- **Status:** accepted
- **Data:** 2026-11-15

## Contexto

O requisito central é que um cliente nunca veja o processo de outro, e que só CEOs avancem
fases. Uma barreira única (só o app ou só o RLS) é um ponto único de falha. Além disso, a
aprovação de fase precisa ser atômica sob concorrência (dois CEOs clicando ao mesmo tempo), o
que exige transação e lock, coisa que uma chamada PostgREST simples não oferece.

Opções avaliadas para a escrita:

1. Policies de `INSERT/UPDATE` para CEOs + escrita direta via PostgREST. O CEO poderia contornar
   as regras (pular fases, forjar o aprovador) chamando o PostgREST com o próprio JWT.
2. App com secret key (ignorando RLS) para tudo. Uma barreira só; um bug vira vazamento.
3. **Funções `SECURITY DEFINER` como único caminho de escrita**, chamadas com o JWT do usuário.

## Decisão

- **Camada 1, pipeline HTTP (`withRoute`):** autenticação, papel, pendências, Origin, rate limit
  e validação. O caso de uso confere a posse do recurso.
- **Camada 2, funções do banco (escrita):** toda escrita é uma função `SECURITY DEFINER` com
  `SET search_path = ''`, nomes qualificados, `REVOKE EXECUTE … FROM PUBLIC, anon`, checagem de
  `private.is_ceo()` (papel `ceo` + `aal2` + sessão viva + perfil ativo), validação de input,
  `SELECT … FOR UPDATE` e auditoria na mesma transação.
- **Camada 3, RLS (leitura):** RLS habilitado em todas as tabelas de `public`; policies somente
  `SELECT`; clientes restritos ao próprio tenant via `private.current_client_id()`; CEOs `aal2`
  leem tudo. `anon` não tem privilégio algum; `authenticated` não tem `INSERT/UPDATE/DELETE`.
- **Separação de colunas:** tabelas visíveis ao cliente contêm apenas colunas seguras para ele;
  dados internos (aprovador, auditoria) ficam em tabelas exclusivas de CEO.
- **Secret key** só para a Auth Admin API (criar usuário, definir senha, banir) e para
  `rate_limit_hit`, num único módulo `server-only`.
- O agregado `Process` em TypeScript também valida as invariantes (falha rápido, com erros
  claros); o banco é a autoridade final sob concorrência.

## Consequências

- **Positivas:** defesa em profundidade real (um bug numa camada não vaza dados); invariantes
  garantidas pelo banco; acesso direto ao PostgREST não dá mais poder do que o BFF.
- **Negativas:** parte da regra de negócio existe em PL/pgSQL e em TypeScript (duplicação
  consciente, coberta por testes nas duas pontas); migrations exigem disciplina (hook e agent
  `rls-auditor`).
- **Testes obrigatórios:** pgTAP para cada policy e função, incluindo cross-tenant, `anon`,
  `aal1` e append-only.
