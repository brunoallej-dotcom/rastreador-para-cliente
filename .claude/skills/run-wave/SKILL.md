---
name: run-wave
description: Abre, executa e fecha uma onda do plano (docs/plan/implementation-waves.md). Confere dependências, cria a branch, carrega critérios de aceite e goal command e, no fim, roda os gates e os agents de revisão e sincroniza o status no plano e no NOTES.md. Use quando o usuário disser "começar a onda N", "próxima onda" ou "/run-wave".
argument-hint: "[número-da-onda | next]"
disable-model-invocation: true
---

Onda pedida: $ARGUMENTS (vazio ou `next` = próxima elegível).

## 1. Abrir

1. Leia `NOTES.md` e `docs/plan/implementation-waves.md`. Se as tabelas divergirem, pare e
   aponte a divergência (o plano é a fonte da verdade).
2. Escolha a onda: o número informado, ou a primeira ⬜ cujas dependências estejam todas ✅.
3. Confira as dependências. Se alguma não estiver ✅, pare e informe o que falta. Ondas
   "paralelas" só podem rodar juntas em worktrees separadas.
4. Confira o git: árvore limpa e `main` atualizada. Se houver mudanças não commitadas, pergunte
   antes de seguir. Crie a branch `feat/wave-<n>-<slug>`.
5. Carregue o contexto mínimo: a seção da onda no plano, as seções da spec citadas, os critérios
   de aceite (AC-xx e E-xx), as operações do contrato envolvidas e os ADRs relevantes.
6. Marque a onda como 🟡 no plano **e** no `NOTES.md`.
7. Mostre ao usuário: objetivo, escopo, critérios de aceite e o **Goal command**. Sugira rodá-lo
   (`/goal …`) para manter a sessão presa aos critérios.

## 2. Executar

- Ordem do slice: spec (só leitura; se faltar detalhe, atualize a spec primeiro) → contrato
  (só leitura; mudança exige bump e confirmação do usuário) → domain → application →
  infrastructure → presentation → testes.
- Banco: use a skill `new-migration`. Isolamento: `tenant-isolation-tests`. Endpoints:
  `new-endpoint`.
- Mantenha-se no escopo de arquivos da onda. Arquivo fora do escopo, sobretudo se pertencer a
  uma onda paralela, exige perguntar antes.
- Testes de aceite levam o ID no nome (`AC-xx`, `E-xx`).

## 3. Fechar

1. Rode os gates: `pnpm verify` mais os comandos específicos da onda (os do Goal command).
2. Rode os agents conforme o caso:
   - tocou `supabase/` → `rls-auditor`;
   - tocou rota, schema ou contrato → `contract-guardian`;
   - sempre → `code-reviewer` (plugin AISAC).
   Achado CRÍTICO ou ALTO bloqueia o fechamento.
3. Rode a skill `verify`.
4. Só então marque a onda como ✅ no plano **e** no `NOTES.md`, atualize "Status atual" e
   "Próxima onda", e acrescente uma entrada no "Log de sessões" (o que foi feito, como foi
   verificado e o que ficou pendente).
5. Proponha a mensagem de commit (Conventional Commit em inglês) e o texto do PR. **Commit, push e
   PR só com confirmação explícita do usuário.**

Se algum critério de aceite não puder ser verificado por comando, não marque ✅: registre o
motivo no `NOTES.md` e pergunte ao usuário.
