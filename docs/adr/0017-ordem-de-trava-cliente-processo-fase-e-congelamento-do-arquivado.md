# ADR 0017 — Ordem de trava cliente, processo, fase, e o congelamento dos processos do cliente arquivado

- **Status:** accepted (ajusta o §3.7.3 da spec da Onda 9, que dizia que nada trava `public.clients`)
- **Data:** 2026-11-18

## Contexto

Duas decisões de produto do usuário (2026-11-17) entraram na Onda 10.2:

- **F-87 (Q-13):** arquivar o cliente congela os processos que ele já tem. Aprovar a fase, renomear e cancelar
  respondem 422 `CLIENT_ARCHIVED`; a leitura continua e desarquivar descongela.
- **F-80 (Q-14):** o título de um processo é único entre os ativos do cliente (índice único parcial, 409).

A spec previa, para o F-87, ler o `archived_at` do cliente num `JOIN` da própria consulta que trava o processo
(`FOR NO KEY UPDATE OF p`), sem travar `public.clients`, porque travar o cliente **depois** do processo inverteria a
ordem de `create_process` (cliente, depois o processo que ele insere). A análise da corrida com o arquivamento
(threat model F-120, F-121) mostrou dois problemas nesse desenho:

1. No `READ COMMITTED`, depois de esperar a trava do processo, a reavaliação refaz só a linha travada. O `archived_at`
   do `JOIN` seria o do **começo** da consulta, e uma aprovação parada atrás de outra passaria sobre um arquivamento
   que gravou durante a espera: a janela é do tamanho da espera. Verificado por mutação: sem a trava do cliente
   (mesmo relendo o `archived_at` depois da trava do processo), os testes de API da corrida com o arquivamento
   (E-101) falham, porque a aprovação não espera o arquivamento em andamento.
2. Com o índice de título (F-80), a ordem "processo, depois cliente" deixa de ser só feia: `create_process` segura o
   cliente e o `INSERT` espera, no índice, um renome ainda não gravado; se esse renome já segurasse o processo e
   pedisse o cliente, as duas esperariam uma pela outra.

## Decisão

- **A ordem de trava do módulo é de pai para filho: cliente, processo, fase**, em toda função de escrita.
- `update_process` e `approve_current_stage` leem o `client_id` do processo **sem trava** (nenhuma função o
  escreve), travam o cliente com **`FOR SHARE`** (e leem o `archived_at` já com a trava), travam o processo com `FOR
  NO KEY UPDATE`, conferindo o `client_id` lido, e só então (a aprovação) a fase em andamento. `create_process`
  segue com `FOR NO KEY UPDATE` no cliente. Nunca `FOR UPDATE`, e nunca `FOR SHARE` seguido de `FOR NO KEY UPDATE`
  na mesma linha de cliente (uma troca de trava que duas transações esperariam).
- **`CLIENT_ARCHIVED` vem depois de `NOT_FOUND` e antes de `PROCESS_NOT_ACTIVE`**, do título em uso e de
  `STALE_STAGE`: é a causa que o CEO resolve primeiro (desarquivar), e vale para o processo em qualquer status.
- **O título único é do índice**, e as duas funções trocam só a violação **dele** (esquema, tabela e nome do
  constraint) por `PROCESS_TITLE_TAKEN`, que o app mapeia para 409 `CONFLICT`. Qualquer outra violação única sobe
  como `23505` (500).

## Consequências

- Não há janela: nenhum processo muda depois de o `archived_at` do cliente ser gravado, a não ser que ele seja
  desarquivado. Um arquivamento em andamento faz a escrita esperar o COMMIT e responder `CLIENT_ARCHIVED`; um
  arquivamento que chega depois de uma escrita espera por ela.
- `FOR SHARE` não conflita com `FOR SHARE`: duas aprovações (ou renomes) de processos do mesmo cliente não esperam
  uma pela outra. Custo: elas esperam um `update_client`, um `create_process` ou o gatilho do perfil do mesmo
  cliente, que duram milissegundos, e a linha do cliente ganha uma marca de trava compartilhada (sem versão nova).
- **Regra para funções futuras:** quem trava processo e fase trava antes o cliente. O pgTAP (016, 017 e 022) confere a
  ordem e a ausência de `FOR UPDATE` no catálogo, e os testes de API provam as duas direções com uma sessão do banco
  que segura a trava, sem `sleep`.
- Dois renomes que se cruzam (P1 para o título do P2 e o P2 para o do P1) dão deadlock no índice: 503, e a outra
  termina em 409 (E-102).

## Alternativas rejeitadas

- **`JOIN` com `FOR NO KEY UPDATE OF p`** (o desenho da spec): deixa a janela do item 1 e só a documentaria como
  residual.
- **Travar o cliente depois do processo:** deadlock com `create_process` (item 2).
- **`SERIALIZABLE`:** devolveria `40001` em disputas que hoje se resolvem esperando, e o 503 seria o caso comum, não o
  raro.
- **`Idempotency-Key` para o F-80:** uma tabela de chaves, um cabeçalho novo e um segundo caminho para o mesmo
  problema, quando o título único já resolve o retry.
