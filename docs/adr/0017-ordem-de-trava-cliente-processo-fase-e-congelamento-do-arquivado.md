# ADR 0017 — Ordem de trava cliente, processo, fase, e o congelamento dos processos do cliente arquivado

- **Status:** accepted (ajusta o §3.7.3 da spec da Onda 9, que dizia que nada trava `public.clients`)
- **Data:** 2026-11-18

## Contexto

Duas decisões de produto do usuário (2026-11-17) entraram na Onda 10.2:

- **F-87 (Q-13):** arquivar o cliente congela os processos que ele já tem. Aprovar a fase, renomear e cancelar
  respondem 422 `CLIENT_ARCHIVED`; a leitura continua e desarquivar descongela.
- **F-80 (Q-14):** o título de um processo é único entre os ativos do cliente (índice único parcial, 409).

A spec previa, para o F-87, ler o `archived_at` do cliente num `JOIN` da própria consulta que trava o processo
(`FOR NO KEY UPDATE OF p`), sem travar `public.clients`. A análise da corrida com o arquivamento (threat model F-120)
mostrou que esse desenho deixa uma janela:

1. No `READ COMMITTED`, depois de esperar a trava do processo, a reavaliação refaz só a linha travada. O `archived_at`
   do `JOIN` seria o do **começo** da consulta, e uma aprovação parada atrás de outra passaria sobre um arquivamento
   que gravou durante a espera: a janela ia do instante da consulta até o COMMIT. Verificado por mutação: sem a trava
   do cliente (mesmo relendo o `archived_at` depois da trava do processo), os testes de API da corrida com o
   arquivamento (E-101) falham, porque a aprovação não espera o arquivamento em andamento.
2. Travar o cliente **depois** do processo não é a saída. Não por um deadlock com o índice de título (uma linha só
   travada, ainda não atualizada, não faz a checagem de unicidade esperar: o `create_process` receberia `23505` na
   hora, e um renome só escreve a entrada do índice depois de segurar as duas travas), mas porque a ordem processo,
   cliente seria a **segunda** convenção do módulo. A `create_process` já trava o cliente primeiro; uma regra só,
   de pai para filho, é mais fácil de conferir e de manter.

## Decisão

- **A ordem de trava do módulo é de pai para filho: cliente, processo, fase**, em toda função de escrita. Quem
  segura o cliente em modo **exclusivo** (`update_client`, `create_process`, o gatilho do perfil) nunca espera por
  processo nem por fase, e quem segura o processo já passou pelo cliente: não há ciclo de espera além do dos renomes
  cruzados (F-123).
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
- **Regra para funções futuras:** quem escreve em processo, fase ou aprovação trava antes o cliente com `FOR SHARE` e
  recusa o arquivado. O pgTAP 022 guarda isso com um inventário fixo dos escritores (hoje `create_process`,
  `update_process` e `approve_current_stage`): uma função nova que escreva ali falha o teste até alguém decidir a trava
  (T-56, F-124). Os testes de API provam as duas direções da corrida com uma sessão do banco que segura a trava, sem
  `sleep`, e o pgTAP confere a ordem das funções que existem.
- **Custo da trava compartilhada:** cada escrita grava um `xmax` na linha do cliente, e aprovações simultâneas do mesmo
  cliente criam MultiXacts. Desprezível na escala do §2.2 (poucos CEOs, dezenas de escritas por minuto).
- **Inanição teórica (F-126, aceita):** um `FOR SHARE` que só encontra outras travas compartilhadas passa na frente
  de um `FOR NO KEY UPDATE` na fila. Aprovações e renomes sobrepostos, sem parar, de um mesmo cliente poderiam atrasar
  um arquivamento ou um `create_process` até o `statement_timeout` (503). Com 4 CEOs humanos a probabilidade é baixa.
- **Efeito de ordenação sem consequência (F-125):** `approved_at` e `archived_at` são cada um o `now()` do começo da sua
  transação. Um arquivamento que começou antes e pegou a trava depois da aprovação deixa os dois instantes invertidos
  por milissegundos. A ordem dos fatos é a do `id` da auditoria.
- Dois renomes que se cruzam (P1 para o título do P2 e o P2 para o do P1) dão deadlock no índice: 503, e a outra
  termina em 409 (E-102).

## Alternativas rejeitadas

- **`JOIN` com `FOR NO KEY UPDATE OF p`** (o desenho da spec): deixa a janela do item 1 e só a documentaria como
  residual.
- **Travar o cliente depois do processo:** fecharia a janela, mas contra a ordem de `create_process` e dos demais, e
  teria duas convenções de trava no módulo (item 2 do contexto).
- **`SERIALIZABLE`:** devolveria `40001` em disputas que hoje se resolvem esperando, e o 503 seria o caso comum, não o
  raro.
- **`Idempotency-Key` para o F-80:** uma tabela de chaves, um cabeçalho novo e um segundo caminho para o mesmo
  problema, quando o título único já resolve o retry.
