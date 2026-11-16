# Threat model — Rastreador de entregas (backend + banco)

> **Data:** 2026-11-15 (atualizado em 2026-11-16, Onda 3) · **Escopo:** API `/api/v1`, Supabase (Auth + Postgres), CI/CD e ferramentas
> de desenvolvimento · **Spec:** [`docs/specs/client-delivery-tracker.md`](../specs/client-delivery-tracker.md)
>
> Os controles citados (SEC-xx) estão definidos em §2.3 da spec. Atualize este documento sempre
> que a superfície de ataque mudar (rota nova, integração nova, papel novo).

## 1. Ativos

| Ativo | Por que importa |
|-------|-----------------|
| Dados de processo de cada cliente | Confidencialidade entre clientes concorrentes (vazamento cross-tenant é o pior cenário) |
| Contas de CEO | Uma conta de CEO lê tudo e avança processos de qualquer cliente |
| Integridade do fluxo de fases | Um "Ok" indevido muda o que o cliente vê e o que foi contratado |
| Trilha de auditoria | Prova de quem aprovou o quê (não repúdio) |
| `SUPABASE_SECRET_KEY` | Ignora RLS: comprometimento total do banco e do Auth |
| Dados pessoais (nome e e-mail) | LGPD |

## 2. Fronteiras de confiança e fluxo de dados

```mermaid
flowchart LR
  B[Browser do cliente ou CEO] -- "HTTPS, cookie HttpOnly" --> V["Vercel gru1<br/>Next.js BFF /api/v1"]
  V -- "HTTPS, publishable key + JWT do usuário" --> PG[("Supabase sa-east-1<br/>PostgREST → Postgres com RLS")]
  V -- "HTTPS, publishable key" --> AU[Supabase Auth]
  V -- "HTTPS, secret key (só admin-client.ts)" --> AD[Supabase Auth Admin API]
  OP[Operador com pnpm ceo:create] -- "secret key local" --> AD
  CI[GitHub Actions] -- "deploy" --> V
  DEV["Claude Code + MCP Supabase<br/>(read-only, projeto de dev)"] -. "OAuth" .-> PGD[("Supabase DEV")]
```

| Fronteira | Ameaça principal |
|-----------|------------------|
| Browser → BFF | Usuário malicioso autenticado (cliente curioso), CSRF, força bruta |
| BFF → PostgREST | Bug de autorização no app (mitigado por RLS e funções) |
| JWT do usuário → PostgREST direto | Usuário extrai o próprio JWT e chama o PostgREST sem passar pelo BFF |
| Secret key | Vazamento por log, commit, bundle do browser ou dependência maliciosa |
| CI/CD | Action ou dependência comprometida |
| Ferramentas de IA (MCP) | Prompt injection pelo conteúdo do banco; ação destrutiva |

## 3. STRIDE

| # | Elemento | STRIDE | Ameaça | Mitigação | Controles |
|---|----------|--------|--------|-----------|-----------|
| T-01 | Login | S | Força bruta e credential stuffing | Rate limit por IP (IPv6 agregado ao /64) e por conta, senha forte, HIBP, MFA de CEO. **Lacunas conhecidas:** o limite por IP só enxerga o /64, então um atacante com muitos prefixos escapa dele (o limite por conta e o teto global de T-03 cobrem o resto); o papel `client` não tem MFA (só CEO, SEC-11); o achado F-04 do threat-modeler fica para a Onda 11 | SEC-09, SEC-10, SEC-11 |
| T-02 | Login | I | Enumeração de e-mails | Resposta 401 idêntica (status, corpo e headers), sem cadastro público. **Tempo (F-05):** toda recusa de login responde só depois de um piso de 400 ms mais até 100 ms de jitter, medido do início do handler; o piso fica acima do caminho mais lento ("senha certa, conta desativada", cerca de 3 idas ao Auth), então senha errada, e-mail inexistente e conta desativada levam o mesmo tempo (se o Auth demorar mais que o piso, nada é somado). Com o provider de e-mail ligado, `/otp` e `/recover` do GoTrue seguem acessíveis a quem tiver a publishable key, que só existe no servidor (o browser nunca fala com o Supabase, ADR 0002); `/otp` e `/magiclink` não criam usuário (teste de integração). **Risco residual aceito:** `/otp` diferencia e-mail conhecido de desconhecido | SEC-12, SEC-20 |
| T-03 | Login | D | Esgotar a cota de logins do Supabase Auth (a cota `sign_in_sign_ups` conta por IP de origem e, atrás do BFF, o Auth só vê o IP do servidor) e derrubar o login de todos | Os limites por IP (20 / 15 min) e por conta **não** protegem essa cota contra um atacante distribuído: são por prefixo e por e-mail, e há muitos prefixos. **Teto global (F-02):** todo login gasta um orçamento `global` de 300 por 300 s antes de chamar o Auth, sempre abaixo da cota do Auth (1000 por 5 min no `config.toml` local; o projeto hospedado precisa ser configurado acima, Onda 11); acima dele, 429 `RATE_LIMITED` com `Retry-After`. **Residual aceito:** o teto troca um 503 por um 429 para todos durante o ataque, não impede a negação de serviço; o alerta de rajada de 429 (Onda 11) é a resposta | SEC-09 |
| T-04 | Login | D | Bloqueio direcionado: errar a senha de um CEO de propósito | Janela curta (15 min), sem bloqueio permanente, alerta. **Não mitigado, e sustentável:** 11 tentativas a cada 15 min, de qualquer IP, mantêm a conta bloqueada indefinidamente, não só a atrasam. **Decidido em 2026-11-16 (F-03): opção (c), cookie de dispositivo** (recomendação da OWASP): o navegador que já entrou com sucesso tem limite próprio e não é bloqueado pelo ataque à conta, e a força bruta continua limitada. Muda o §3.9 da spec; implementação na Onda 11. Até lá o risco segue aberto, com alerta | SEC-09 |
| T-05 | Sessão | S | Roubo de cookie via XSS | `HttpOnly`, CSP, API só JSON; frontend futuro com CSP de nonce | SEC-07, SEC-14 |
| T-06 | Sessão | S | Reuso de refresh token roubado; credencial roubada que vive para sempre | Rotação com detecção de reuso (Supabase revoga a família). A sessão vale no máximo 12 h e acaba após 4 h sem uso (ADR 0009): o Auth aplica `timebox` e `inactivity_timeout`, o banco repete os dois limites em `private.session_is_alive()` (F-08, migration `session_time_limits_in_db`), e o cookie vive 12 h | SEC-07 |
| T-07 | Sessão | E | JWT continua válido após logout ou desativação | `current_principal()` exige sessão viva em `auth.sessions` (dentro de 12 h e 4 h) e perfil ativo a cada requisição. O logout confirma no banco, antes do 204, que o token antigo já não tem principal (o client do Auth diz "deslogado" mesmo quando o Auth respondeu 401, 403 ou 404 sem revogar nada); se não confirmar, 503 e o cookie volta | SEC-07 |
| T-08 | Mutações | T | CSRF numa aprovação | SameSite=Lax, checagem de `Origin`, JSON obrigatório | SEC-08 |
| T-09 | `/me/*` | I | Cliente troca o `processId` (BOLA/IDOR) | Tenant derivado da sessão; filtro por tenant no repositório e RLS; 404 | SEC-03, SEC-05 |
| T-10 | `/me/*` | I | Cliente lê campos internos (quem aprovou) | Tabelas do cliente só com colunas seguras; dados internos em tabelas exclusivas de CEO; DTO explícito; contrato com `additionalProperties: false` | SEC-04 |
| T-11 | PostgREST direto | E | Cliente usa o próprio JWT para escrever ou ler fora do tenant | `authenticated` sem `INSERT/UPDATE/DELETE`; RLS somente `SELECT` por tenant; funções checam papel internamente | SEC-04 |
| T-12 | `/admin/*` | E | Cliente chama endpoint de CEO (BFLA) | Papel checado no pipeline **e** `private.is_ceo()` nas funções e policies | SEC-01, SEC-11 |
| T-13 | Contas | E | Criar ou promover um CEO pela API | Nenhum endpoint cria CEO; papel vem de `app_metadata` (só a secret key escreve); trigger recusa papel ausente; funções de conta recusam alvo CEO | RF-14, SEC-04 |
| T-14 | Contas | E | Usuário edita `user_metadata` para virar CEO | `raw_user_meta_data` nunca é lido para autorização | SEC-04 |
| T-15 | Banco | T | SQL injection (app, filtros PostgREST, funções) | Sem SQL no app; sem interpolação em `.or/.filter`; funções sem SQL dinâmico e com `search_path=''`; Zod `.strict()` | SEC-06 |
| T-16 | Banco | E | Hijack de `search_path` em função `SECURITY DEFINER` | `SET search_path = ''` com nomes qualificados, verificado por pgTAP | SEC-04, AC-25 |
| T-17 | Banco | E | Função nova executável por `PUBLIC` (padrão do Postgres) | `REVOKE EXECUTE … FROM PUBLIC, anon` em toda função, verificado por hook e pgTAP | SEC-04, AC-25 |
| T-18 | Aprovação | T | Dois CEOs aprovam ao mesmo tempo e o processo pula duas fases | `FOR UPDATE` + `expectedStageId` + índice único de fase atual | AC-17 |
| T-19 | Aprovação | R | CEO nega ter aprovado | `stage_approvals` + `audit_events` append-only na mesma transação, com `request_id` | SEC-16 |
| T-20 | Auditoria | T | Alterar ou apagar a trilha | `REVOKE UPDATE/DELETE/TRUNCATE` + trigger que bloqueia | AC-24 |
| T-21 | API | D | Payload gigante ou paginação sem limite | Corpo ≤ 16 KiB, tamanhos máximos, `limit` ≤ 100, rate limit por usuário | SEC-17, SEC-09 |
| T-22 | MFA | S/E | Força bruta e replay de TOTP, sondagem de ids de fator, fator extra para subir a `aal2`, fator removido com JWT `aal2` vivo, sequestro do primeiro cadastro (F-20 a F-24) | **Força bruta:** 5 / 5 min por usuário (da rota, cobra toda requisição, a que acerta também, antes de olhar o código; por usuário, não por IP) e **teto diário de 20 por usuário** (`totp-verify-daily`, orçamento do handler: sem ele 5 / 5 min dão 1.440 tentativas por dia, cerca de 8 meses até acertar; com ele, décadas) (F-22). **Replay (F-21, RFC 6238 seção 5.2):** o Auth aceita o mesmo código mais de uma vez na janela (~90 s); `consume_totp_code` queima o código (SHA-256 de `<fator>:<código>`) por 120 s, antes de o Auth ver o código, e só o dono do fator consome. **Sondagem:** código errado, vencido, já usado e fator de outro usuário ou inexistente respondem o mesmo 422 `INVALID_MFA_CODE`; o log distingue (`invalid_code`, `code_reused`, `factor_not_found`, `factor_ambiguous`). **Fator da sessão:** o `factorId` do corpo é opcional e obsoleto; sem ele o servidor lista os fatores TOTP **do próprio usuário** com a sessão dele (nenhum client admin) e usa o único verificado ou, não havendo, o único candidato; sem fator ou com mais de um no mesmo estado recusa com o mesmo 422, e nunca tenta o código em vários fatores. A identidade continua vindo da credencial, e `consume_totp_code` e os dois limites valem sobre o fator resolvido. **Fator extra:** quem já tem fator verificado leva 409, e o próprio Auth exige `aal2` para criar um fator (`insufficient_aal`), então uma sessão `aal1` roubada não se promove; um fator só (sem `friendly_name`). **Fator removido (F-24):** `private.is_ceo()` exige também um fator TOTP verificado, então remover o fator tira o acesso de CEO (RLS e funções) na hora, mesmo com um JWT `aal2` ainda válido. **Primeiro cadastro (F-20):** quem tem a senha (ou um cookie `aal1`) antes de o CEO cadastrar o TOTP pode substituir o fator candidato do CEO e verificar o próprio; quando um verify **ativa** o primeiro fator, as outras sessões do CEO são derrubadas (`signOut` com escopo `others`), e o CEO que tentar o fator antigo com `factorId` deixa `auth.mfa.failed` com `factor_not_found` no log (sem `factorId`, o servidor usa o fator do atacante e o log mostra `invalid_code`; o traço do sequestro continua em `auth.mfa.enrolled`, com `replacedFactors`, e em `auth.mfa.verified`, com `activated`). Resíduos: ver §7 e §8 | SEC-09, SEC-11 |
| T-23 | Erros | I | Stack trace ou erro SQL vazando estrutura | problem+json com `code` estável; mapeamento explícito; 500 genérico | SEC-13 |
| T-24 | Exceções | E | Falha numa checagem libera acesso (fail open) | Toda exceção em auth, authz ou rate limit nega a requisição | SEC-13, E-22 |
| T-25 | Segredos | I | Secret key no bundle do browser ou em log | Sem `NEXT_PUBLIC_`; `server-only`; uso restrito a um arquivo; redação de logs; gitleaks; hook. **F-12:** o singleton do admin client não é exportado: só uma fachada estreita (a Auth Admin API e o RPC `rate_limit_hit`), sem `.from`, `.rpc` genérico nem `.auth.signIn*`; o ESLint só deixa o rate limiter e a infraestrutura de identity importá-la | SEC-15, SEC-16 |
| T-26 | Supply chain | T | Dependência ou Action maliciosa | Lockfile, SHA pinado, Dependabot, `pnpm audit`, SAST, review de MCP e plugins | SEC-18 |
| T-27 | Ferramentas de IA | T/I | Conteúdo do banco (nome de cliente, fase) com prompt injection lido pelo agente via MCP | MCP read-only, só no projeto de dev, saída tratada como dado | SEC-18 |
| T-28 | Previews | I | Preview da Vercel apontando para dados de produção | Previews usam staging + Deployment Protection | §3.11 |
| T-29 | Sessão | D | Amplificação antes da autenticação: um cookie forjado (`{"access_token":"x","refresh_token":"y","expires_at":1}` basta) faz o servidor chamar o Auth (refresh, `getUser` ou busca de JWKS) a partir do IP da Vercel, sem limite algum antes da autenticação; um 429 do Auth derruba o refresh de todos os usuários legítimos (F-01). Variantes: `expires_at` como `"1"`, `null`, `0`, `-1` ou `Infinity`, cookie vazio mais chunk, chunk com buraco, token simétrico, sem `kid`, `kid` desconhecido | **Invariante:** toda chamada ao Auth feita ao resolver um principal é cobrada do orçamento por IP `session-upstream` (60 por 900 s, IPv6 no /64), e um IP sem orçamento não chega ao Auth. Três camadas. **(1) Predição que falha fechada** (`classifySession`): o cookie é lido como `@supabase/ssr` e o auth-js o leem (`combineChunks`, prefixo `base64-`, `JSON.parse`, `_isValidSession`, `hasExpired` com a mesma verdade e coerção numérica, `decodeJWT`, `validateExp`) e a resposta é "sem chamada" **só** quando se prova que não há chamada: nenhum cookie de sessão, ou token não vencido de algoritmo assimétrico (ES256/RS256) cujo `kid` foi visto verificando neste processo há menos de 5 min (metade do TTL de 10 min do cache de JWKS). Qualquer outra coisa, inclusive cookie presente e ilegível, gasta uma unidade antes de `getClaims()`. Acima do orçamento: 401 **sem apagar os cookies**, log `auth.rate_limited` e nenhuma chamada ao Auth. **(2) Recusa local (MÉDIO 2):** o que faria o auth-js lançar uma exceção que não é erro de autenticação (e viraria 500 para qualquer anônimo: algoritmo fora de HS*/ES256/RS256, `alg` que não é string, cabeçalho ou payload que não é JSON, token que não é string, `kid` conhecido com outro algoritmo) e o que ele rejeitaria sem chamar o Auth (`exp` ausente ou vencido) recebe 401 antes do cliente rodar, sem gastar orçamento. **(3) Medição:** o `fetch` do cliente da requisição conta as chamadas a `/auth/v1/`; o resolvedor compara a contagem antes e depois de `getClaims()` e cobra a diferença depois do fato (parando na primeira recusa), com o log `auth.session_budget_mispredicted` (nível warn, contagem e `ipHash`, nunca o cookie). Predição errada vira alerta, não brecha. **Segunda linha:** mesmo para um token que se verifica localmente, o resolvedor consulta a memória do limitador (`peekDenial`, sem contar, sem banco): IP já sabidamente sem orçamento recebe 401. Limitador que falha: 503 (fail closed). Se o Auth responde 429 ao refresh, 503 e o cookie é mantido. Um `kid` é esquecido se a verificação falha depois de uma chamada ao Auth ou com qualquer erro que não seja `AuthInvalidJwtError`, nunca por uma simples falha de assinatura local (senão um forjador com um `kid` real o expulsaria da lista). **Trade-off aceito:** um navegador legítimo, com token local, atrás de um IP que um forjador esgotou também leva 401 até o fim da janela (o cookie é mantido e a sessão volta quando o orçamento volta). **Residual:** um `kid` novo e legítimo gasta uma unidade uma vez por processo (e de novo após 5 min sem uso) | SEC-09, SEC-13 |
| T-30 | Rate limit | D | O limitador como amplificador: um flood contra um sujeito já bloqueado custa uma escrita no banco por requisição; `private.rate_limit_counters` cresce sem limite com sujeitos variados (F-06, F-07) | Cache de negações em memória, por instância, consultado antes do RPC (só deixa o limite mais estrito, nunca libera, então não enfraquece o fail closed) e limitado: cheio, sai a entrada mais antiga em O(1), sem varrer o mapa a cada negação (BAIXO 5), para que um flood de sujeitos distintos não vire carga de CPU; `rate_limit_hit` apaga, em cerca de 1% das chamadas, até 500 janelas vencidas há mais de 48 h (migration `rate_limit_opportunistic_cleanup`). A limpeza diária por `pg_cron` entra na Onda 11 | SEC-09, E-22 |
| T-31 | Sessão | S/T | Fixação de sessão, CSRF e cookie tossing | Todo login cria uma sessão e tokens novos no Auth e sobrescreve o cookie (não há como impor um id de sessão); `__Host-` obriga `Secure`, `Path=/` e nenhum `Domain`, o que impede um subdomínio de plantar o cookie; `SameSite=Lax` mais checagem de `Origin` e JSON obrigatório (T-08). **Residual (F-10):** um login feito sobre uma sessão existente não revoga a anterior; ela expira pelo `timebox` de 12 h (ADR 0009) | SEC-07, SEC-08 |
| T-32 | Logs | R/T | Correlação falsificada ou insuficiente: um `X-Request-Id` escolhido pelo cliente entra na trilha de auditoria e nos logs; eventos de auth sem sessão nem origem (F-09, F-11) | O id da requisição é sempre gerado no servidor (UUID v4) e é o que vai ao header, ao `problem+json`, aos logs e ao `x-request-id` do banco, então a auditoria só carrega ids do servidor; um valor válido do cliente é registrado à parte como `clientRequestId`. Os eventos `auth.login.*` e `auth.logout` levam `sessionId` e `ipHash` (HMAC com chave derivada, nunca o IP), e `auth.rate_limited` leva `subjectHash` | SEC-16, RNF-04 |

## 4. OWASP Top 10:2025

| Categoria | Como é tratada |
|-----------|----------------|
| A01 Broken Access Control | Deny by default (SEC-01); tenant da sessão (SEC-03); autorização em três camadas com RLS (SEC-04); 404 cross-tenant (SEC-05); MFA de CEO (SEC-11); SSRF fora da superfície (SEC-19) |
| A02 Security Misconfiguration | Headers (SEC-14); cadastro público desligado, `pg_graphql` removido, chaves JWT assimétricas (SEC-20); `config.toml` versionado; previews isolados |
| A03 Software Supply Chain Failures | Lockfile, Actions por SHA, Dependabot, `pnpm audit`, SAST, gitleaks, MCP e plugins revisados (SEC-18) |
| A04 Cryptographic Failures | TLS em tudo + HSTS; bcrypt do Supabase Auth; HMAC nas chaves de rate limit; segredos fora do código (SEC-15) |
| A05 Injection | §3.8 da spec: sem SQL no app, sem interpolação em filtros, funções sem SQL dinâmico, Zod `.strict()` (SEC-06); API só JSON com CSP (XSS) |
| A06 Insecure Design | Threat model, máquina de estados com invariantes no app e no banco, concorrência otimista, escrita só por funções (SEC-04) |
| A07 Authentication Failures | Rate limit (SEC-09), política de senha e HIBP (SEC-10), MFA (SEC-11), sem enumeração (SEC-12), sessão revogável (SEC-07) |
| A08 Software or Data Integrity Failures | Auditoria append-only (SEC-16); migrations imutáveis depois de mergeadas; deploy só por pipeline verde |
| A09 Security Logging & Alerting Failures | Logs JSON com request id, eventos de auth, auditoria no banco, alertas (spec §3.10) |
| A10 Mishandling of Exceptional Conditions | Fail closed (SEC-13); timeouts (SEC-19); transações atômicas com compensação (E-23); mapeamento de erros explícito |

## 5. OWASP API Security Top 10:2023

| Risco | Tratamento |
|-------|------------|
| API1 BOLA | Tenant da sessão + RLS + 404 (T-09) |
| API2 Broken Authentication | T-01 a T-07, T-22 |
| API3 Broken Object Property Level Authorization | DTOs explícitos, `.strict()` na entrada, `additionalProperties: false` na saída, tabelas do cliente sem colunas internas (T-10) |
| API4 Unrestricted Resource Consumption | Limites de corpo, strings, fases e paginação; rate limit (T-21) |
| API5 Broken Function Level Authorization | Papel no pipeline e no banco (T-12) |
| API6 Unrestricted Access to Sensitive Business Flows | Aprovação só por CEO `aal2`, com concorrência controlada e auditada (T-18, T-19) |
| API7 Server Side Request Forgery | Nenhum fetch de URL do usuário (SEC-19) |
| API8 Security Misconfiguration | A02 acima |
| API9 Improper Inventory Management | Contrato versionado e único; hook de Stop bloqueia rota sem contrato; agent `contract-guardian` |
| API10 Unsafe Consumption of APIs | Respostas do Supabase validadas com Zod; timeouts |

## 6. Abuse cases que viram testes

| Abuse case | Teste |
|------------|-------|
| Cliente A pede `/me/processes/{id-de-B}` | API: 404 (AC-09) |
| Cliente A chama o PostgREST direto com o próprio JWT em `processes` de B e tenta `INSERT` | pgTAP (AC-09, AC-10) |
| Cliente chama `approve_current_stage` via RPC | pgTAP: 42501 |
| CEO com sessão `aal1` chama uma função de CEO | pgTAP: 42501 (AC-08) |
| CEO com JWT `aal2` ainda válido, mas sem fator TOTP verificado (removido, só candidato ou só de telefone), lê ou chama função de CEO | pgTAP: nega (F-24) |
| O mesmo código TOTP é enviado duas vezes, na mesma sessão ou em outra sessão do mesmo CEO | API: 422 na segunda vez, com o mesmo corpo de um código errado e `auth.mfa.failed` com `code_reused`; pgTAP: `consume_totp_code` recusa dentro de 120 s e aceita depois (F-21) |
| Usuário queima os códigos do fator de outro, ou verifica com o fator de outro | pgTAP: `NOT_FOUND`; API: 422 igual a um código errado (F-21, E-28) |
| 20 tentativas de código no dia e a 21ª | API: 429 com `Retry-After`, sem chamar o Auth (F-22) |
| Candidato a fator substituído e sessão paralela aberta só com a senha | API: a ativação do primeiro fator derruba a outra sessão (401); o fator antigo dá `factor_not_found` no log (F-20) |
| Cookie `aal1` copiado, o CEO verifica na sessão dele e o refresh token antigo é usado | API: ainda devolve a sessão `aal2` dentro do intervalo de reuso do Auth (resíduo conhecido, F-23) |
| Duas aprovações simultâneas | API: 1 × 200 e 1 × 409 (AC-17) |
| POST de aprovação vindo de outra origem | API: 403 `ORIGIN_NOT_ALLOWED` (AC-23) |
| 11 logins errados para a mesma conta | API: 429 (AC-03) |
| Cookie reaproveitado após logout | API: 401 (AC-04) |
| Logout quando o Auth responde 403 sem revogar | API: 503 e cookie mantido; a sessão continua viva (AC-04) |
| Troca de senha com a senha atual errada (6 tentativas em 15 min) | API: 422 `INVALID_CURRENT_PASSWORD` nas 5 primeiras, 429 na 6ª, mesmo com a senha certa; nada muda (AC-06) |
| Chamar `mark_password_changed()` direto no PostgREST, sem trocar a senha | API: `PASSWORD_UNCHANGED`, a pendência continua (AC-05, ADR 0007) |
| Cliente manda `role` (ou `app_metadata`) em qualquer corpo, ou escreve `role: ceo` em `user_metadata` | API: 400 pelo `.strict()`; a sessão segue `client` e `/admin/*` segue 403 (AC-31) |
| 75 requisições com um cookie forjado do mesmo IP | API: no máximo 60 chamadas ao Auth, o resto 401 sem `Set-Cookie` (F-01) |
| 63 requisições do mesmo IP para cada variante de cookie forjado (`expires_at` estranho, chunks, token simétrico, sem `kid`, `kid` desconhecido ou real com assinatura falsa, ES384) | API: no máximo 60 chamadas ao Auth por variante, nenhuma depois de esgotado o orçamento, sempre 401 e nunca 5xx (F-01) |
| Token ES384 forjado com o `kid` real | API: 401, não 500, e nenhuma chamada ao Auth (MÉDIO 2) |
| Refresh que deu certo e verificação que então falha com 503 | unit: os cookies novos ficam, o refresh token consumido não volta (MÉDIO 3) |
| Login recusado de três jeitos (senha errada, e-mail inexistente, conta desativada) | API: mesmo 401 e mesmo piso de tempo (AC-02, F-05) |
| Sessão com 12 h 1 min, ou sem uso há 4 h 1 min, ainda com JWT válido | pgTAP: sem principal (SEC-07, F-08) |
| Corpo com campo extra `clientId` em `/me/*` ou `role` em provisionamento | API: 400 (AC-23) |

## 7. Riscos residuais aceitos

- **T-04 (não aceito, decidido, ainda não implementado):** um atacante consegue manter bloqueado o
  login de um CEO específico de forma sustentada (11 tentativas a cada 15 min bastam), não só
  atrasá-lo. Em 2026-11-16 o usuário escolheu o cookie de dispositivo (F-03, opção (c)), que entra
  na Onda 11; até lá o risco está aberto, com alerta.
- **Janela do access token:** sem o BFF, o JWT vale até 15 min. Pelo BFF, a revogação é imediata
  (checagem de sessão no banco).
- **Login sobre uma sessão existente (F-10):** a sessão anterior não é revogada; expira pelo
  `timebox` de 12 h (ADR 0009).
- **Enumeração por `/otp` (T-02):** ver T-02.
- **Refresh token anterior ao verify (F-23, confirmado por teste e à mão):** o Auth deixa o refresh token
  que o navegador tinha **antes** de um verify bom ser usado de novo por `refresh_token_reuse_interval`
  (10 s no local) e responde com a sessão atual, já `aal2`. Quem copiou o cookie `aal1` antes de o CEO
  verificar, e age nesses 10 s, recebe um token `aal2` (o mesmo que o CEO tem: a sessão é a mesma). Passado
  o intervalo, o mesmo token dá `refresh_token_already_used`. Rotacionar a sessão de novo depois do verify
  **não** ajuda (testado: com uma rotação a mais, o resultado foi o mesmo), e o app não
  encurta o intervalo, que é configuração do Auth (`[auth.sessions] refresh_token_reuse_interval`). **Onda 11:**
  baixar o intervalo no projeto hospedado, pesando o custo (dois refreshes concorrentes do mesmo cookie
  passam a falhar). O teste de API fixa o resíduo e exige que o intervalo configurado não passe de 10 s.
- **Esgotar o limite de verificação (F-22, lado B):** quem tem a senha pode gastar os 5 / 5 min e os
  20 / dia do CEO com códigos errados e impedir o CEO de verificar até a janela passar. É a mesma classe do
  T-04 (bloqueio direcionado) e fica no mesmo item. A janela do teto diário é fixa: na virada do dia cabem
  até 40 tentativas seguidas.
- **Chamada extra ao Auth no enroll (F-26, aceito):** o enroll lista os fatores (`listFactors`, um
  `getUser` no Auth) antes de criar o novo, e o verify faz `challenge` e `verify`. Essas chamadas não
  entram no orçamento `session-upstream` (que só cobre a resolução do principal) e são limitadas pelas
  regras da rota (10 / 15 min no enroll, 5 / 5 min mais 20 / dia no verify).
- **Revogação das outras sessões sem confirmação (F-20):** o cliente do Auth trata 401, 403 e 404 da
  revogação como "já desconectado", então uma revogação que o Auth recusou por esses status não é
  vista pelo app (o `auth.mfa.followup_failed` só cobre os demais erros). O teste de API prova o efeito
  real no Auth local.
- **Logout que falha (BAIXO 6):** quando o logout falha (503), os cookies são devolvidos ao navegador com
  `maxAge` de 12 h de novo, então o cookie pode viver além do `timebox`. Aceito: o banco aplica 12 h de
  vida e 4 h sem uso à sessão (`private.session_is_alive()`, F-08), então o cookie estendido não
  autentica nada depois do limite.
- **Refresh que termina depois do prazo de 5 s (MÉDIO 3):** se o Auth conclui o refresh depois que o
  resolvedor desistiu (503), o navegador ainda tem o refresh token antigo, que o Auth aceita dentro do
  intervalo de reuso (10 s) e depois trata como reuso e revoga a família. O resolvedor fecha o jar
  (`fenceRequestClient`) para que o trabalho abandonado não escreva cookies, mas não consegue desfazer
  o refresh do lado do Auth.
- **Chamadas ao Auth depois do prazo (T-29):** o `getClaims()` abandonado por prazo continua
  tentando de novo (o auth-js repete um refresh que falha por rede, por até cerca de 30 s). O fence
  também bloqueia o `fetch` do cliente: cada nova tentativa falha na hora, sem requisição, então
  nada chega ao Auth sem cobrança. Resta só a requisição que já estava em voo no momento do fence,
  que termina pelo próprio timeout de 5 s.
- **Insider CEO:** um CEO pode aprovar indevidamente. Mitigado por auditoria, não por prevenção.
  Desfazer aprovação fica para a v1.1 (Q-05).

## 8. Pendências e decisões em aberto

| Item | Situação |
|------|----------|
| F-03 (bloqueio direcionado, T-04) | **Decidido em 2026-11-16: (c) cookie de dispositivo.** Muda o §3.9 da spec; implementação na Onda 11. Não mitigado até lá |
| F-04 (T-01) | Adiado para a Onda 11 |
| F-20 (c) (T-22) | **Gate de go-live da Onda 11 (decidido em 2026-11-16):** (1) amarrar o cadastro do TOTP à sessão que limpou o `CHANGE_PASSWORD` (hoje qualquer sessão `aal1` do CEO cadastra); (2) script operacional de reset de MFA (E-25), que também é como o CEO recupera um fator substituído por outra pessoa. Não implementados nesta onda |
| F-23 (T-22) | **Onda 11:** baixar `refresh_token_reuse_interval` no projeto hospedado (ver o §7). Mudança de `supabase/config.toml`, fora da Onda 5 |
| `factorId` depois do cadastro (T-22, E-25) | **Decidido em 2026-11-16: opção (a); implementado no contrato `1.0.0-draft.2` (ADR 0011)** (`factorId` opcional e obsoleto; o servidor resolve o fator do usuário pela sessão). Histórico: `TotpVerifyRequest` exige `factorId`, e nenhuma resposta o devolve depois do enroll (`GET /auth/session` não o traz; o enroll recusa quem já tem fator verificado). Um CEO que entra em outro dispositivo (`VERIFY_MFA`) não consegue chamar o verify. Opções: (a) tornar `factorId` opcional e o servidor resolver o fator TOTP verificado do usuário; (b) incluir o `factorId` no DTO de `Session`. |
| F-13 | **Decidido na Onda 4 (ADR 0010): ligado** (`secure_password_change = true` em `config.toml`). Com sessões de no máximo 12 h (ADR 0009) o Auth nunca pede o nonce no fluxo do app (só o pede para sessão com mais de 24 h), então a chave não muda nada para o usuário; ela fecha o `PUT /auth/v1/user` direto com a sessão velha enquanto o `timebox` não estiver no projeto hospedado (Onda 11). A chave **não prova a senha atual**: isso é do app, que a confere por um sign-in descartável (ADR 0010). No Supabase local só vale depois de recriar o container do Auth |
| F-40 (ALTO) | **GATE DE GO-LIVE (Onda 11): nenhum ambiente hospedado com contas reais antes de `security_update_password_require_current_password` estar ligado** (Management API; não existe em `config.toml`, e o local não a liga). Até lá, quem tem o token de acesso de uma sessão com menos de 24 h e a publishable key (que não é segredo) troca a senha direto no Auth, sem a senha atual que `POST /auth/password` exige. O token só existe no cookie `HttpOnly` e no servidor (ADR 0002) e vale 15 min, mas o gate é a única mitigação completa. O app já envia `current_password` ao `updateUser`, então ligar a chave não quebra o fluxo. Registrado também no §3.11 da spec. **Candidatos da Onda 11, ainda não decididos:** (a) um job do `pg_cron` que apague de `auth.sessions` as sessões que `session_is_alive()` já nega (hoje elas só deixam de autenticar nas rotas do app e continuam existindo no Auth, e o `PUT /auth/v1/user` direto não passa pelo banco); (b) um trigger de detecção em `auth.users` que registre toda troca de `encrypted_password` que não veio de `mark_password_changed()`, para alertar |
| F-41 (decisão do usuário) | **Senha temporária sem validade:** a senha temporária de um CEO ou de um cliente vale até ser trocada, por tempo indefinido (ela foi vista por quem a entregou). Proposta: validade de, por exemplo, 72 h, aplicada em `current_active_user_id()` (conta com `must_change_password` e senha mais velha que o prazo deixa de ter principal) e um caminho de reset por um CEO para reabrir a conta. Exige mudança de spec (RF-04, SEC-10, §3.5). **Decidido em 2026-11-16: 72 h, na Onda 6.1**; o reset de cliente (Onda 7) renova o prazo, e o reset de senha de CEO vira script na Onda 11 |
| F-42 | **Tratado na Onda 4:** a criação de CEO grava `account.provisioned` (sem ator, canal `auth_admin`) pelo trigger de perfil, na mesma transação; falha da auditoria derruba a criação (migration `ceo_creation_audit`, pgTAP `011`, teste de integração) |
| F-43 e M5 do code review | **Tratado na Onda 4 (`ceo:create`):** só `SUPABASE_URL` e `SUPABASE_SECRET_KEY`; `--target` igual ao host da URL; `http:` só em loopback; URL e chave do mesmo lugar (shell ou arquivo, `--env-file`); recusa com `CI` definido e com stdout que não é terminal sem `--allow-non-tty`; stdout só com a senha |
| F-44 | **Tratado na Onda 4:** se a primeira chamada de `mark_password_changed()` gravou e só a resposta se perdeu, o `PASSWORD_UNCHANGED` da segunda é sucesso (só no retry; a linha de base só iguala o hash depois de um `updateUser` bem-sucedido se uma chamada anterior gravou). O `updateUser` sem resposta, que pode ter gravado a senha, responde 503 com a orientação dos dois estados (M4) |
| F-45 | **Aceito:** duas trocas concorrentes da mesma conta. Os dois `updateUser` e as duas `mark_password_changed()` se ordenam no Auth e no `FOR UPDATE` do perfil; no pior caso a segunda recebe 422 `PASSWORD_UNCHANGED` mesmo com a senha trocada (a primeira renovou a linha de base). A conta fica consistente e o usuário repete. Não vale um lock de aplicação para quem troca a própria senha, limitado a 5 por 15 min |
| F-46 | **Aceito:** a sessão do cookie clonado sobrevive à troca. A troca derruba as OUTRAS sessões e mantém a da requisição por desenho (AC-06); um atacante que clonou o cookie da sessão que está trocando a senha mantém essa sessão, mas não conhece a senha nova. Quem suspeita de um cookie roubado faz logout (que a revoga) ou pede reset a um CEO |
| F-47 | **Aceito:** o sign-in de prova da senha atual aparece no log do Auth como um login (`last_sign_in_at` e eventos de login do usuário) e gasta uma unidade do orçamento global de logins. É a única forma de provar a senha sem alterar o estado (ADR 0010); o ruído é de um usuário já autenticado, limitado a 5 por 15 min |
| Proposta de mudança no contrato (**aprovada em 2026-11-16; implementada no contrato `1.0.0-draft.2`, ADR 0011**) | O contrato **não foi editado** na Onda 4; as cinco inconsistências abaixo foram corrigidas no `draft.2`, uma mudança aditiva: (1) `ChangePasswordRequest.newPassword` declara `minLength: 12` e `maxLength: 72`, mas E-12 e a resposta `Unprocessable` mandam 422 `WEAK_PASSWORD`, não 400: tirar os limites do schema e deixá-los na descrição (a implementação aceita qualquer string e a política responde 422); (2) `currentPassword.maxLength: 72` conta caracteres em JSON Schema, e a implementação conta bytes UTF-8: dizer "bytes" na descrição; (3) o orçamento global de logins (`global`, 300 por 300 s, F-02) não está em `x-rate-limit` de `/auth/login`, e passou a ser gasto também por `/auth/password`; (4) o `204` de `/auth/password` pode trazer `Set-Cookie` da sessão (o Auth regrava a mesma sessão) e a resposta não o documenta; (5) `/auth/password` (e `/auth/logout`, `/auth/session`) podem responder 503 `SERVICE_UNAVAILABLE` com `Retry-After` (E-21) e não o documentam |
| F-50 (ALTO, security-scan de 2026-11-16) | **O problema:** os limites de força bruta e de replay (login 10 / 15 min por conta, teto global e piso de 400 ms; TOTP 5 / 5 min, 20 por dia e queima de código) só existem no BFF. Quem tem a senha e a publishable key chama direto `/auth/v1/token` e `/auth/v1/factors/{id}/verify`, onde só valem os limites por IP do Auth hospedado (login 30 / 5 min, configurável; verify de MFA 15 / min, fixo); com muitos IPs, a busca do TOTP cai de décadas para dias, e o Auth não tem proteção contra replay (supabase/auth#2882). Os hooks `mfa_verification_attempt` e `password_verification_attempt` só existem nos planos Teams e Enterprise. **Decidido em 2026-11-16:** (c) é o controle principal e gate da Onda 11: o navegador nunca recebe a publishable key (nenhuma variável do Supabase usa o prefixo público do Next.js), então ela é tratada como segredo, rotacionada a qualquer exposição, com HIBP ligado e alerta sobre os logs do Auth. (b) é a defesa em profundidade, na Onda 6.1 (ADR 0013): `is_ceo()` passa a exigir um atestado por `session_id`, gravado pelo backend depois do verify, então uma `aal2` obtida direto no Auth não dá poder de CEO; o atestado é recusado quando o fator tem, na janela do TOTP, um challenge verificado que não veio do backend (fecha o oráculo de chutar o código no Auth e reapresentá-lo pelo backend). (a) o plano Teams fica fora: com (c) bem feito, não é necessário |
| BAIXOs do security-scan de 2026-11-16 | **Decididos em 2026-11-16:** (1) o limite por usuário só vale depois de `current_principal()`: aceito, porque antes da autenticação não há usuário e o limite por IP cobre essa fase; (2) minimatch GHSA-g3hv-75wg-m249 (só desenvolvimento, via `typescript-eslint` → `typescript-estree`, que exige `^10` até a versão mais nova, 8.72.2, enquanto a correção está na 11): aceito por ora, porque o linter só recebe os globs da nossa própria configuração; rever quando o `typescript-eslint` subir para o minimatch 11 (o job `audit` do CI usa `--prod` e não o pega); (3) OTP de e-mail com `max_frequency = 1s` e `otp_expiry = 3600`: apertar no `config.toml` na Onda 11 (o fluxo não é usado); (4) headers `Cross-Origin-Opener-Policy` e `Cross-Origin-Resource-Policy`: Onda 11 |
| F-14 | Registrado pelo threat-modeler como observação, sem ação nesta onda |
| MÉDIO 4 (T-02) | O piso de 400 ms do login recusado pode não cobrir o caminho "conta desativada" em produção: são cerca de 3 idas ao Auth, de gru1 a sa-east-1, e o piso foi medido com o Supabase local. **Onda 11:** medir o p95 dos três caminhos recusados em produção e subir `REFUSED_LOGIN_FLOOR_MS` acima dele; até lá a diferença de tempo é um canal lateral possível, não confirmado |
| BAIXO 6 | Aceito, ver o §7 (logout que falha devolve o cookie com `maxAge` de 12 h; o banco aplica 12 h e 4 h) |
