# ADR 0018 — Planos gratuitos: Supabase Free em produção e repositório público

- **Status:** accepted. Substitui o item "Plano Supabase Pro em produção" do
  [ADR 0001](0001-stack-nextjs-supabase-vercel.md) e o "privado até o go-live" do
  [ADR 0012](0012-repositorio-privado-e-sast-com-semgrep.md).
- **Data:** 2026-11-17

## Contexto

Em 2026-11-17, o responsável tomou duas decisões de custo.

1. **Repositório.** Com o repositório privado (ADR 0012), o GitHub recusou iniciar os jobs do CI
   ("recent account payments have failed or your spending limit needs to be increased"). Numa
   conta pessoal Free, o Actions de repositório privado consome uma cota de minutos. O responsável
   tornou o repositório público, e o CI voltou a rodar.
2. **Supabase.** O ADR 0001 exigia o plano Pro em produção. O responsável decidiu manter dev/staging
   e prod no plano **Free**. Pela documentação do Supabase (consultada em 2026-11-17), o Free não tem:
   - proteção de senha vazada (Pwned Passwords/HIBP), que é Pro e acima;
   - `timebox` e `inactivity_timeout` das sessões do Auth, que também são Pro e acima;
   - funcionamento contínuo: o projeto pausa depois de 7 dias sem atividade e só volta quando alguém
     o reativa no painel. Os dados são preservados.

   O backup diário gerenciado também é dos planos pagos; isso será conferido na Onda 11.

## Decisão

- **Supabase Free** para dev/staging e prod, ambos em `sa-east-1`. Passar a organização de prod para
  o Pro continua possível a qualquer momento, sem migração.
- **Repositório público.** O threat model e os achados em aberto ficam visíveis, e o responsável
  aceitou esse risco. O resto do ADR 0012 continua valendo: o Semgrep CE no job `sast`, as regras
  locais e o gitleaks.
- **Compensações**, todas na Onda 11:
  1. **Sessão:** o banco já aplica os limites de 12 h e 4 h (`private.session_is_alive()`,
     ADR 0009), e o cookie continua com o teto de 12 h. O `timebox` e o `inactivity_timeout` do Auth
     hospedado deixam de ser gate de go-live. No `config.toml` local eles continuam iguais.
  2. **Senha vazada:** o backend passa a recusar senha vazada consultando a API de k-anonimato do
     Pwned Passwords. Só os 5 primeiros caracteres do SHA-1 saem do servidor.
     - Vale para as senhas que o usuário escolhe: a troca em `POST /auth/password` e o `ceo:create`.
     - O comportamento quando a API falha (aberto ou fechado), o timeout e a superfície nova entram
       no threat model da Onda 11.
     - Isso substitui o "HIBP ligado" do F-50 (c).
     - **Resíduo:** a troca feita direto no Auth (`PUT /auth/v1/user` com a senha atual, que o F-40
       permite) não passa por essa checagem. Com o HIBP do Pro, o próprio Auth a recusaria. Entra
       no threat model da Onda 11.
  3. **Backup:** um dump diário, agendado e criptografado, desenhado na Onda 11. Como o repositório
     é público, o dump nunca fica sem criptografia como artefato do GitHub.
  4. **Pausa:** risco aceito. Não haverá tráfego artificial para evitar a pausa. Um projeto pausado
     volta pelo painel do Supabase.

## Consequências

- **Positivas:** custo zero de infraestrutura, e o CI volta a rodar sem depender de cobrança.
- **Negativas:**
  - a produção pode ficar fora do ar depois de uma semana sem uso, até alguém reativá-la;
  - a sessão perde uma camada. O Auth hospedado não encerra a sessão vencida sozinho; o banco a
    nega a cada requisição, mas ela continua em `auth.sessions`. A limpeza por `pg_cron` já é
    candidata do F-40;
  - a checagem de senha vazada passa a ser código nosso, com uma chamada de rede externa no fluxo
    de senha;
  - o backup fica sob nossa responsabilidade.
- **A monitorar:** os limites do Free (500 MB de banco, 50 mil usuários ativos por mês, 5 GB de
  egress), folgados para cerca de 500 clientes e 4 CEOs.
- Atualizados junto com este ADR: spec RNF-08, SEC-07 e §3.11; a nota do ADR 0009; os status dos
  ADRs 0001 e 0012; e o plano da Onda 11.
