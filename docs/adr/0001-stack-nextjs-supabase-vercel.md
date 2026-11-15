# ADR 0001 — Stack: Next.js + TypeScript na Vercel, Supabase (Postgres + Auth)

- **Status:** proposed
- **Data:** 2026-11-15
- **Spec:** [`docs/specs/client-delivery-tracker.md`](../specs/client-delivery-tracker.md)

## Contexto

O produto é um portal pequeno: até cerca de 500 clientes, 4 CEOs, leitura frequente e escrita
rara. Precisa de login com contas criadas manualmente, isolamento rígido entre clientes,
MFA para os administradores e dados no Brasil (LGPD). O time quer uma stack única para backend
agora e frontend depois. A proposta inicial foi Vercel + Next.js (React) + TypeScript + Tailwind
+ Supabase.

Alternativas avaliadas:

1. **Next.js + Supabase (proposta).** Auth pronto (senha, MFA TOTP, Admin API, revogação de
   sessão), Postgres com RLS, região São Paulo, migrations e testes pgTAP pela CLI.
2. **Next.js + Postgres gerenciado (Neon) + Drizzle + Auth.js ou Better Auth.** Mais controle,
   mas seria preciso construir e manter senha, MFA, criação administrativa de contas e
   revogação, que são justamente o núcleo de segurança.
3. **Backend separado (NestJS ou Fastify) + frontend Next.js.** Fronteiras mais explícitas, porém
   dois deploys, CORS entre origens e mais superfície para um sistema pequeno.

## Decisão

Adotar a opção 1:

- **Next.js 16+** (App Router, Route Handlers no runtime Node.js) com **TypeScript strict**.
  Tailwind fica para a fase de frontend.
- **Vercel** com funções em **`gru1`** (São Paulo), declarado em `vercel.json`.
- **Supabase** em **`sa-east-1`** (São Paulo): Postgres + Auth. Storage, Realtime e `pg_graphql`
  não são usados.
- **Plano Supabase Pro em produção:** projetos Free pausam por inatividade e não têm proteção
  contra senhas vazadas (HIBP).
- Bibliotecas de base: `@supabase/ssr` e `@supabase/supabase-js`, `zod`, `pino`, `vitest`,
  Supabase CLI (dev dependency) e `@redocly/cli`. Versões exatas fixadas no lockfile na Onda 0.
- Gerenciador de pacotes **pnpm** com lockfile commitado.

## Consequências

- **Positivas:** time-to-market curto; segurança de autenticação delegada a um componente
  maduro; RLS como segunda barreira nativa; ambiente local idêntico ao de produção (Supabase
  CLI + Docker); latência baixa e dados no Brasil.
- **Negativas:** acoplamento ao Supabase Auth (migrar exigiria exportar os hashes de usuário);
  dependência de Docker para testes de integração; custo do plano Pro.
- **Riscos:** limites por IP do Supabase Auth enxergam o IP da Vercel (tratado no ADR 0004);
  mudanças de API do Supabase (chaves `sb_publishable_`/`sb_secret_`) acompanhadas via Dependabot.
