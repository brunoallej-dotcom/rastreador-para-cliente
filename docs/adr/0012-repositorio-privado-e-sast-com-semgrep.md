# ADR 0012 — Repositório privado até o go-live e SAST com Semgrep CE no lugar do CodeQL

- **Status:** proposed
- **Data:** 2026-11-16

## Contexto

O repositório era público e publicava o threat model com achados ainda abertos. Em 2026-11-16 o
responsável decidiu torná-lo **privado até o go-live**.

Ele pertence a uma conta pessoal no plano GitHub Free, e isso muda três coisas:

- **Code scanning** (o upload de SARIF para a aba Security, que o job `codeql` usava) não existe
  em repositório privado de conta pessoal.
- A licença do CodeQL não cobre rodá-lo em código privado que não seja de código aberto.
- O **secret scanning** e o push protection do GitHub também não estão disponíveis nesse caso.

O método AISAC exige SAST no CI desde o primeiro dia (spec SEC-18, AC-30), então o job `codeql`
tinha de ser trocado **antes** da mudança de visibilidade. A spec e o plano já aceitam "CodeQL ou
Semgrep".

## Decisão

- O repositório fica **privado até o go-live**. A visibilidade é alterada pelo responsável, não
  pelo pipeline.
- O job `codeql` sai; entra o job `sast`, que roda o **Semgrep CE** (motor LGPL-2.1, sem conta nem
  token) numa imagem de container `semgrep/semgrep` **pinada por digest**, com
  `permissions: contents: read` e sem `security-events`.
- Execução: `semgrep scan --metrics=off --error`. Nada é enviado ao Semgrep nem ao GitHub; qualquer
  achado reprova o job e aparece só no log dele.
- Regras: packs do registry para TypeScript, JavaScript, Node.js, Next.js, OWASP Top 10 e GitHub
  Actions, mais duas regras locais em `.semgrep/rules.yml`: `auth.getSession()` proibido no servidor
  e template literal ou concatenação em `.or()`, `.filter()` e `.textSearch()`. São as mesmas
  proibições que o ESLint já aplica em `src/`, repetidas em outro motor para que uma não pare de
  funcionar em silêncio. Segredos continuam com o gitleaks.
- A invocação fica em `scripts/sast.sh`, usada pelo CI e por `pnpm sast` (que roda a mesma imagem,
  lida do `ci.yml`, via Docker). `pnpm sast:test` confere as regras locais contra os fixtures de
  `.semgrep/rules.ts`; o CI roda isso antes do scan.
- Falso positivo: `// nosemgrep: <rule-id>` na linha, com uma linha de justificativa. Arquivos que
  não precisam ser analisados ficam no `.semgrepignore`.

## Consequências

- **Sem aba Security nem lista de alertas.** Os achados existem só no log do job, e um achado
  reprova o CI. Não há triagem persistente, histórico nem "dismiss": a correção ou o `nosemgrep`
  justificado é o único caminho.
- **Menos determinismo.** As regras vêm do registry do Semgrep em tempo de execução; só o motor é
  pinado. Uma regra nova ou alterada pode reprovar um PR sem mudança de código, e uma falha de
  rede ao buscar as regras reprova o job (falha fechada). Vendorizar as regras em `.semgrep/` é a
  saída se isso incomodar.
- **Cobertura diferente do CodeQL.** O Semgrep CE não faz taint entre arquivos, então perde fluxos
  que o CodeQL acharia. Para este código (handlers finos, ESLint de fronteiras, RLS e pgTAP) é
  uma troca aceitável, mas SAST profundo volta à pauta se o projeto crescer.
- **Secret scanning do GitHub indisponível.** O gitleaks segue como único scanner de segredos,
  incluindo o histórico inteiro do PR.
- **Minutos de Actions entram na cota gratuita** (repositório público não conta). Um CI custa cerca
  de 2 minutos por execução; o job `sast` roda em paralelo aos demais.
- **O Dependabot não acompanha essa imagem**: o digest do Semgrep (`SEMGREP_IMAGE` no job `sast`)
  é atualizado à mão, com um release de pelo menos duas semanas, como as Actions e as dependências.
  Depois de trocar, rode `pnpm sast:test && pnpm sast`.
- Ao publicar o repositório (go-live ou depois), o CodeQL pode voltar como segundo SAST, sem remover
  o Semgrep.
