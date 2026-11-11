# CodeMurphy

Code review automatizado que você controla: escolha os modelos, as regras e o
contexto de cada projeto. Rode os revisores lado a lado para descobrir quais
acham problemas reais nos seus PRs, quanto custam e quanto demoram.

- Revisa segurança, correção, escalabilidade, clareza, testes e casos de borda.
  Cada achado precisa citar uma linha alterada do diff, inclusive remoções.
- Combina uma checagem determinística de credenciais com modelos de OpenAI,
  Anthropic, OpenRouter e endpoints compatíveis com Chat Completions, como Gemini e Ollama.
- Lê contexto de arquivos escolhidos, do próprio projeto ou de outros
  repositórios, fixados em commits. Aplica regras diferentes por caminho.
- Publica comentários inline no GitHub ou roda em modo silencioso para
  comparar modelos. Registra tempo, tokens e estimativas de custo.
- Compara os resultados com bugs rotulados e achados importados do CodeRabbit
  ou de outro revisor. A suíte incluída é sintética: ainda não há evidência
  de que o CodeMurphy supera uma ferramenta comercial em PRs reais.

## Começar

Python 3.11+ e Git. O programa não tem dependências Python em tempo de execução.

```bash
git clone https://github.com/ramirleite1987-bot/codemurphy.git
cd codemurphy
python3 -m codemurphy benchmark examples/benchmark/suite.json --static-only
```

Opcional: instale o comando com `python3 -m pip install .` dentro de um ambiente
virtual. Os comandos abaixo usam `codemurphy`.

```bash
# Em um repositório Git: revisão offline das alterações no índice.
codemurphy review --staged --static-only

# Com a configuração do projeto, revisar commits e comparar os modelos.
codemurphy review --base origin/main --mode compare \
  --config .codemurphy.json --db ~/.local/share/codemurphy/history.sqlite3 \
  --format json --output codemurphy-report.json
```

Copie [a configuração de exemplo](examples/codemurphy.json) para
`.codemurphy.json` no projeto a revisar. Escolha os IDs de modelo disponíveis
na sua conta e configure as chaves nas variáveis indicadas. Em `primary` só
o modelo principal recebe o diff; `compare` chama todos os modelos com a
mesma entrada. Para carregar a configuração de um commit que você confia, use `--use-base-config`.
No CLI do GitHub, combine essa opção com `--trusted-base BRANCH` ou indique um arquivo
local com `--config`.
Alterações fora do índice não entram na revisão.

Para outro endpoint, use `provider: "openai-compatible"`, informe
`base_url` até o prefixo da API (sem `/chat/completions`) e ajuste
`api_key_env`. Gemini usa `https://generativelanguage.googleapis.com/v1beta/openai`;
Ollama local usa `http://127.0.0.1:11434/v1` e `api_key_env: null`. Para um gateway
customizado, use uma chave dedicada (não reutilize as variáveis reservadas
para os endpoints oficiais). Ajuste
`token_parameter` para `max_tokens` ou `max_completion_tokens` se o endpoint
exigir um campo específico. Para Anthropic, o adapter usa a API Messages.

## Contexto e regras

`context.files` lê os arquivos permitidos na base do diff. `context.linked`
usa uma lista explícita de arquivos de outros repositórios. Exemplo de
entrada (substitua o SHA ilustrativo pelo commit real):

```json
{
  "id": "mobile",
  "repo": "minha-org/mobile",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "files": ["contracts/invoice.md", "docs/integration.md"]
}
```

Para contexto no disco, substitua `repo` por `local`, por exemplo
`"../mobile"`. Isso só funciona no CLI local. Um repositório privado no
GitHub requer `CODEMURPHY_CONTEXT_TOKEN` de leitura, ou um token que já
tenha acesso; no Action, passe `context-token`. O CodeMurphy escolhe
trechos relevantes por lote e verifica as citações retornadas pelo modelo.
Contexto opcional do próprio projeto ausente gera aviso; arquivos
explicitamente ligados devem estar acessíveis.

Use `review.rules` para instruções por caminho, `review.exclude` para
arquivos gerados e `review.categories` para ajustar o escopo. `*` casa
dentro de um segmento; `**` atravessa diretórios. Ajuste
`min_severity`, `min_confidence`, `max_comments`, `max_parallel` e os
orçamentos `chunk_chars`, `max_diff_chars`, `max_context_chars` e `max_batches`.
A confiança é declarada pelo modelo; calibre o limiar com casos rotulados.
Use `review.structured_comments: true` para exigir gatilho, impacto, correção
e uma forma de verificar cada achado. Com `review.verify_with`, outro
modelo recebe o mesmo diff e contexto para contestar os achados do
revisor principal. Só resultados confirmados podem ser publicados, e uma
falha nessa etapa suspende a postagem. Nesse modo, os modelos comparados
em paralelo ficam no relatório e não interferem na publicação. Os candidatos originais e o custo da confirmação
aparecem separadamente no relatório e nas métricas.
Configure `json_mode: true` no modelo quando o endpoint compatível aceitar
`response_format: json_object` (por exemplo, Ollama).
Os relatórios indicam linhas omitidas e falhas de requisição.

## GitHub Actions

1. Coloque `.codemurphy.json` na branch de base confiável.
2. Copie [o workflow de exemplo](examples/github-review.yml) para
   `.github/workflows/codemurphy.yml` e fixe a Action pelo SHA da versão.
3. Cadastre as chaves de cada modelo em **Settings → Secrets and variables →
   Actions**. Para um provedor compatível, a Action expõe
   `compatible-api-key` como `CODEMURPHY_MODEL_API_KEY`.

O workflow usa `pull_request_target` para ler a configuração confiável e
comentar com o token do GitHub. A Action lê o diff pela API e não faz checkout
do PR. Mantenha o job isolado: não adicione passos que executem arquivos do
PR nesse workflow. Forks são ignorados por padrão. Para testar sem chaves,
configure `static-only: 'true'`. Para observar a qualidade antes de comentar,
use `mode: compare` e `publish: 'false'`, com permissão de PR somente leitura.
Para comparar em paralelo sem adicionar ruído aos PRs, use `mode: compare`
com `publish-scope: primary`. O resumo mostra falhas e métricas de todos
os modelos; só os achados do principal e da análise determinística são
publicados. `publish-scope: combined` é opt-in.

Os comentários são limitados e verificados contra a revisão atual do PR.
A publicação é suspensa se o diff ou o revisor selecionado ficou incompleto.
No CLI, `github --publish --only-findings` evita a postagem quando não há
achados publicáveis. O padrão não bloqueia por severidade; `--fail-on high` ou o input `fail-on`
habilitam essa política. Códigos de saída: `0` concluído/ignorado pelo
filtro, `1` achado atingiu o limiar, `2` revisão incompleta ou erro operacional.

Arquivos permitidos do diff e de contexto são enviados aos provedores
configurados. A ferramenta mascara padrões comuns de segredo; isso não
garante a remoção de todo dado sensível. Use um endpoint local quando o
código não puder sair do seu ambiente. Contexto privado de outro repositório
exige modo de relatório, sem postagem no PR; o resumo do job omite achados
nesses casos. Trate o JSON de revisão como código-fonte ao retê-lo. A Action
entrega `report-path` no runner e não envia o arquivo para um serviço de
armazenamento automaticamente.

Para usar OpenRouter, veja [o perfil de exemplo](examples/openrouter.json)
e [o guia de hospedagem e credenciais](docs/hosting.md). O workflow piloto
é opt-in e começa em modo de observação.

## Escolher os melhores modelos

```bash
codemurphy benchmark examples/benchmark/suite.json --config examples/codemurphy.json
codemurphy benchmark minha-suite/suite.json --config .codemurphy.json \
  --baseline CodeRabbit=minha-suite/coderabbit.json --format json --output codemurphy-benchmark.json
```

O benchmark mede precisão, recall, recall ponderado pela gravidade, alertas
em casos limpos, custo estimado e p95 de latência. Modelos e ferramentas
externas são comparados sobre a mesma interseção de casos concluídos. Use
[este guia](docs/benchmark.md) para montar uma avaliação com seus próprios PRs.

Use `input_usd_per_million` e `output_usd_per_million` em cada modelo para
estimar o custo com base nos tokens reportados pela API; valores não
informados ou uso desconhecido aparecem como ausentes. A estimativa usa
preços cheios, sem descontos de cache, taxas ou outros custos do provedor.

Para medir utilidade no uso diário, importe relatórios com `codemurphy record
ARQUIVO --db BANCO`, ou grave no banco durante a revisão. Depois rotule
achados como `useful`, `false-positive`, `duplicate` ou `uncertain`:

```bash
codemurphy feedback --db history.sqlite3 --run ID_DA_EXECUCAO \
  --finding ID_DO_ACHADO --verdict useful
codemurphy metrics --db history.sqlite3 --repo owner/repo
```

O SQLite guarda telemetria, IDs e avaliações; não guarda diffs, prompts ou
o texto dos achados. A taxa de utilidade usa somente os achados avaliados
com veredito conclusivo. Use o benchmark para medir problemas que nenhum
modelo encontrou.

## Desenvolvimento

```bash
python3 -m unittest discover -s tests -v
python3 -m codemurphy benchmark examples/benchmark/suite.json --static-only
```

Endpoints compatíveis com saídas estruturadas, como Ollama, podem usar
`json_schema: true` no modelo. O esquema exige a lista `findings` na
revisão e `confirmed` na verificação. A ferramenta continua validando
se as linhas, citações e evidências existem no diff.
