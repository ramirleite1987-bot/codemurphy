# Hospedagem e credenciais do CodeMurphy

Comece pelo GitHub Actions quando a revisão acontece em PRs de poucos
repositórios. Use uma VPS quando precisar guardar histórico e resultados de
vários projetos em um só lugar. Escolha AWS gerenciada se a operação já usa
AWS ou precisa de isolamento, filas e controle central de acesso.

## Piloto com OpenRouter no GitHub Actions

1. Crie uma [chave OpenRouter com limite de créditos](https://openrouter.ai/docs/api/api-reference/api-keys/create-keys)
   para o projeto. Para código privado, escolha **ZDR only** em ambos os
   grupos nas configurações de privacidade ou no guardrail da chave, e
   mantenha o registro de entradas e saídas desativado. Cadastre o segredo
   `OPENROUTER_API_KEY` no repositório.
2. Use [a configuração de exemplo](../examples/openrouter.json) como
   `.codemurphy.openrouter.json` na branch confiável. Os IDs de modelo
   são exemplos; confirme que o modelo suporta a resposta estruturada.
   Se o projeto já tem regras em `.codemurphy.json`, preserve a política
   relevante e revise os arquivos de contexto antes de autorizar o envio.
   Use `review.include` para delimitar os caminhos do diff, `review.exclude`
   para exceções e `review.include_pr_text: false` para omitir título e
   descrição do PR. `context.files` é uma lista separada de referências.
3. Adicione [o workflow](../examples/github-review-openrouter.yml) em
   `.github/workflows/` e fixe a Action por SHA. Ative a variável de
   repositório `CODEMURPHY_OPENROUTER=true` quando o projeto puder usar o
   provedor externo. O piloto grava o resumo no Actions e começa sem postar.
4. Compare os modelos nos [mesmos casos rotulados](benchmark.md). Libere
   comentários após validar precisão e cobertura; nessa etapa o job precisa
   de `pull-requests: write` e `publish: 'true'`.

O provedor `openrouter` usa o endpoint oficial e pede [roteamento ZDR](https://openrouter.ai/docs/guides/features/zdr),
sem coleta de dados pelo provedor e com suporte a todos os parâmetros. O
parâmetro ZDR respeita a configuração de retenção de segurança da conta:
**ZDR only** é a opção que a exclui. Sem rota elegível, a revisão fica
incompleta. O diff e o contexto autorizado passam pelo OpenRouter; use
Ollama se precisam permanecer locais.

Na avaliação, compare qualidade e tempo do modelo separadamente do
preço. Configure o preço de entrada e saída para estimar custos ou
confira o gasto real no painel do OpenRouter. Infraestrutura e inferência
são cobranças distintas.

## VPS ou AWS

- **VPS:** execute o CLI em um contêiner com agendamento e SQLite em volume
  persistente. Comece consultando PRs por uma [GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)
  instalada só nos repositórios autorizados. Elimine duplicatas por repositório,
  número do PR, base e head. Não precisa abrir uma porta de entrada para
  essa topologia. O componente de agendamento e emissão do token da app
  precisa ser provisionado no deploy.
- **AWS:** execute o mesmo worker em [tarefas ECS/Fargate agendadas](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/scheduling_tasks.html),
  injete credenciais pelo Secrets Manager e mantenha a deduplicação e a
  telemetria em armazenamento persistente, como DynamoDB. Acrescente
  webhook com assinatura validada e fila SQS quando a latência de
  polling justificar. Esse worker e sua infraestrutura não são criados
  por este guia.

Os modelos do OpenRouter executam no provedor. O worker precisa de CPU e
memória para preparar diffs e relatórios; hospedar um modelo com Ollama
exige dimensionamento próprio.

## Assinaturas

A chave do OpenRouter usa saldo/faturamento do OpenRouter. A assinatura
ChatGPT pode ser usada no [Codex Code Review](https://learn.chatgpt.com/docs/third-party/github),
e a OpenAI documenta [créditos de API para assinantes Pro e Business elegíveis](https://developers.openai.com/api/docs/guides/chatgpt-api-credits).
Para integrar uso do plano de forma nativa em uma aplicação, existe
[Sign in with ChatGPT](https://developers.openai.com/siwc), com fluxo
próprio e elegibilidade; esse login ainda não faz parte do CodeMurphy.
No acesso direto à API use uma chave OpenAI, não um token de sessão.

Se “Cloud” se refere a Claude: o plano cobre o uso elegível no Claude Code
oficial. Para um serviço de terceiros, siga os [métodos de autenticação da Anthropic](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use):
use chave da API ou um provedor de nuvem compatível.
