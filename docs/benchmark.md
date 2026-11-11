# Avaliação em PRs reais

A suíte de exemplo verifica o caminho da entrada ao relatório. Para decidir
se o CodeMurphy é melhor no seu fluxo, monte uma suíte separada com PRs
representativos dos seus projetos.

1. Congele diffs, SHAs e arquivos de contexto. Use diffs de PRs com bugs
   conhecidos e casos limpos, incluindo mudanças de código, configuração,
   testes e contratos. Preserve casos raros que tiveram impacto grande.
2. Rotule os problemas antes de olhar os resultados. Para cada um, registre
   o caminho, lado, intervalo, categoria e peso. Use palavras-chave quando
   o mesmo trecho puder produzir vários achados distintos.
3. Rode cada ferramenta sobre os mesmos PRs e commits, com as configurações
   que pretende usar na prática. Defina previamente quais comentários
   contam como achados; não importe resumos, conversa ou duplicatas
   removidas manualmente. Registre falhas e tempo até a revisão.
4. Compare na interseção dos casos completos. Inspecione correspondências
   e falsos positivos com revisão humana: o pareamento automático não
   consegue julgar equivalência semântica. Guarde uma suíte independente
   para confirmar qualquer melhoria antes de adotar um modelo.

## Formato da suíte

Veja `examples/benchmark/suite.json`. Cada caso tem `id`, `diff` (patch Git
unificado relativo ao manifesto), `expected` (lista vazia para casos limpos)
e, opcionalmente, `context`. Cada referência congelada tem `id`, `repo`,
`commit`, `path` e `file`; `file` aponta para uma cópia de texto relativa à
suíte. Essa configuração substitui `context` do arquivo de modelos no
benchmark, para que o material permaneça estável.

Cada rótulo em `expected` exige `id`, `path`, `side` (`LEFT` ou `RIGHT`),
`start` e `category`. `end` é inclusivo e, se ausente, igual a `start`.
`weight` vai de 1 a 10. A lista opcional `keywords` exige ao menos uma
expressão no título ou descrição do achado (sem distinguir maiúsculas).
Isso torna erros de pareamento visíveis e corrigíveis, mas não elimina a
necessidade de adjudicação. Um achado conta para no máximo um rótulo; um
rótulo só pode receber crédito uma vez.

## Importar outro revisor

Obtenha o identificador e o hash com `codemurphy benchmark suite.json --describe`.
Normalize manualmente ou por exportação da ferramenta:

```json
{
  "suite": "meus-prs",
  "suite_sha256": "valor retornado por --describe",
  "cases": {
    "pr-42": [
      {
        "path": "orders.py",
        "side": "LEFT",
        "line": 11,
        "category": "security",
        "title": "Missing order authorization",
        "detail": "The new path bypasses the ownership check."
      }
    ],
    "pr-limpo": []
  },
  "measurements": {
    "pr-42": { "latency_ms": 23000 }
  }
}
```

Categorias: `security`, `correctness`, `scalability`, `clarity`, `tests`,
`edge-cases`. Caso concluído sem achados é `[]`; caso sem resultado fica
ausente. `measurements` pode incluir `latency_ms` e `cost_usd` por caso
quando medidos. Não invente um custo por PR a partir de uma assinatura fixa.

O relatório JSON inclui pontuações por caso, os índices de correspondência,
linhas não cobertas e métricas sobre os próprios casos de cada revisor e
sobre a interseção. `static` mede somente a checagem determinística; cada
ID de modelo mede o modelo isolado; `combined` mede a união deduplicada. `published-primary` aplica
o mesmo escopo e limite de comentários da publicação padrão. Use essa linha
quando o baseline contiver comentários efetivamente publicados. Com segunda revisão,
a linha de união combinada é omitida: o verificador avalia apenas os achados
do modelo principal; as pontuações individuais continuam disponíveis.
Sem candidatos/achados suficientes para calcular uma taxa, o resultado é
`null`. A latência de um modelo durante a comparação inclui a concorrência
na execução; use um único modelo por rodada para estimar tempo isolado.
Preços, configuração, modelos e versões podem variar: salve as entradas e
o JSON das rodadas que pretende comparar.
