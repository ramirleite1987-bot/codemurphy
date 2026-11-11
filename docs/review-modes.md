# Modos de revisão no GitHub

O CodeMurphy só publica com `--publish` no CLI ou `publish: 'true'` na
Action. Sem essa opção, qualquer modo gera apenas o relatório.

- **`comment` (padrão):** envia uma revisão do tipo comentário. No CLI,
  use `--only-findings` para omitir o comentário quando não houver achados
  publicáveis.
- **`approve-reject`:** envia `APPROVE` se a revisão completa do modelo
  principal não tiver achados publicáveis. Envia `REQUEST_CHANGES` se
  houver achados confirmados pelo segundo revisor ou detectados pela
  checagem determinística, com os achados ancorados no diff.

Para publicar um veredito, configure `review.verify_with` com o ID de
um segundo modelo e mantenha `publish-scope: primary`. Se o revisor
principal não propuser achados, o verificador não precisa ser chamado.
Se a revisão for estática ou não cobrir todo o diff, se alguma chamada de
modelo falhar, se um achado vier sem evidência válida, ou se houver achados
além do limite de verificação, o
relatório explica por que nenhum veredito foi publicado. Um pedido de
mudanças exige que pelo menos um achado possa ser mostrado na linha
correspondente do diff. `--only-findings` é exclusivo do modo `comment`.
O modo formal compara commits imutáveis a partir do merge base, com limite
de 300 arquivos. Rascunhos e alterações de base, origem ou head durante a
revisão também suspendem o veredito.

No CLI:

```bash
codemurphy github --repo owner/repo --pr 123 --config .codemurphy.json \
  --review-mode approve-reject --publish
```

Na Action, adicione aos inputs do passo:

```yaml
with:
  review-mode: approve-reject
  publish: 'true'
```

O token precisa de `pull-requests: write`. Para aprovar com o
`GITHUB_TOKEN`, a configuração
[Allow GitHub Actions to create and approve pull requests](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests)
precisa permitir a operação. Se usar um token de instalação de outro GitHub
App, informe o login do bot com `publisher-login` na Action ou
`--publisher-login` no CLI. O GitHub exige que a aprovação venha de uma
identidade diferente da autora do PR. Se o GitHub recusar o veredito, o
CodeMurphy informa a falha e não tenta enviar outro tipo de revisão.

A deduplicação usa o autor da revisão e os commits exatos de base e head.
Um comentário anterior não suprime um veredito. A última decisão formal
do mesmo revisor só é reaproveitada se o veredito também coincidir.
`--fail-on` continua controlando apenas o código de saída por severidade.
