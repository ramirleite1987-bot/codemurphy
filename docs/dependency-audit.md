# Dependências públicas: Socket e OSV offline

`codemurphy dependencies` examina um PR aberto, pronto e da mesma origem,
cuja base seja a branch confiável indicada. Ele lê `pnpm-lock.yaml` nos
commits exatos de origem (merge base) e head pelo GitHub. A comparação usa
as versões e os artefatos resolvidos no lockfile v9; remoções e mudanças só
na resolução de peers da mesma versão não geram consulta. Não há instalação
de dependências do PR nem chamada a um modelo.

1. Instale o extra do CodeMurphy com `python -m pip install '.[dependency-audit]'`.
2. Use Node 22.22+ e instale o cliente da Socket em uma pasta de ferramentas
   confiável, fora do projeto que será revisado. O cliente é a biblioteca
   pública [SecurityArchive](https://www.npmjs.com/package/@vltpkg/security-archive)
   que o VLT usa para consultar a Socket. Ela não é usada como gerenciador de pacotes.

   ```sh
   npm install --prefix "$CM_SOCKET_TOOLS" --ignore-scripts --no-audit --no-fund \
     @vltpkg/security-archive@1.7.0
   ```

3. Use um [OSV Scanner](https://github.com/google/osv-scanner/releases) v2
   verificado (testado em v2.7.1). Aponte `--osv-db` para uma pasta que contenha
   `osv-scalibr/npm/all.zip`, baixado do [snapshot público do npm](https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip).
   O scanner recebe o lockfile local em modo `--offline` e não resolve dependências.
4. Crie um JSON confiável como `{"public_npm":["vite","rolldown"]}` com nomes
   exatos já conhecidos como públicos. Para um repositório privado, forneça
   `CODEMURPHY_GITHUB_TOKEN` no ambiente. Rode:

   ```sh
   codemurphy dependencies --repo owner/repo --pr 123 --trusted-base main \
     --allowlist "$CM_PUBLIC_NPM_ALLOWLIST" --socket-tools "$CM_SOCKET_TOOLS" \
     --osv-scanner "$CM_OSV_SCANNER" --osv-db "$CM_OSV_DB" \
     --output "$CM_PRIVATE_REPORT"
   ```

O npm recebe apenas consultas por nomes da lista para confirmar a versão,
o tarball e a integridade SHA-512. A Socket recebe somente os pares de nome e
versão que passaram nessa verificação. Nomes não aprovados, caminhos locais,
referências Git, artefatos de registries privados e divergências de integridade
ficam fora. O processo Node lê apenas a pasta de ferramentas e seu cache
temporário, recebe só os pares verificados e não herda credenciais. A consulta
remota depende da disponibilidade do serviço público da Socket.

O JSON é criado com permissão `0600`. `scope` mostra quantos artefatos mudaram,
quantos passaram no filtro e por que os outros ficaram de fora. `socket.covered`
conta respostas com metadados para a versão pedida. O OSV precisa cobrir as mesmas
versões para a comparação concluir. IDs e aliases em comum são cruzados por
pacote e versão. `socket_only_advisories` traz identificadores da Socket que
não apareceram nesse snapshot do OSV; `socket_signals` contém indicadores de
comportamento ou de saúde do pacote. Suspeitas geradas por IA ficam separadas
de alertas de malware conhecido. Um indicador de acesso a arquivos, por
exemplo, não comprova uma vulnerabilidade. Falhas e cobertura parcial saem
com código 2; um relatório vazio nessas condições não é evidência de segurança.

O comando não publica nem alimenta decisões de aprovação ou bloqueio do PR.
