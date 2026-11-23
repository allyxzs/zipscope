# ZipScope 1.1

Inspeção local do índice de arquivos ZIP, antes da extração.

## Uso

Abra index.html e escolha ou arraste um ZIP. O aplicativo mostra os nomes, tamanhos declarados, taxa de expansão e sinais que merecem revisão. Os filtros permitem visualizar todas as entradas ou somente as sinalizadas. Use “Mostrar mais 200” para avançar na lista.

## Melhorias desta versão

- Página independente com estilos e JavaScript incorporados, evitando falhas causadas por pastas de recursos ausentes.
- Funcionamento offline, com fontes do dispositivo e sem dependências de CDN.
- Leitura direta do índice central, preservando caminhos suspeitos e entradas repetidas.
- Identificação de caminhos com barras invertidas, diretórios suspeitos, links simbólicos, criptografia e caracteres especiais.
- Resultados antigos são ocultados ao iniciar outra análise. A seleção mais recente tem prioridade.
- Limites explícitos e mensagens para arquivos incompatíveis.
- Pontuação apresentada como indicador heurístico.

## Limites

Até 512 MB por ZIP, 30 mil entradas e 32 MB de índice central. O aplicativo lê o final do arquivo e o índice, evitando carregar o conteúdo completo na memória. ZIP64, arquivos divididos em volumes e algumas variantes de ZIP não são compatíveis. ZIPs criptografados com índice legível podem ser listados, com alerta.

Os tamanhos são declarados pelo próprio arquivo. A análise não verifica CRC, não valida o conteúdo de cada entrada e não inspeciona arquivos compactados internos. A pontuação não confirma malware nem garante segurança.

## Arquivos

index.html contém a interface, estilos e lógica. LICENSE mantém a licença MIT original.

## Privacidade

Todo o processamento ocorre no dispositivo. A página não envia arquivos nem consulta serviços externos.
