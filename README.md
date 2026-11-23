# ZipScope 1.2

Inspeção local do índice de arquivos ZIP antes da extração. Abra index.html e selecione um ZIP. A análise mostra caminhos, tamanhos declarados, taxas de expansão e indicadores para revisão.

## Atualização 1.2

- Busca por nome, pasta e extensão, combinada com o filtro de entradas sinalizadas.
- Contagem de tamanho e maior arquivo corrigida para considerar arquivos, mantendo a inspeção de caminhos das pastas.
- Pastas identificadas na listagem.
- Mensagens de extensão dupla e lista vazia mais precisas.
- Arquivo .nojekyll incluído para servir o projeto como site estático.
- Interface e código continuam incorporados em index.html, com funcionamento offline.

## Uso e limites

Escolha um ZIP de até 512 MB. O índice pode ter até 30 mil entradas e 32 MB. Use “Mostrar mais 200” para ampliar a lista.

ZIP64, ZIPs divididos em volumes e algumas variantes não são compatíveis. A leitura usa apenas o índice central e o final do arquivo, sem descompactar os conteúdos.

A pontuação é heurística. Os tamanhos são declarados pelo próprio ZIP. O aplicativo não verifica CRC, conteúdo dos arquivos ou ZIPs internos e não garante ausência de malware.

## Privacidade

Os arquivos são processados no dispositivo. A página funciona sem serviços externos.

## Arquivos

- index.html — interface, estilos e lógica.
- .nojekyll — configuração para servir o site estático.
- LICENSE — licença MIT original.

## Verificação

A sintaxe JavaScript e casos de leitura de ZIP foram verificados. A revisão visual no navegador está pendente.
