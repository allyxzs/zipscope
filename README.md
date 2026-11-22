# ZipScope

Raio-X de arquivos ZIP, direto no navegador.

## O que é

O ZipScope abre um arquivo .zip e mostra o que existe dentro dele **antes** de qualquer extração: cada entrada, tamanho real, tamanho compactado, taxa de compressão, extensões perigosas, caminhos maliciosos e um nível de suspeita de zip bomb.

Baixar e extrair um ZIP desconhecido é um risco real: zip bombs enchem o disco, caminhos com ".." gravam arquivos fora da pasta de destino e extensões disfarçadas executam código. O ZipScope existe para você olhar antes de abrir.

## Recursos

- Lista completa das entradas do pacote, com tamanho real, tamanho compactado e taxa de compressão por arquivo.
- Detector de bomba com pontuação de 0 a 100 e quatro níveis: tranquilo, atenção, suspeito e bomba provável.
- Alertas explicados em português: expansão absurda, volume descompactado, caminhos com "..", caminhos absolutos, extensão dupla, executáveis, scripts, macros e ZIPs aninhados.
- Filtro para ver apenas as entradas sinalizadas.
- Interface responsiva, em tema escuro, com tipografia monoespaçada nos dados.

## Como funciona

O arquivo é lido com a File API e interpretado pelo JSZip. A análise percorre o índice central do ZIP e nunca descompacta o conteúdo, então abrir um pacote enorme é rápido e não estoura a memória. A pontuação de suspeita soma um peso para cada sinal encontrado e é limitada a 100.

## Estrutura

    index.html        página única
    css/styles.css    estilos
    js/app.js         leitura do ZIP, análise e interface
    README.md
    LICENSE

## Privacidade

Nenhum arquivo é enviado para servidor nenhum. Todo o processamento acontece na máquina de quem abre a página, e o conteúdo do ZIP nunca é extraído no disco.

## Tecnologia

JavaScript puro, JSZip 3.10 e File API. Sem framework, sem etapa de build e sem dependência de servidor.

## Licença

MIT.
