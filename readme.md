# PrefetchTamper !

> Modifica um arquivo **Windows Prefetch (`.pf`)** específico, mantendo algumas das entradas existentes e removendo o restante.

## O que faz

O programa:
- Mantém somente as primeiras **11 entradas**.
- Limpa os caminhos e registros das entradas restantes.
- Remove as `trace chains`, quando existentes.
- Recompacta o arquivo.
- Grava o resultado novamente e restaura os timestamps originais.

> [!TIP]
> A intenção é disponibilizar uma estrutura inicial para que outras pessoas possam estudar
