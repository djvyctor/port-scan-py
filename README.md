Port Scanner com Identificação de Serviços e Verificação de Vulnerabilidades
Este script realiza as seguintes funções principais:

Escaneamento de portas:

Verifica portas abertas em um endereço IP fornecido pelo usuário.
Utiliza sockets para testar conexões em um intervalo de portas.
Identificação de serviços:

Determina quais serviços estão rodando nas portas abertas, utilizando a biblioteca nmap.
Verificação de vulnerabilidades conhecidas:

Compara os serviços identificados com uma lista de vulnerabilidades conhecidas para sugerir possíveis riscos.
Tecnologias utilizadas:
Python: Linguagem de programação principal.
socket: Biblioteca para criar conexões de rede.
nmap: Ferramenta para varredura e identificação de serviços.
Como usar:
Execute o script.
Insira o IP ou domínio que deseja escanear.
O script analisará as portas (padrão: 1-1024) e listará:
Portas abertas.
Serviços rodando.
Vulnerabilidades conhecidas.

[+] Escaneando portas em 192.168.1.1
    - Porta 22 aberta!
    - Porta 80 aberta!
[+] Identificando serviços em 192.168.1.1
    - Porta 22: ssh
    - Porta 80: http
[+] Verificando vulnerabilidades básicas...
    - Porta 22 (ssh): Ataques de força bruta comuns
    - Porta 80 (http): Possível vulnerabilidade em versões desatualizadas

Observações:
Ideal para análises básicas de segurança.
Não substitui ferramentas profissionais ou auditorias de segurança mais robustas.
