# Python Port Scanner (Multi-threaded) 

Ferramenta de reconhecimento de rede de alta performance desenvolvida em Python. Este script utiliza **Threading** e **Queues** para realizar varreduras simultâneas em portas TCP, permitindo identificar serviços ativos em milissegundos.

##  Funcionalidades

* **Multi-threading:** Varredura rápida utilizando múltiplas threads simultâneas.
* **Resolução de DNS:** Suporta tanto endereços IP quanto domínios (ex: google.com).
* **Identificação de Serviços:** Tradução automática de portas comuns para seus respectivos serviços (HTTP, SSH, FTP, etc).
* **Thread Safety:** Utilização de `Lock` para garantir que a saída no terminal não seja atropelada por diferentes threads.
* **Gerenciamento de Erros:** Tratamento de exceções para conexões recusadas e timeouts.

##  Tecnologias Utilizadas

* **Python 3.x**
* `socket`: Para comunicação de baixo nível.
* `threading`: Para execução paralela.
* `queue`: Para gerenciamento de carga de trabalho entre as threads.


Análise de segurança (Aviso Legal)
Este roteiro foi desenvolvido exclusivamente para fins educacionais e auditorias de segurança autorizadas.
Ética: O uso desta ferramenta contra alvos sem permissão prévia é ilegal.
Responsabilidade: O autor não se responsabiliza por qualquer uso indevido ou danos causados a terceiros.    

    



