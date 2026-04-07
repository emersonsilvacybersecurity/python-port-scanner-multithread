# 🔎 Python Port Scanner (Multi-threaded)

Ferramenta de reconhecimento de rede de alta performance desenvolvida em Python. Este script utiliza Threading e Queues para realizar varreduras simultâneas em portas TCP, permitindo identificar serviços ativos em milissegundos.

---

## ⚙️ Funcionalidades

- 🚀 Multi-threading: Varredura rápida utilizando múltiplas threads simultâneas.
- 🌐 Resolução de DNS: Suporta tanto endereços IP quanto domínios (ex: google.com).
- 🔍 Identificação de Serviços: Tradução automática de portas comuns (HTTP, SSH, FTP, etc).
- 🔒 Thread Safety: Uso de Lock para evitar conflito de saída no terminal.
- ⚠️ Gerenciamento de Erros: Tratamento de conexões recusadas e timeouts.

---

## 🧰 Tecnologias Utilizadas

- Python 3.x
- socket
- threading
- queue

---

## 🚀 Como executar

Siga os passos abaixo para rodar o projeto localmente:

### 📥 1. Clonar o repositório
```bash
git clone https://github.com/emersonsilvacybersecurity/python-port-scanner-multithread.git
```

### 📂 2. Acessar a pasta do projeto
```bash
cd python-port-scanner-multithread
```

### ▶️ 3. Executar o script

#### 💻 Windows
```bash
python PortScannerMultithread.py
```

#### 🐧 Linux
```bash
python3 PortScannerMultithread.py
```

## ⚠️ Análise de segurança (Aviso Legal)

Este roteiro foi desenvolvido exclusivamente para fins educacionais e auditorias de segurança autorizadas.

- ⚖️ Ética: O uso desta ferramenta contra alvos sem permissão prévia é ilegal.
- 🚫 Responsabilidade: O autor não se responsabiliza por qualquer uso indevido ou danos causados a terceiros.




    



