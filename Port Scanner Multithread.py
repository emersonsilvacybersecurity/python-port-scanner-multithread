import socket
import sys
from datetime import datetime
from queue import Queue
from threading import Thread, Lock

class PortScanner:
    def __init__(self, target_host, thread_count=100):
        self.target_host = target_host
        self.target_ip = self._resolve_host(target_host)
        self.thread_count = thread_count
        self.queue = Queue()
        self.open_ports = []
        self.print_lock = Lock() # Garante que as mensagens não saiam embaralhadas

    def _resolve_host(self, host):
        """Resolve o domínio para IP e valida a conexão."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            print(f"\n[!] Erro Crítico: Não foi possível resolver o host '{host}'.")
            sys.exit(1)

    def _scan_port(self, port):
        """Tenta realizar um TCP Handshake na porta especificada."""
        try:
            # Uso de Context Manager (with) para fechar o socket automaticamente
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0) # 1 segundo é o padrão de mercado para scanners rápidos
                result = s.connect_ex((self.target_ip, port))
                
                if result == 0:
                    with self.print_lock:
                        print(f"  [+] Porta {port:5} | Aberta  | {self._get_service_name(port)}")
                        self.open_ports.append(port)
        except Exception:
            pass # Ignora erros de conexão individuais para manter o fluxo

    def _get_service_name(self, port):
        """Tenta identificar o serviço padrão da porta."""
        try:
            return socket.getservbyport(port)
        except:
            return "Serviço Desconhecido"

    def _worker(self):
        """Gerencia as tarefas da fila para as threads."""
        while not self.queue.empty():
            port = self.queue.get()
            self._scan_port(port)
            self.queue.task_done()

    def run(self, start_port=1, end_port=1024):
        """Inicia o processo de escaneamento."""
        print("-" * 50)
        print(f"Iniciando Scan em: {self.target_host} ({self.target_ip})")
        print(f"Horário de início: {datetime.now().strftime('%H:%M:%S')}")
        print("-" * 50)

        # Preenche a fila (Queue)
        for port in range(start_port, end_port + 1):
            self.queue.put(port)

        # Lança as Threads
        threads = []
        for _ in range(self.thread_count):
            t = Thread(target=self._worker)
            t.daemon = True # Encerra as threads se o script principal for fechado
            t.start()
            threads.append(t)

        # Aguarda a conclusão
        self.queue.join()
        
        print("-" * 50)
        print(f"Scan finalizado em {self.target_host}.")
        print(f"Total de portas abertas: {len(self.open_ports)}")
        print("-" * 50)

if __name__ == "__main__":
    # Exemplo de uso seguro e verificável na internet: scanme.nmap.org
    alvo_input = input("Digite o domínio ou IP para análise: ").strip()
    
    scanner = PortScanner(target_host=alvo_input, thread_count=100)
    scanner.run(start_port=1, end_port=1000)
    