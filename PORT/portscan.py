import socket
import nmap

def scan_ports(ip, ports):

    print(f"[+] Escaneando portas em {ip}")
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:  
                print(f"    - Porta {port} aberta!")
                open_ports.append(port)
    return open_ports

def identify_services(ip, open_ports):

    print(f"[+] Identificando serviços em {ip}")
    nm = nmap.PortScanner()
    services = {}
    for port in open_ports:
        try:
            nm.scan(ip, str(port))
            service = nm[ip]['tcp'][port]['name']
            print(f"    - Porta {port}: {service}")
            services[port] = service
        except KeyError:
            print(f"    - Porta {port}: Serviço desconhecido")
            services[port] = "desconhecido"
    return services

def check_vulnerabilities(services):

    known_vulnerabilities = {
        'ftp': "Senha padrão fraca ou sem criptografia",
        'ssh': "Ataques de força bruta comuns",
        'http': "Possível vulnerabilidade em versões desatualizadas",
        'mysql': "Senha padrão fraca ou acesso remoto exposto",
    }
    print("[+] Verificando vulnerabilidades básicas...")
    vulnerabilities = {}
    for port, service in services.items():
        if service in known_vulnerabilities:
            vulnerabilities[port] = known_vulnerabilities[service]
            print(f"    - Porta {port} ({service}): {known_vulnerabilities[service]}")
        else:
            print(f"    - Porta {port} ({service}): Sem vulnerabilidades conhecidas")
    return vulnerabilities

if __name__ == "__main__":
    target_ip = input("Digite o IP ou domínio para escanear: ")

    ports_to_scan = range(1, 1025)
    

    open_ports = scan_ports(target_ip, ports_to_scan)
    
    if open_ports:

        services = identify_services(target_ip, open_ports)

        vulnerabilities = check_vulnerabilities(services)
    else:
        print("[!] Nenhuma porta aberta encontrada.")
