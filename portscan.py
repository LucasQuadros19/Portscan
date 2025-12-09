from scapy.all import *
import socket
import sys

# Configuração para o Scapy não imprimir mensagens de log padrão
conf.verb = 0

def resolver_alvo(alvo):
    """
    Resolve DNS se necessário e retorna o IP.
    """
    try:
        ip = socket.gethostbyname(alvo)
        print(f"[*] Alvo: {alvo} resolvido para IP: {ip}")
        return ip
    except socket.gaierror:
        print(f"[!] Erro: Não foi possível resolver o hostname {alvo}.")
        sys.exit(1)

def tcp_syn_scan(target_ip, port):
    """
    Envia SYN. 
    Se SYN-ACK -> Aberta (e envia RST). 
    Se RST -> Fechada.
    """
    # Construção do Pacote: IP -> TCP (Flags="S" de SYN)
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
    
    # sr1 envia o pacote e espera a primeira resposta
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:
        return "Filtrada (Sem resposta)"
    elif resp.haslayer(TCP):
        # 0x12 é hexadecimal para SYN+ACK (SYN=0x02, ACK=0x10)
        if resp.getlayer(TCP).flags == 0x12:
            # Envia RST para fechar a conexão graciosamente (Stealth)
            sr(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
            return "ABERTA"
        elif resp.getlayer(TCP).flags == 0x14: # 0x14 é RST+ACK
            return "Fechada"
    return "Desconhecido/Filtrado"

def udp_scan(target_ip, port):
    """
    Envia UDP vazio.
    ICMP Port Unreachable -> Fechada.
    Sem resposta -> Aberta/Filtrada.
    """
    pkt = IP(dst=target_ip)/UDP(dport=port)
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:
        return "Aberta/Filtrada"
    elif resp.haslayer(ICMP):
        # Type 3 = Dest Unreachable, Code 3 = Port Unreachable
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3:
            return "Fechada"
    return "Aberta/Filtrada"

def tcp_ack_scan(target_ip, port):
    """
    Envia ACK.
    RST -> Unfiltered (Passou pelo firewall).
    Sem resposta -> Filtered (Firewall bloqueou).
    """
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="A")
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:
        return "Filtrada (Firewall Bloqueou)"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x04: # RST
            return "Não Filtrada (Chegou ao alvo)"
    elif resp.haslayer(ICMP):
         if int(resp.getlayer(ICMP).type) == 3:
            return "Filtrada (ICMP Error)"
    return "Filtrada"

def tcp_xmas_scan(target_ip, port):
    """
    Envia FIN, PSH, URG.
    RST -> Fechada.
    Sem resposta -> Aberta/Filtrada.
    """
    # Flags FPU (Fin, Push, Urgent)
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="FPU")
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:
        return "Aberta/Filtrada"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x14: # RST
            return "Fechada"
    elif resp.haslayer(ICMP):
        return "Filtrada"
    return "Aberta/Filtrada"

def main():
    print("=== Scapy Port Scanner ===")
    target = input("Digite o IP ou Hostname Alvo: ")
    ports_input = input("Digite as portas (ex: 22,80,443): ")
    
    # Tratamento da lista de portas
    try:
        ports = [int(p.strip()) for p in ports_input.split(',')]
    except ValueError:
        print("[!] Erro: Formato de portas inválido.")
        sys.exit(1)

    target_ip = resolver_alvo(target)
    
    print(f"\nIniciando scans em {target_ip}...\n")
    print(f"{'PORTA':<8} {'TIPO':<10} {'STATUS':<25}")
    print("-" * 45)

    try:
        for port in ports:
            # 1. SYN Scan
            status_syn = tcp_syn_scan(target_ip, port)
            print(f"{port:<8} {'SYN':<10} {status_syn:<25}")
            
            # 2. UDP Scan
            status_udp = udp_scan(target_ip, port)
            print(f"{port:<8} {'UDP':<10} {status_udp:<25}")
            
            # 3. ACK Scan
            status_ack = tcp_ack_scan(target_ip, port)
            print(f"{port:<8} {'ACK':<10} {status_ack:<25}")

            # 4. Xmas Scan
            status_xmas = tcp_xmas_scan(target_ip, port)
            print(f"{port:<8} {'XMAS':<10} {status_xmas:<25}")
            
            print("-" * 45)
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrompido pelo usuário.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Ocorreu um erro inesperado: {e}")

if __name__ == "__main__":
    main()
