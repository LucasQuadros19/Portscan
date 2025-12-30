from scapy.all import *
import socket
import sys
import time
from urllib.parse import urlparse # Import necessário para interpretar URLs

# Configuração silenciosa do Scapy
conf.verb = 0

PORTAS_COMUNS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]

def limpar_alvo(alvo_input):
    """
    Interpreta o input do usuário e extrai apenas o hostname limpo.
    Aceita: 
    - https://www.site.com/paginas -> www.site.com
    - http://192.168.1.50:8080 -> 192.168.1.50
    - site.com -> site.com
    """
    alvo = alvo_input.strip()

    if not alvo.startswith(("http://", "https://")):
        alvo = "http://" + alvo
        
    parsed = urlparse(alvo)
    hostname = parsed.netloc # Pega apenas o domínio/IP (ex: www.google.com:80)
    
    # Se houver porta explícita (ex: :8080), removemos para resolver o IP base
    if ':' in hostname:
        hostname = hostname.split(':')[0]
        
    return hostname

def resolver_alvo(alvo_input):
    """
    Limpa o hostname e resolve o IP.
    """
    host_limpo = limpar_alvo(alvo_input)
    
    try:
        ip = socket.gethostbyname(host_limpo)
        # Mostra o feedback visual da interpretação
        if host_limpo != alvo_input:
            print(f"[*] Input interpretado: '{alvo_input}' -> '{host_limpo}'")
        print(f"[*] Alvo resolvido para IP: {ip}")
        return ip
    except socket.gaierror:
        print(f"\n[!] Erro DNS: Não foi possível resolver o host '{host_limpo}'.")
        print("    Verifique a conexão ou se o endereço está correto.")
        sys.exit(1)

def enviar_pacote(pkt, timeout=1):
    """
    Envia pacote com proteção contra travamento do Ctrl+C
    """
    inicio = time.time()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    duracao = time.time() - inicio

    # Se retornou None muito rápido, foi interrupção do usuário
    if resp is None and duracao < (timeout * 0.8):
        raise KeyboardInterrupt
    
    return resp


def tcp_syn_scan(target_ip, port):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
    resp = enviar_pacote(pkt)
    
    if resp is None: return "Filtrada (Sem resposta)"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            sr(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
            return "ABERTA"
        elif resp.getlayer(TCP).flags == 0x14: return "Fechada"
    return "Desconhecido"

def udp_scan(target_ip, port):
    pkt = IP(dst=target_ip)/UDP(dport=port)
    resp = enviar_pacote(pkt)
    if resp is None: return "Aberta/Filtrada"
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3:
            return "Fechada"
    return "Aberta/Filtrada"

def tcp_ack_scan(target_ip, port):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="A")
    resp = enviar_pacote(pkt)
    if resp is None: return "Filtrada (Firewall)"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x04: return "Não Filtrada"
    elif resp.haslayer(ICMP):
         if int(resp.getlayer(ICMP).type) == 3: return "Filtrada (ICMP)"
    return "Filtrada"

def tcp_xmas_scan(target_ip, port):
    pkt = IP(dst=target_ip)/TCP(dport=port, flags="FPU")
    resp = enviar_pacote(pkt)
    if resp is None: return "Aberta/Filtrada"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x14: return "Fechada"
    elif resp.haslayer(ICMP): return "Filtrada"
    return "Aberta/Filtrada"

# --- MENUS ---

def obter_portas():
    print("\n--- Seleção de Portas ---")
    print("1. Lista (ex: 80,443)")
    print("2. Intervalo (ex: 1-100)")
    print("3. Portas comuns (Top Ports)")
    
    opcao = input("\nOpção: ").strip()
    
    if opcao == '1':
        entrada = input("Portas: ")
        return [int(p.strip()) for p in entrada.split(',')]
    elif opcao == '2':
        entrada = input("Intervalo (inicio-fim): ")
        i, f = map(int, entrada.split('-'))
        if i > f: raise ValueError("Início maior que o fim")
        return list(range(i, f + 1))
    elif opcao == '3':
        return PORTAS_COMUNS
    else:
        raise ValueError("Opção inválida")

def main():
    try:
        print("=== Scapy Port Scanner Pro ===")
        # Aceita qualquer formato agora (URL, IP, Domínio)
        raw_target = input("Alvo (URL, IP ou Hostname): ").strip()
        
        if not raw_target:
            print("[!] O alvo não pode ser vazio.")
            sys.exit(1)

        # Resolve e limpa o alvo
        target_ip = resolver_alvo(raw_target)
        
        ports = obter_portas()

        print(f"\nIniciando scans em {target_ip}...\n")
        print(f"{'PORTA':<8} {'TIPO':<10} {'STATUS':<25}")
        print("-" * 45)

        for port in ports:
            try:
                # Armazena resultados para imprimir alinhado
                res_syn = tcp_syn_scan(target_ip, port)
                print(f"{port:<8} {'SYN':<10} {res_syn:<25}")
                
                res_udp = udp_scan(target_ip, port)
                print(f"{port:<8} {'UDP':<10} {res_udp:<25}")
                
                res_ack = tcp_ack_scan(target_ip, port)
                print(f"{port:<8} {'ACK':<10} {res_ack:<25}")
                
                res_xmas = tcp_xmas_scan(target_ip, port)
                print(f"{port:<8} {'XMAS':<10} {res_xmas:<25}")
                
                print("-" * 45)
            except KeyboardInterrupt:
                raise KeyboardInterrupt # Joga para o catch principal

    except KeyboardInterrupt:
        print("\n\n[!] Interrompido pelo usuário. Saindo...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Erro: {e}")

if __name__ == "__main__":
    main()