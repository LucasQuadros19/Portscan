from scapy.all import *
import socket
import sys
import time
import argparse
import ipaddress
import random
import string
from urllib.parse import urlparse

# Silenciar Scapy
conf.verb = 0

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# ==============================================================================
#   1. VISUALIZAÇÃO AVANÇADA
# ==============================================================================

def desenhar_regua_bits():
    print(f"    0                   1                   2                   3")
    print(f"    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1")

def desenhar_ip_body(pkt):
    if IP not in pkt: return
    ip = pkt[IP]
    version = ip.version if ip.version is not None else 4
    ihl = ip.ihl if ip.ihl is not None else 5
    tos = ip.tos if ip.tos is not None else 0
    total_len = ip.len if ip.len is not None else 0
    identification = ip.id if ip.id is not None else 0
    flags = str(ip.flags)
    frag_offset = ip.frag if ip.frag is not None else 0
    ttl = ip.ttl if ip.ttl is not None else 64
    proto = ip.proto if ip.proto is not None else 6
    chksum = ip.chksum if ip.chksum is not None else 0
    src = ip.src
    dst = ip.dst

    print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")
    print(f"   |Ver: {version:<1}|IHL: {ihl:<1}|  TOS: {tos:<3}      |      Total Length: {total_len:<5}         |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |       Identification: {identification:<5}       |Flg:{flags:<3}|   Frag Offset: {frag_offset:<4}   |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |  TTL: {ttl:<3}      |  Proto: {proto:<3}     |     Header Checksum: {hex(chksum):<6} |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |                   Source: {Colors.CYAN}{src:<15}{Colors.RESET}                         |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |                Destination: {Colors.GREEN}{dst:<15}{Colors.RESET}                       |")
    print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")

def desenhar_tcp_body(pkt):
    if TCP not in pkt: return
    tcp = pkt[TCP]
    sport = tcp.sport if tcp.sport is not None else 0
    dport = tcp.dport if tcp.dport is not None else 0
    seq = tcp.seq if tcp.seq is not None else 0
    ack = tcp.ack if tcp.ack is not None else 0
    window = tcp.window if tcp.window is not None else 0
    chksum = tcp.chksum if tcp.chksum is not None else 0
    urgptr = tcp.urgptr if tcp.urgptr is not None else 0
    
    f_val = int(tcp.flags) if tcp.flags is not None else 0
    urg = 1 if f_val & 0x20 else 0
    ack_bit = 1 if f_val & 0x10 else 0
    psh = 1 if f_val & 0x08 else 0
    rst = 1 if f_val & 0x04 else 0
    syn = 1 if f_val & 0x02 else 0
    fin = 1 if f_val & 0x01 else 0

    print(f"   |     Source Port: {sport:<5}        |   Dest Port: {dport:<5}          |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |          Sequence Number: {seq:<10}                              |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |       Acknowledgment Number: {ack:<10}                           |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |  Data |           |{Colors.YELLOW}U{Colors.RESET}|{Colors.YELLOW}A{Colors.RESET}|{Colors.YELLOW}P{Colors.RESET}|{Colors.RED}R{Colors.RESET}|{Colors.GREEN}S{Colors.RESET}|{Colors.YELLOW}F{Colors.RESET}|                               |")
    print(f"   | Offset| Reserved  |{Colors.YELLOW}{urg}{Colors.RESET}|{Colors.YELLOW}{ack_bit}{Colors.RESET}|{Colors.YELLOW}{psh}{Colors.RESET}|{Colors.RED}{rst}{Colors.RESET}|{Colors.GREEN}{syn}{Colors.RESET}|{Colors.YELLOW}{fin}{Colors.RESET}|      Window: {window:<5}            |")
    print(f"   |       |           | | | | | | |                               |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |      Checksum: {hex(chksum):<6}         |    Urgent Pointer: {urgptr:<5}      |")
    print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")
    
    if Raw in pkt:
        payload_len = len(pkt[Raw].load)
        print(f"   |                   Data / Payload ({payload_len} bytes)                   |")
        print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")

def imprimir_bytes_separados(pkt, formato='hex'):
    raw_pkt = raw(pkt)
    try: ip_header_len = (raw_pkt[0] & 0x0f) * 4
    except: ip_header_len = 20
    ip_bytes = raw_pkt[:ip_header_len]
    remaining = raw_pkt[ip_header_len:]
    tcp_header_len = 20
    if len(remaining) >= 13: tcp_header_len = ((remaining[12] >> 4) & 0x0f) * 4
    tcp_bytes = remaining[:tcp_header_len]
    payload_bytes = remaining[tcp_header_len:]
    
    def fmt_chunk(b_data, mode):
        if mode == 'hex':
            hex_str = b_data.hex()
            return " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        else:
            bin_str = "".join(f"{b:08b}" for b in b_data)
            return "\n".join(" ".join(bin_str[i:i+8] for i in range(k, k+32, 8)) for k in range(0, len(bin_str), 32))

    print(f"{Colors.BLUE}[ IPv4 Header ({len(ip_bytes)} bytes) ]{Colors.RESET}")
    print(f"{Colors.CYAN}{fmt_chunk(ip_bytes, formato)}{Colors.RESET}")
    print(f"\n{Colors.BLUE}[ TCP Header ({len(tcp_bytes)} bytes) ]{Colors.RESET}")
    print(f"{Colors.YELLOW}{fmt_chunk(tcp_bytes, formato)}{Colors.RESET}")
    if len(payload_bytes) > 0:
        print(f"\n{Colors.BLUE}[ Data / Payload ({len(payload_bytes)} bytes) ]{Colors.RESET}")
        print(f"{Colors.MAGENTA}{fmt_chunk(payload_bytes, formato)}{Colors.RESET}")

def mostrar_pacote(pkt, tipo, modo):
    cor = Colors.MAGENTA if tipo == "ENVIADO" else Colors.CYAN
    seta = ">>" if tipo == "ENVIADO" else "<<"
    print(f"\n{cor}{Colors.BOLD}{seta} PACOTE {tipo} ({modo.upper()}){Colors.RESET}")
    if modo == 'text':
        desenhar_regua_bits()
        if IP in pkt: desenhar_ip_body(pkt)
        if TCP in pkt: desenhar_tcp_body(pkt)
    elif modo == 'hex': imprimir_bytes_separados(pkt, 'hex')
    elif modo == 'bin': imprimir_bytes_separados(pkt, 'bin')

# ==============================================================================
#   2. LÓGICA DE REDE
# ==============================================================================

def criar_pacote(ip, port, flags, padding, src_port):
    pkt = IP(dst=ip)/TCP(sport=src_port, dport=port, flags=flags)
    if padding:
        lixo = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(20,50)))
        pkt = pkt / Raw(load=lixo)
    return pkt

def enviar_pacote(pkt, fragmentar, view_mode):
    if view_mode: mostrar_pacote(pkt, "ENVIADO", view_mode)
    if fragmentar:
        fragmentos = fragment(pkt, fragsize=8)
        for f in fragmentos: send(f, verbose=0)
        return None
    else:
        resp = sr1(pkt, timeout=1.0, verbose=0)
        if view_mode and resp: mostrar_pacote(resp, "RECEBIDO", view_mode)
        elif view_mode: print(f"{Colors.RED}[!] Sem resposta (Timeout){Colors.RESET}")
        return resp

def analisar_resposta(resp, modo, ip, port, view_mode, src_port):
    if resp is None:
        if modo in ["Null", "FIN", "PSH"]: return "open|filtered"
        return "filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags & 0x04: 
            if modo == "Window":
                if resp.getlayer(TCP).window > 0: return "open"
                else: return "closed"
            return "closed"
        if flags & 0x12:
            if modo == "SYN":
                rst_pkt = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R", seq=resp.seq, ack=resp.ack)
                if view_mode:
                    print(f"\n{Colors.YELLOW}[*] Conexão estabelecida! Enviando RST para fechar (Stealth)...{Colors.RESET}")
                    mostrar_pacote(rst_pkt, "ENVIADO", view_mode)
                send(rst_pkt, verbose=0)
            return "open"
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3: return "filtered"
    return "filtered"

def pegar_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        if port in [80, 8080, 443]: s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        else: s.send(b'Hello\r\n')
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner.split('\n')[0][:50] if banner else None
    except: return None

# --- UTILITÁRIOS ---

def validar_alvo(alvo_input):
    try: return str(ipaddress.ip_address(alvo_input)), alvo_input
    except: pass
    if not alvo_input.startswith("http"): alvo_input = "http://" + alvo_input
    try:
        host = urlparse(alvo_input).netloc.split(':')[0] or alvo_input.replace("http://", "")
        return socket.gethostbyname(host), host
    except:
        print(f"{Colors.RED}[!] Erro: Host não encontrado.{Colors.RESET}")
        sys.exit(1)

def parse_portas(porta_str):
    if porta_str == "common":
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    elif '-' in porta_str: return list(range(int(porta_str.split('-')[0]), int(porta_str.split('-')[1]) + 1))
    return [int(p) for p in porta_str.split(',')]

def nome_servico(port):
    try: return socket.getservbyport(port, 'tcp')
    except: return "unknown"

# ==============================================================================
#   3. MAIN
# ==============================================================================

def exibir_banner_ajuda():
    print(f"{Colors.BLUE}" + "="*65 + f"{Colors.RESET}")
    print(f"{Colors.BOLD}      SCAPY SCANNER - FERRAMENTA DE ANÁLISE E ESTUDO{Colors.RESET}")
    print(f"{Colors.BLUE}" + "="*65 + f"{Colors.RESET}")
    print(f"\n{Colors.BOLD}USO:{Colors.RESET} sudo python3 portscan.py <ALVO> [OPÇÕES]")
    print(f"\n{Colors.YELLOW}[1] TÉCNICAS DE SCAN:{Colors.RESET}")
    print(f"  {Colors.BOLD}-sS{Colors.RESET} : TCP SYN Scan (BASE)")
    print(f"  {Colors.BOLD}-sW{Colors.RESET} : TCP Window Scan")
    print(f"  {Colors.BOLD}-sN{Colors.RESET} : TCP Null Scan")
    print(f"  {Colors.BOLD}-sF{Colors.RESET} : TCP FIN Scan")
    print(f"  {Colors.BOLD}-sP{Colors.RESET} : TCP PSH Scan")
    print(f"\n{Colors.YELLOW}[2] TÉCNICAS DE EVASÃO:{Colors.RESET}")
    print(f"  {Colors.BOLD}-f{Colors.RESET}    : Fragmentação")
    print(f"  {Colors.BOLD}--pad{Colors.RESET} : Padding")
    print(f"\n{Colors.YELLOW}[3] VISUALIZAÇÃO:{Colors.RESET}")
    print(f"  {Colors.BOLD}-sV{Colors.RESET}         : Detectar Versão (Informativo)")
    print(f"  {Colors.BOLD}--view text{Colors.RESET} : Ver Diagrama IP+TCP")
    print(f"  {Colors.BOLD}--view hex{Colors.RESET}  : Ver HexDump")
    print(f"  {Colors.BOLD}--view bin{Colors.RESET}  : Ver Binário")
    print(f"\n{Colors.YELLOW}[4] PORTAS:{Colors.RESET}")
    print(f"  {Colors.BOLD}-p common{Colors.RESET}, {Colors.BOLD}-p 80,443{Colors.RESET}, {Colors.BOLD}-p 20-30{Colors.RESET}")
    print(f"\n{Colors.BLUE}" + "-"*65 + f"{Colors.RESET}")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target", nargs='?')
    parser.add_argument("-p", "--ports", default="common")
    parser.add_argument("-sS", "--syn", action="store_true")
    parser.add_argument("-sW", "--window", action="store_true")
    parser.add_argument("-sN", "--null", action="store_true")
    parser.add_argument("-sF", "--fin", action="store_true")
    parser.add_argument("-sP", "--psh", action="store_true")
    parser.add_argument("-f", "--frag", action="store_true")
    parser.add_argument("--pad", action="store_true")
    parser.add_argument("-sV", "--version", action="store_true")
    parser.add_argument("--view", choices=['text', 'hex', 'bin'])
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help or not args.target: exibir_banner_ajuda()

    try:
        ip_alvo, hostname = validar_alvo(args.target)
        portas = parse_portas(args.ports)
        
        if args.syn: mode, flags = "SYN", "S"
        elif args.psh: mode, flags = "PSH", "P"
        elif args.fin: mode, flags = "FIN", "F"
        elif args.null: mode, flags = "Null", ""
        elif args.window: mode, flags = "Window", "A"
        else:
            print(f"{Colors.YELLOW}[!] Nenhum scan escolhido. Usando SYN (-sS).{Colors.RESET}")
            mode, flags = "SYN", "S"

        print(f"\n{Colors.BOLD}Iniciando {mode} Scan em {hostname}{Colors.RESET}")
        
        infos = []
        if args.frag: infos.append("Fragmentação")
        if args.pad: infos.append("Padding")
        if args.view: infos.append(f"Visual: {args.view.upper()}")
        if infos: print(f"{Colors.BLUE}[*] Opções: {', '.join(infos)}{Colors.RESET}")

        resultados = []
        start_time = time.time()

        for port in portas:
            try:
                src_port = random.randint(1025, 65535)
                pkt = criar_pacote(ip_alvo, port, flags, args.pad, src_port)
                resp = enviar_pacote(pkt, args.frag, args.view)
                
                if args.frag: state = "open|filtered"
                else: state = analisar_resposta(resp, mode, ip_alvo, port, args.view, src_port)
                
                # --- BANNER GRAB (INFORMATIVO) ---
                banner = ""
                if args.version and ("open" in state):
                    if args.view: print(f"{Colors.YELLOW}    [*] Tentando Banner Grab...{Colors.RESET}")
                    
                    obtained = pegar_banner(ip_alvo, port)
                    
                    if obtained:
                        banner = obtained
                        # Confirmamos que é Open (se havia dúvida como open|filtered)
                        state = "open"
                    else:
                        # NÃO FECHAMOS A PORTA SE O BANNER FALHAR
                        banner = "Sem Banner"
                        if args.view: print(f"{Colors.RED}    [x] Banner falhou (Timeout/SSL?), mas porta segue aberta.{Colors.RESET}")
                
                servico = nome_servico(port)
                resultados.append({"port": port, "state": state, "service": servico, "banner": banner})
                if args.view: print("-" * 50); time.sleep(0.5)

            except KeyboardInterrupt: sys.exit(0)

        print("\n" + "="*65)
        print(f"{'PORT':<10} {'STATE':<15} {'SERVICE':<15} {'BANNER'}")
        print("-" * 65)
        
        encontrou_algo = False
        for r in resultados:
            if r['state'] not in ["closed", "filtered"]:
                encontrou_algo = True
                p_fmt = f"{r['port']}/tcp"
                cor = Colors.GREEN if r['state'] == "open" else Colors.YELLOW
                b_txt = r['banner'] if r['banner'] else ""
                print(f"{p_fmt:<10} {cor}{r['state']:<15}{Colors.RESET} {r['service']:<15} {Colors.CYAN}{b_txt}{Colors.RESET}")
        
        if not encontrou_algo:
            print(f"{Colors.YELLOW}Nenhuma porta aberta encontrada.{Colors.RESET}")

        print(f"\nTempo: {time.time() - start_time:.2f}s")

    except PermissionError: print(f"\n{Colors.RED}[!] ERRO: É necessário executar como ROOT (sudo).{Colors.RESET}")
    except KeyboardInterrupt: print(f"\n{Colors.YELLOW}[!] Interrompido pelo usuário.{Colors.RESET}")
    except Exception as e: print(f"\n{Colors.RED}[!] Erro inesperado: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()