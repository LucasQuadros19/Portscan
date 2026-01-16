from scapy.all import *
import socket
import sys
import time
import argparse
import ipaddress
import random
import string
from urllib.parse import urlparse
import signal



conf.verb = 0  

def signal_handler(sig, frame):
    print(f"\n\n{Colors.RED}[!] ABORTADO PELO USUÁRIO (Ctrl+C). Saindo...{Colors.RESET}")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

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
#   1.SCANNER 
# ==============================================================================

def criar_pacote(ip, port, flags, padding, http, src_port):
    
    # 1. Base TCP/IP
    pkt = IP(dst=ip)/TCP(sport=src_port, dport=port, flags=flags, seq=1000)
    
    # 2. HTTP Injection
    if http:
        payload = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: google.com\r\n\r\n"
        pkt = pkt / Raw(load=payload)
    
    # Padding
    elif padding:
       
        lixo = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(20,50)))
        pkt = pkt / Raw(load=lixo)
        
    return pkt

def analisar_resposta(resp, modo, ip, port, view_mode, src_port):
  
    # Sem resposta?
    if resp is None:
        # (Null/FIN/PSH) Aberta ou dropada
        if modo in ["Null", "FIN", "PSH"]: return "open|filtered"
        return "filtered"
        
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        
        #(Null/FIN/PSH)
        if modo in ["Null", "FIN", "PSH"]:
            if flags & 0x04: return "closed" 
            return "filtered"

        # SYN
        if flags & 0x04: return "closed" 
        if flags & 0x12: 

            if modo == "SYN":
                rst_pkt = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R", seq=resp.seq, ack=resp.ack)
                send(rst_pkt, verbose=0)
            return "open"
            
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3: return "filtered" # Host/Port Unreachable
        
    return "filtered"

def enviar_pacote(pkt, fragmentar, view_mode):
    if fragmentar:
        
        fragmentos = fragment(pkt, fragsize=8)
        
        
        for i, frag in enumerate(fragmentos):
            if view_mode:
                print(f"\n{Colors.YELLOW}[+] Enviando Fragmento {i+1} (Offset: {frag[IP].frag * 8} bytes){Colors.RESET}")
                mostrar_pacote(frag, f"FRAG-{i+1}", view_mode)
            
            send(frag, verbose=0)
        return None
    else:
        
        if view_mode: mostrar_pacote(pkt, "ENVIADO", view_mode)
        
        resp = sr1(pkt, timeout=1.0, verbose=0)
        if view_mode and resp: mostrar_pacote(resp, "RECEBIDO", view_mode)
        elif view_mode: print(f"{Colors.RED}[!] Sem resposta (Timeout/Drop){Colors.RESET}")
        return resp

def pegar_banner(ip, port):
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        
        # Tenta leitura passiva (ex: SSH manda banner sozinho)
        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                s.close()
                return banner.split('\n')[0][:50]
        except socket.timeout: pass

        # Se falhar, tenta leitura ativa (HTTP)
        if port in [80, 8080, 443]: s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        else: s.send(b'Hello\r\n')
        
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner.split('\n')[0][:50] if banner else None
    
    except KeyboardInterrupt: raise
    except Exception: return None

# ==============================================================================
#   2. FUNÇÕES DE VISUALIZAÇÃO (RFC & HEX DUMP)
#   (Deixadas aqui para não poluir a apresentação da lógica acima)
# ==============================================================================

def desenhar_regua_bits():
    print(f"    0                   1                   2                   3")
    print(f"    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1")

def desenhar_ip_body(pkt):
    if IP not in pkt: return
    ip = pkt[IP]
    # Tratamento de campos None para evitar erro visual antes do envio
    ver = ip.version if ip.version is not None else 4
    ihl = ip.ihl if ip.ihl is not None else 5
    tos = ip.tos if ip.tos is not None else 0
    t_len = ip.len if ip.len is not None else 0
    ident = ip.id if ip.id is not None else 0
    flags = str(ip.flags)
    frag = ip.frag if ip.frag is not None else 0
    ttl = ip.ttl if ip.ttl is not None else 64
    proto = ip.proto if ip.proto is not None else 6
    chk = ip.chksum if ip.chksum is not None else 0
    
    print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")
    print(f"   |Ver: {ver:<1}|IHL: {ihl:<1}|  TOS: {tos:<3}      |      Total Length: {t_len:<5}         |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |       Identification: {ident:<5}       |Flg:{flags:<3}|   Frag Offset: {frag:<4}   |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |  TTL: {ttl:<3}      |  Proto: {proto:<3}     |     Header Checksum: {hex(chk):<6} |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |                   Source: {Colors.CYAN}{ip.src:<15}{Colors.RESET}                         |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |                Destination: {Colors.GREEN}{ip.dst:<15}{Colors.RESET}                       |")
    print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")

def desenhar_tcp_body(pkt):
    if TCP not in pkt: return
    tcp = pkt[TCP]
    
    sport = tcp.sport if tcp.sport is not None else 0
    dport = tcp.dport if tcp.dport is not None else 0
    seq = tcp.seq if tcp.seq is not None else 0
    ack = tcp.ack if tcp.ack is not None else 0
    window = tcp.window if tcp.window is not None else 0
    chk = tcp.chksum if tcp.chksum is not None else 0
    urg_ptr = tcp.urgptr if tcp.urgptr is not None else 0
    
    f_val = int(tcp.flags) if tcp.flags is not None else 0
    urg = 1 if f_val & 0x20 else 0
    ack_bit = 1 if f_val & 0x10 else 0
    psh = 1 if f_val & 0x08 else 0
    rst = 1 if f_val & 0x04 else 0
    syn = 1 if f_val & 0x02 else 0
    fin = 1 if f_val & 0x01 else 0

    def c(bit, ativo): return f"{Colors.RED}{bit}{Colors.RESET}" if ativo else f"{Colors.YELLOW}{bit}{Colors.RESET}"

    flags_vis = f"{c('U',urg)}|{c('A',ack_bit)}|{c('P',psh)}|{c('R',rst)}|{c('S',syn)}|{c('F',fin)}"
    bits_vis  = f"{c(urg,urg)}|{c(ack_bit,ack_bit)}|{c(psh,psh)}|{c(rst,rst)}|{c(syn,syn)}|{c(fin,fin)}"

    print(f"   |     Source Port: {sport:<5}        |   Dest Port: {dport:<5}          |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |          Sequence Number: {seq:<10}                              |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |       Acknowledgment Number: {ack:<10}                           |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |  Data |           |{flags_vis}|                               |")
    print(f"   | Offset| Reserved  |{bits_vis}|      Window: {window:<5}            |")
    print(f"   |       |           | | | | | | |                               |")
    print(f"   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"   |      Checksum: {hex(chk):<6}         |    Urgent Pointer: {urg_ptr:<5}      |")
    print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")
    
    if Raw in pkt:
        payload_data = pkt[Raw].load
        payload_len = len(payload_data)
        try:
            preview = payload_data.decode('utf-8', errors='ignore').strip()
            if len(preview) > 50: preview = preview[:50] + "..."
        except:
            preview = "Dados binários"

        print(f"   | [PAYLOAD] Tamanho: {payload_len} bytes                                   |")
        print(f"   | Conteúdo: {Colors.MAGENTA}{preview:<50}{Colors.RESET}|")
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
        
        # --- NOVO: MOSTRAR O CONTEÚDO BRUTO SE FOR FRAGMENTO ---
        # Se tem IP, mas não tem TCP (porque foi cortado), mostramos os dados brutos
        if IP in pkt and TCP not in pkt and Raw in pkt:
            dados = pkt[Raw].load
            # Converte bytes para Hex para ficar bonito (ex: 00 a1 b2...)
            hex_data = " ".join(f"{b:02x}" for b in dados)
            print(f"   | [DADOS FRAGMENTADOS / FATIA TCP]:                        |")
            print(f"   | {Colors.YELLOW}{hex_data:<58}{Colors.RESET} |")
            print(f"   {Colors.BLUE}+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+{Colors.RESET}")

    elif modo == 'hex': imprimir_bytes_separados(pkt, 'hex')
    elif modo == 'bin': imprimir_bytes_separados(pkt, 'bin')

# ==============================================================================
#   3. UTILITÁRIOS (VALIDAÇÃO E PARSING)
# ==============================================================================

def validar_alvo(alvo_input):
    # 1. Validação Estrita de IP (x.x.x.x)
    try:
        ip_obj = ipaddress.IPv4Address(alvo_input)
        return str(ip_obj), alvo_input
    except ValueError:
        pass # Não é IP puro

    # 2. Rejeição de formatos inválidos (ex: 127001)
    if alvo_input.isdigit():
        print(f"\n{Colors.RED}[!] ERRO: Formato de IP inválido ('{alvo_input}'). Use x.x.x.x{Colors.RESET}")
        sys.exit(1)

    # 3. Resolução de DNS
    try:
        ip_resolvido = socket.gethostbyname(alvo_input)
        return ip_resolvido, alvo_input
    except socket.gaierror:
        print(f"\n{Colors.RED}[!] ERRO: Host não encontrado ('{alvo_input}').{Colors.RESET}")
        sys.exit(1)

def parse_portas(porta_str):
    if porta_str == "common":
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    try:
        if '-' in porta_str:
            inicio, fim = map(int, porta_str.split('-'))
            return list(range(inicio, fim + 1))
        elif ',' in porta_str:
            return list(map(int, porta_str.split(',')))
        else:
            p = int(porta_str)
            if p < 1 or p > 65535: raise ValueError
            return [p]
    except:
        print(f"\n{Colors.RED}[!] ERRO: Porta inválida (Use 80, 22-100 ou 80,443){Colors.RESET}")
        sys.exit(1)

def nome_servico(port):
    try: return socket.getservbyport(port, 'tcp')
    except: return "unknown"

# ==============================================================================
#   4. MAIN (EXECUÇÃO)
# ==============================================================================

def exibir_banner_ajuda():
    
    print(f"{Colors.BLUE}" + "="*65 + f"{Colors.RESET}")
    print(f"\n{Colors.BOLD}USO:{Colors.RESET} sudo python3 portscan.py <ALVO> [OPÇÕES]")
    print(f"\n{Colors.YELLOW}SCAN :{Colors.RESET}")
    print(f"  {Colors.BOLD}-sS{Colors.RESET} : SYN Scan")
    print(f"  {Colors.BOLD}-sF{Colors.RESET} : FIN Scan")
    print(f"  {Colors.BOLD}-sN{Colors.RESET} : NULL Scan")
    print(f"  {Colors.BOLD}-sP{Colors.RESET} : PSH Scan")
    print(f"\n{Colors.YELLOW} TÉCNICAS DE EVASÃO:{Colors.RESET}")
    print(f"  {Colors.BOLD}-f{Colors.RESET}    : Fragmentação ")
    print(f"  {Colors.BOLD}--pad{Colors.RESET} : Padding")
    print(f"  {Colors.BOLD}--http{Colors.RESET}: HTTP Injection")
    print(f"\n{Colors.YELLOW}VISUALIZAÇÃO:{Colors.RESET}")
    print(f"  {Colors.BOLD}-sV{Colors.RESET}         : Banner")
    print(f"  {Colors.BOLD}--view text{Colors.RESET} :Diagrama ")
    print(f"\n{Colors.BLUE}" + "-"*65 + f"{Colors.RESET}")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target", nargs='?')
    parser.add_argument("-p", "--ports", default="common")
    parser.add_argument("-sS", "--syn", action="store_true")
    parser.add_argument("-sN", "--null", action="store_true")
    parser.add_argument("-sF", "--fin", action="store_true")
    parser.add_argument("-sP", "--psh", action="store_true")
    parser.add_argument("-f", "--frag", action="store_true")
    parser.add_argument("--pad", action="store_true")
    parser.add_argument("--http", action="store_true")
    parser.add_argument("-sV", "--version", action="store_true")
    parser.add_argument("--view", choices=['text', 'hex', 'bin'])
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help or not args.target: exibir_banner_ajuda()

    ip_alvo, hostname = validar_alvo(args.target)
    portas = parse_portas(args.ports)
    
    if args.syn: mode, flags = "SYN", "S"
    elif args.fin: mode, flags = "FIN", "F"
    elif args.null: mode, flags = "Null", ""
    elif args.psh: mode, flags = "PSH", "P"
    else: mode, flags = "SYN", "S"

    print(f"\n{Colors.BOLD}Iniciando {mode} Scan em {hostname} ({ip_alvo}){Colors.RESET}")
    
    infos = []
    if args.frag: infos.append("Fragmentação")
    if args.http: infos.append("HTTP Injection")
    elif args.pad: infos.append("Padding")
    if args.view: infos.append(f"Visual: {args.view.upper()}")
    if infos: print(f"{Colors.BLUE}[*] Opções: {', '.join(infos)}{Colors.RESET}")

    resultados = []
    start_time = time.time()

    try:
        for port in portas:
            src_port = random.randint(1025, 65535)
            pkt = criar_pacote(ip_alvo, port, flags, args.pad, args.http, src_port)
            resp = enviar_pacote(pkt, args.frag, args.view)
            
            if args.frag: state = "unknown"
            else: state = analisar_resposta(resp, mode, ip_alvo, port, args.view, src_port)
            
            banner = ""
            if args.version and (state == "open" and mode == "SYN"):
                if args.view: print(f"{Colors.YELLOW}    [*] Tentando Banner Grab...{Colors.RESET}")
                banner = pegar_banner(ip_alvo, port)
                if not banner: banner = "Sem Banner"
            
            servico = nome_servico(port)
            resultados.append({"port": port, "state": state, "service": servico, "banner": banner})
            if args.view: print("-" * 50); time.sleep(0.5)

    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrompido pelo usuário. Saindo...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Erro Crítico: {e}{Colors.RESET}")
        sys.exit(1)

    print("\n" + "="*70)
    print(f"{'PORT':<10} {'STATE':<15} {'SERVICE':<15} {'BANNER'}")
    print("-" * 70)
    
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

if __name__ == "__main__":
    main()