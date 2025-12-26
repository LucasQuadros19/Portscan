#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>

// --- LISTA DAS TOP 20 PORTAS ---
int top_ports[] = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080};
int num_top_ports = 19;

// Variáveis Globais
volatile int stop_program = 0; // Usado APENAS para Ctrl+C ou fim total
char target_ip_global[32]; 
int global_socket = -1;

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum = 0;
    while(nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if(nbytes == 1) { oddbyte = 0; *((unsigned char*)&oddbyte) = *(unsigned char*)ptr; sum += oddbyte; }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return(answer);
}

// Tratamento de Ctrl+C
void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\n\n[!] Interrupção detectada (Ctrl+C). Encerrando...\n");
        stop_program = 1;
        if (global_socket > 0) close(global_socket);
        exit(0);
    }
}

void gerar_ip_randomico(char *buffer) {
    sprintf(buffer, "%d.%d.%d.%d", (rand()%220)+1, rand()%255, rand()%255, (rand()%254)+1);
}

// Resolve DNS
int hostname_to_ip(char *hostname, char *output_ip) {
    struct hostent *he;
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, hostname, &(sa.sin_addr)) != 0) {
        strcpy(output_ip, hostname);
        return 1;
    }
    printf("[*] Resolvendo DNS para '%s'...\n", hostname);
    if ((he = gethostbyname(hostname)) == NULL) return 0;
    strcpy(output_ip, inet_ntoa(*(struct in_addr*)he->h_addr_list[0]));
    return 1;
}

// IP Local Automático
int obter_ip_local_automatico(char *buffer_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);
    if (connect(sock, (const struct sockaddr*) &serv, sizeof(serv)) < 0) { close(sock); return -1; }
    struct sockaddr_in nome_local;
    socklen_t namelen = sizeof(nome_local);
    if (getsockname(sock, (struct sockaddr*) &nome_local, &namelen) < 0) { close(sock); return -1; }
    inet_ntop(AF_INET, &nome_local.sin_addr, buffer_ip, 32);
    close(sock);
    return 0;
}

// --- SNIFFER THREAD (Ouvido) ---
void *sniffer_thread(void *arg) {
    int sock_raw;
    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    unsigned char *buffer = (unsigned char *)malloc(65536);

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock_raw < 0) {
        perror("Erro Sniffer Socket");
        return NULL;
    }

    // O loop continua até o programa inteiro acabar. 
    // NÃO PARA quando acha uma porta, para poder achar as próximas.
    while(!stop_program) {
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
        if(data_size < 0) continue;

        struct iphdr *iph = (struct iphdr*)buffer;
        unsigned short iphdrlen = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen);

        struct sockaddr_in source;
        source.sin_addr.s_addr = iph->saddr;

        // Filtra: Veio do Alvo?
        if (strcmp(inet_ntoa(source.sin_addr), target_ip_global) == 0) {
            // É SYN-ACK? (Porta Aberta)
            if (tcph->syn == 1 && tcph->ack == 1) {
                printf("\n\033[1;32m[!!!] SUCESSO! Porta %d ABERTA! \033[0m\n", ntohs(tcph->source));
            }
        }
    }
    close(sock_raw);
    free(buffer);
    return NULL;
}

// --- FUNÇÃO DE ENVIO DECOY PARA UMA PORTA ---
void scan_port_decoy(int target_port, int num_decoys, char *my_ip, int sock) {
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct pseudo_header psh;
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip_global);

    int total_packets = num_decoys + 1;
    int real_packet_index = rand() % total_packets;

    fflush(stdout); 

    for (int i = 0; i < total_packets; i++) {
        if (stop_program) return; // Sai se Ctrl+C

        char current_source_ip[32];
        if (i == real_packet_index) {
            strcpy(current_source_ip, my_ip);
        } else {
            gerar_ip_randomico(current_source_ip);
        }

        memset(datagram, 0, 4096);

        // IP Header
        iph->ihl = 5; iph->version = 4; iph->tos = 0;
        iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
        iph->id = htonl(54321 + i); iph->frag_off = 0; iph->ttl = 255;
        iph->protocol = IPPROTO_TCP; iph->check = 0;
        iph->saddr = inet_addr(current_source_ip);
        iph->daddr = inet_addr(target_ip_global);
        iph->check = csum((unsigned short *) datagram, iph->ihl << 2);

        // TCP Header
        tcph->source = htons(40000 + (rand() % 10000));
        tcph->dest = htons(target_port);
        tcph->seq = 0; tcph->ack_seq = 0;
        tcph->doff = 5; tcph->fin = 0; tcph->syn = 1; 
        tcph->rst = 0; tcph->psh = 0; tcph->ack = 0; 
        tcph->urg = 0; tcph->window = htons(5840); 
        tcph->check = 0; tcph->urg_ptr = 0;

        // Checksum
        psh.source_address = inet_addr(current_source_ip);
        psh.dest_address = inet_addr(target_ip_global);
        psh.placeholder = 0; psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram , (char*) &psh , sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
        tcph->check = csum((unsigned short*) pseudogram , psize);
        free(pseudogram);

        if (sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *) &dest, sizeof(dest)) < 0) {
            // Silencioso
        }
        usleep(1500); // Pequeno delay entre iscas
    }
    printf("Enviado.\n");
    // Removi o "stop_program = 1" daqui, para ele poder ir para a próxima porta!
}

// --- MAIN ---
int main(void) {
    signal(SIGINT, handle_signal);
    srand(time(NULL));

    char my_real_ip[32];
    char target_input[100];
    int num_decoys, mode;
    int p_start, p_end;
    pthread_t sniffer_id;

    printf("\n=== FINAL DECOY SCANNER (MULTI-PORT + DNS) ===\n");
    
    // 1. Alvo
    printf("Alvo (IP ou Hostname): ");
    scanf("%99s", target_input);
    if (!hostname_to_ip(target_input, target_ip_global)) {
        printf("Erro Fatal DNS.\n"); return 1;
    }
    printf("[*] Alvo Resolvido: %s\n", target_ip_global);

    // 2. IP Local
    if (obter_ip_local_automatico(my_real_ip) != 0) {
        printf("IP Local: "); scanf("%31s", my_real_ip);
    } else {
        printf("[*] IP Local: %s\n", my_real_ip);
    }

    // 3. Iscas
    printf("Decoys por porta: ");
    scanf("%d", &num_decoys);

    // 4. MENU
    printf("\n--- MODO DE SCAN ---\n");
    printf("1. Porta Unica\n");
    printf("2. Intervalo (Range)\n");
    printf("3. Top 20 Portas\n");
    printf("Opcao: ");
    scanf("%d", &mode);

    // Iniciar Sniffer
    printf("\n[*] Iniciando Sniffer...\n");
    pthread_create(&sniffer_id, NULL, sniffer_thread, NULL);

    // Raw Socket
    global_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(global_socket < 0) { perror("Erro Socket (sudo?)"); return 1; }
    int one = 1;
    setsockopt(global_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // LÓGICA DO MENU
    switch(mode) {
        case 1:
            printf("Porta: "); scanf("%d", &p_start);
            scan_port_decoy(p_start, num_decoys, my_real_ip, global_socket);
            break;
        case 2:
            printf("Inicio: "); scanf("%d", &p_start);
            printf("Fim: "); scanf("%d", &p_end);
            for(int p = p_start; p <= p_end; p++) {
                if(stop_program) break;
                scan_port_decoy(p, num_decoys, my_real_ip, global_socket);
            }
            break;
        case 3:
            printf("[*] Scaneando Top 20 Portas...\n");
            for(int i = 0; i < num_top_ports; i++) {
                if(stop_program) break;
                scan_port_decoy(top_ports[i], num_decoys, my_real_ip, global_socket);
            }
            break;
        default:
            printf("Opcao invalida.\n");
    }

    printf("\n[+] Scan Finalizado. Aguardando ultimas respostas (3s)...\n");
    sleep(3);
    stop_program = 1; // Agora sim paramos o sniffer
    close(global_socket);
    return 0;
}