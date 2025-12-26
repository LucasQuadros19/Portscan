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

// --- VARIÁVEIS GLOBAIS ---
volatile int stop_sniffer = 0;
char target_ip_global[32]; 
int global_socket = -1;

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Checksum (Padrão)
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

void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\n[!] Encerrando...\n");
        exit(0);
    }
}

// Resolve DNS para IP
int hostname_to_ip(char *hostname, char *output_ip) {
    struct hostent *he;
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, hostname, &(sa.sin_addr)) != 0) {
        strcpy(output_ip, hostname);
        return 1;
    }
    if ((he = gethostbyname(hostname)) == NULL) return 0;
    strcpy(output_ip, inet_ntoa(*(struct in_addr*)he->h_addr_list[0]));
    return 1;
}

// Pega IP Local automaticamente
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

// --- SNIFFER THREAD ---
void *sniffer_thread(void *arg) {
    int sock_raw;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    if(sock_raw < 0) return NULL;

    while(!stop_sniffer) {
        struct sockaddr saddr;
        int saddr_size = sizeof(saddr);
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
        if(data_size < 0) continue;

        struct iphdr *iph = (struct iphdr*)buffer;
        unsigned short iphdrlen = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen);

        struct sockaddr_in source;
        source.sin_addr.s_addr = iph->saddr;

        if (strcmp(inet_ntoa(source.sin_addr), target_ip_global) == 0) {
            if (tcph->syn == 1 && tcph->ack == 1) {
                printf("\n\033[1;32m[!!!] SUCESSO! Porta %d ABERTA (Bypass funcionou!) \033[0m\n", ntohs(tcph->source));
            }
        }
    }
    close(sock_raw);
    free(buffer);
    return NULL;
}

int main(void) {
    signal(SIGINT, handle_signal);
    srand(time(NULL));

    char my_real_ip[32];
    char target_input[100];
    int target_port;
    int spoofed_port; // A porta "Mágica" para o bypass
    pthread_t sniffer_id;

    printf("\n=== SOURCE PORT MANIPULATION SCANNER (-g) ===\n");
    
    // 1. Configurações
    printf("Alvo (IP/Domain): ");
    scanf("%99s", target_input);
    if (!hostname_to_ip(target_input, target_ip_global)) {
        printf("Erro DNS.\n"); return 1;
    }
    printf("Porta Alvo (ex: 80): ");
    scanf("%d", &target_port);

    // 2. A TÉCNICA DE BYPASS
    printf("Porta de ORIGEM para forcar (ex: 53 para DNS, 20 para FTP): ");
    scanf("%d", &spoofed_port);

    if (obter_ip_local_automatico(my_real_ip) != 0) {
        printf("Digite seu IP Local: "); scanf("%31s", my_real_ip);
    }

    // Inicia Sniffer
    printf("[*] Ouvindo respostas...\n");
    pthread_create(&sniffer_id, NULL, sniffer_thread, NULL);

    // Socket Raw
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s < 0) { perror("Erro socket (sudo?)"); return 1; }
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // Preparação do Pacote
    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
    struct pseudo_header psh;
    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(target_port);
    dest.sin_addr.s_addr = inet_addr(target_ip_global);

    printf("[+] Enviando pacote camuflado: %s:%d -> %s:%d\n", 
           my_real_ip, spoofed_port, target_ip_global, target_port);

    // -- CONSTRUÇÃO DO PACOTE --

    // IP Header
    iph->ihl = 5; iph->version = 4; iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htonl(54321); iph->frag_off = 0; iph->ttl = 255;
    iph->protocol = IPPROTO_TCP; iph->check = 0;
    iph->saddr = inet_addr(my_real_ip); // Aqui usamos SEU IP REAL (não é decoy)
    iph->daddr = inet_addr(target_ip_global);
    iph->check = csum((unsigned short *) datagram, iph->ihl << 2);

    // TCP Header (A MÁGICA ACONTECE AQUI)
    tcph->source = htons(spoofed_port); // <--- FORÇAMOS A PORTA ESCOLHIDA
    tcph->dest = htons(target_port);
    tcph->seq = 0; tcph->ack_seq = 0;
    tcph->doff = 5; tcph->fin = 0; tcph->syn = 1; 
    tcph->rst = 0; tcph->psh = 0; tcph->ack = 0; 
    tcph->urg = 0; tcph->window = htons(5840); 
    tcph->check = 0; tcph->urg_ptr = 0;

    // Checksum TCP
    psh.source_address = inet_addr(my_real_ip);
    psh.dest_address = inet_addr(target_ip_global);
    psh.placeholder = 0; psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram , (char*) &psh , sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
    tcph->check = csum((unsigned short*) pseudogram , psize);
    free(pseudogram);

    // Envio
    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &dest, sizeof(dest)) < 0) {
        perror("Erro envio");
    } else {
        printf("[+] Pacote enviado com sucesso.\n");
    }

    // Aguarda um pouco por resposta
    sleep(2);
    stop_sniffer = 1;
    close(s);
    return 0;
}