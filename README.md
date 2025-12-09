
# Scapy Port Scanner

Este projeto consiste em um Scanner de Portas desenvolvido em Python utilizando a biblioteca **Scapy**. O objetivo principal da ferramenta é fins de estudo.

A ferramenta emula funcionalidades encontradas no NMAP.

## Funcionalidades

  * **Resolução de DNS Automática:** Aceita IP (ex: `45.33.32.156`) ou Hostname (ex: `scanme.nmap.org`).
  * **Múltiplos Tipos de Scan:**
      * **TCP SYN Scan:** Scan furtivo (padrão).
      * **UDP Scan:** Identificação de serviços UDP via erros ICMP.
      * **TCP ACK Scan:** Mapeamento de regras de Firewall.
      * **TCP Xmas Scan:** Scan baseado em violação de RFC (FIN, PSH, URG).


## Pré-requisitos

Para executar este scanner, é necessário ter o Python instalado e privilégios de **Administrador/Root**, pois o Scapy cria "Raw Sockets" (pacotes crus) que manipulam diretamente a placa de rede.

1.  **Python 3.x** instalado.
2.  Instalação da biblioteca Scapy:
    ```bash
    pip install scapy
    ```

##  Como Executar

Execute o script via terminal com privilégios elevados:

**Linux / macOS:**

```bash
sudo python3 portscan.py
```

**Windows (PowerShell/CMD como Administrador):**

```cmd
python portscan.py
```

-----

## Lógica dos Scans Implementados

Abaixo está a explicação técnica de como cada scan interpreta as respostas dos pacotes.

### 1\. TCP SYN Scan (Stealth / Half-Open)

Este é o método padrão de scan, pois é rápido e menos ruidoso nos logs do servidor.

  * **Envio:** Pacote TCP com flag **SYN**.
  * **Lógica:**
      * Se receber **SYN+ACK** → A porta está **ABERTA**. O script envia imediatamente um **RST** para derrubar a conexão antes que ela seja estabelecida (evitando log de aplicação).
      * Se receber **RST** → A porta está **FECHADA**.
      * Sem resposta (Timeout) → A porta está **FILTRADA** (provavelmente um firewall descartou o pacote).
        <img width="610" height="385" alt="image" src="https://github.com/user-attachments/assets/120fea55-9214-4d7b-9e1a-de9ceb342d89" />


### 2\. UDP Scan

Diferente do TCP, o UDP não possui confirmação de entrega (Stateless).

  * **Envio:** Pacote UDP vazio para a porta alvo.
  * **Lógica:**
      * Se receber **ICMP Destination Unreachable (Port Unreachable)** → A porta está **FECHADA**. O sistema operacional do alvo avisa que não há serviço ouvindo ali.
      * Sem resposta → A porta é considerada **ABERTA ou FILTRADA**. (Não há como distinguir com certeza sem envio de payload específico, pois o firewall pode ter bloqueado ou o serviço aceitou o pacote silenciosamente).
   
        
        <img width="606" height="381" alt="image" src="https://github.com/user-attachments/assets/1c410598-f9d2-45c3-98d0-2859d91e719b" />


### 3\. TCP ACK Scan

Este scan **não detecta portas abertas**. Ele serve para identificar a presença e o tipo de Firewall.

  * **Envio:** Pacote TCP com flag **ACK** (simulando uma conexão existente).
  * **Lógica:**
      * Se receber **RST** → O pacote passou pelo firewall e chegou ao alvo (Estado: **Não Filtrado**).
      * Sem resposta ou ICMP Unreachable → O firewall bloqueou o pacote (Estado: **Filtrado**).
        <img width="607" height="384" alt="image" src="https://github.com/user-attachments/assets/f4e51ac9-cbd0-40be-acf8-f3b0c15d379a" />


### 4\. TCP Xmas Scan

Utiliza uma combinação de flags incomum (FIN, PSH, URG) para testar a conformidade com a RFC do TCP.

  * **Envio:** Pacote com flags `FPU` acesas.
  * **Lógica:**
      * Se receber **RST** → A porta está **FECHADA**.
      * Sem resposta → A porta está **ABERTA ou FILTRADA**.
      * *Nota:* Este scan falha contra sistemas Windows, pois a Microsoft implementa a pilha TCP de forma a responder RST para qualquer pacote malformado, independentemente do estado da porta.
       <img width="607" height="388" alt="image" src="https://github.com/user-attachments/assets/6e930620-0b43-409f-a0d6-32cb553fcff3" />



-----

## Validação com Wireshark

Para validar o funcionamento do script, recomenda-se rodar o Wireshark em paralelo monitorando a interface de rede:

1.  Filtre pelo IP do alvo: `ip.addr == SEU_ALVO`.
2.  **Observação no SYN Scan:** Você verá o envio do **SYN**, o recebimento do **SYN, ACK** do alvo e o envio do **RST** pela sua máquina, comprovando o fechamento forçado da conexão.
3.  **Observação no UDP Scan:** Você verá o envio do UDP e o retorno de um erro **ICMP** indicando "Port Unreachable" para portas fechadas.
   <img width="1014" height="185" alt="image" src="https://github.com/user-attachments/assets/4c8f3bf8-9e5c-4dbc-891f-25b049dde8df" />


