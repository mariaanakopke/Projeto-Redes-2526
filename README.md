# Packet Sniffer Passivo — TP2 de Redes de Computadores

Universidade do Minho | Licenciatura em Engenharia Informatica | 2025/2026

---

## Visao Geral

Sniffer de rede puramente passivo desenvolvido em Python com Scapy. O sistema captura e analisa trafego de rede sem qualquer forma de injecao de pacotes, modificacao de fluxo ou intercetacao activa (sem MITM). Funciona exclusivamente em modo de leitura: recebe copias dos frames que passam na interface e processa-as localmente.

O sniffer cobre extracoes de L2 a L7, com tracking stateful de fases de protocolo (handshakes, ciclos de resolucao, sequencias de atribuicao de enderecamento). E compativel com execucao em interfaces fisicas reais e em topologias emuladas via CORE Network Emulator, correndo no end-host com permissoes de root.

**Restricoes de operacao:**

- Requer `root` / `sudo` para acesso a raw sockets.
- Captura estritamente E2E: analisa o trafego visivel no end-host onde e executado.
- Nao modifica, nao reencaminha e nao gera pacotes.

---

## Arquitectura — Separacao de Responsabilidades

O codigo e organizado em seis modulos com responsabilidades mutuamente exclusivas. Nenhum modulo toma decisoes que pertencem a outro.

```
main.py
  |
  +-- FilterManager (filters.py)     decisao de DROP — BPF + Python
  |
  +-- CaptureEngine (capture.py)     motor: recebe pacotes, coordena pipeline
        |
        +-- PacketParser (parser_proto.py)   extracao L2-L7 -> dict plano
        |
        +-- FilterManager.match()            drop ou aceitar
        |
        +-- Logger (logger.py)               escrita para disco (txt/csv/jsonl)
        |
        +-- ProtocolAnalyzer (analyzer.py)   tracking stateful (so pacotes aceites)
```

| Modulo | Responsabilidade unica |
|---|---|
| `capture.py` | Motor de captura. Coordena o pipeline parse -> filter -> display -> log -> analyze. Nao toma decisoes de protocolo. |
| `parser_proto.py` | Transforma um pacote Scapy num dicionario plano com todos os campos de L2 a L7. Nao filtra, nao rastreia estado. |
| `filters.py` | Unico ponto de decisao de DROP. Dado um `dict` parsed, retorna `True` (aceitar) ou `False` (descartar). Nao emite eventos, nao altera estado. |
| `analyzer.py` | Recebe apenas pacotes ja aceites pelo filtro. Mantem maquinas de estado e emite eventos de protocolo. Nao toca em pacotes raw. |
| `logger.py` | Serializa o `dict` parsed para disco no formato pedido. Nao filtra, nao rastreia, nao imprime para o terminal. |

Esta separacao garante que o `ProtocolAnalyzer` nunca ve pacotes que o `FilterManager` rejeitou, e que o `FilterManager` nunca acede a estado de sessao — as duas responsabilidades nao se misturam em nenhum ponto do codigo.

---

## Funcionalidades e Tracking

### Extracao de Campos (L2 a L7)

O `PacketParser` produz um dicionario plano com os seguintes campos garantidos para cada pacote:

**Camada 2**

| Campo | Descricao |
|---|---|
| `src_mac`, `dst_mac` | Enderecos MAC de origem e destino (Ethernet ou 802.11) |
| `proto` | Protocolo identificado: `ARP`, `IPv4`, `IPv6`, `TCP`, `UDP`, `ICMP`, `ICMPV6`, `HTTP`, `DNS`, `DHCP` |

Suporte a frames Ethernet (IEEE 802.3) e frames Wi-Fi em modo monitor (IEEE 802.11), com extraccao de `addr1`/`addr2` para MAC destino/origem. Importacao de Scapy guarda com `try/except` para ambientes sem `scapy.layers.dot11`.

**Camada 3**

| Campo | Descricao |
|---|---|
| `src_ip`, `dst_ip` | Enderecos IPv4 ou IPv6 |
| `ttl` | TTL (IPv4) ou Hop Limit (IPv6) |
| `frag_id`, `frag_offset`, `frag_mf`, `frag_df` | Campos de fragmentacao IPv4 e IPv6 (via `IPv6ExtHdrFragment`) |

**Camada 4**

| Campo | Descricao |
|---|---|
| `src_port`, `dst_port` | Portos de origem e destino |
| `flags` | Flags TCP decodificadas: `SYN`, `ACK`, `SYN+ACK`, `FIN`, `RST`, `PSH`, etc. |
| `tcp_seq`, `tcp_ack` | Numeros de sequencia e acknowledgment |
| `tcp_window` | Janela deslizante (valor raw; escala via `tcp_options["WScale"]`) |
| `tcp_options` | Dicionario com `MSS`, `WScale`, `SACK_Permitted`, `SACK_Blocks`, `TS_val`, `TS_ecr` |
| `icmp_type`, `icmp_code`, `icmp_id`, `icmp_seq` | Campos ICMP (Echo Request/Reply, Dest Unreach, Time Exceeded) e ICMPv6 (tipos 128/129) |

**Camada 5 — Aplicacao**

| Campo | Descricao |
|---|---|
| `dns_id`, `dns_qr`, `dns_rcode`, `dns_name`, `dns_qtype` | Transaccao DNS (Query/Response, NOERROR/NXDOMAIN/SERVFAIL) |
| `dhcp_xid`, `dhcp_msg_type`, `dhcp_yiaddr`, `dhcp_chaddr`, `dhcp_siaddr` | Ciclo DHCP (xid de emparelhamento, tipo de mensagem, IP oferecido, MAC do cliente) |
| `payload_size` | Bytes de dados acima de L4 (`Raw` layer), distinto do tamanho total do frame |
| `summary` | String legivel com informacao principal do pacote |

---

### Tracking Stateful de Fases de Protocolo

O `ProtocolAnalyzer` opera sobre pacotes aceites e mantem o estado das sessoes activas.

#### Maquina de Estados TCP (`TCPState`)

Cada fluxo e identificado pelo par canonico `(client_ip:port, server_ip:port)`. O papel de cliente (iniciador do SYN) e o papel de servidor sao fixados na criacao do fluxo e verificados em cada transicao — um `SYN+ACK` so e aceite se vier do servidor, e o `ACK` de conclusao do handshake so e aceite se vier do cliente.

```
CLOSED -> [SYN do cliente]      -> SYN_SENT
SYN_SENT -> [SYN+ACK do servidor] -> SYN_RECEIVED
SYN_RECEIVED -> [ACK do cliente] -> ESTABLISHED
ESTABLISHED -> [FIN]             -> FIN_WAIT
FIN_WAIT -> [FIN+ACK]            -> CLOSED (FIN)
Qualquer estado -> [RST]         -> CLOSED
```

Durante a fase `ESTABLISHED`, o tracker estima bytes transferidos em cada direccao por progressao dos numeros de ACK (`bytes_client_to_server`, `bytes_server_to_client`), com guarda contra wrap do espaco de sequencia (limite de 1 GB por delta).

O evento de `FIN` reporta o total de bytes estimados transferidos em ambas as direccoes antes da terminacao.

#### Ciclos Locais — ARP e ICMP

**ARP:** cada `Request` e registado por IP destino. O `Reply` correspondente e emparelhado e a entrada e removida da tabela de pendentes. A tabela ARP observada e reportada no sumario final.

**ICMP / ICMPv6:** pares Echo Request / Echo Reply sao emparelhados por `(src_ip, dst_ip, icmp_id)`. O campo `icmp_id` distingue sessoes de ping simultaneas do mesmo host, eliminando colisoes que ocorriam com chaves baseadas apenas em IPs. ICMPv6 usa os mesmos campos com tipos 128 (Request) e 129 (Reply); o espaco de enderecos IPv6 garante que nao ha colisao com sessoes ICMPv4.

#### Fragmentacao IP — Timeout e Reassembly

O `FragmentTracker` agrupa fragmentos pelo campo `Identification` (IPv4) ou `id` do `IPv6ExtHdrFragment`. Deteta a chegada do fragmento final (`MF=0`) e reporta o datagrama completo com o numero de fragmentos e tamanho total estimado.

Fragments sets que nao recebem o fragmento final dentro de `30` segundos (configuravel em `FragmentTracker(timeout_sec=...)`) sao descartados pelo garbage collector `_gc()`, que e invocado em cada nova chegada de fragmento. O evento de GC e impresso com o numero de fragmentos recebidos e o tempo decorrido.

#### Tracking L5 — DNS, DHCP, HTTP

**DNSTracker:** emparelha Query e Response pelo campo `dns_id` (Transaction ID). Uma Query sem Response correspondente permanece em pendentes ate ser limpa manualmente ou por reinicio. O rcode da Response (`NOERROR`, `SERVFAIL`, `NXDOMAIN`) e reportado no evento de emparelhamento.

**DHCPTracker:** segue as quatro fases do ciclo DORA (`Discover -> Offer -> Request -> ACK`) pelo campo `dhcp_xid` (BOOTP Transaction ID). Cada fase e reportada individualmente. A conclusao do ciclo ACK reporta o IP atribuido e a sequencia completa. Respostas `NAK` fecham a sessao com reporte de recusa.

**HTTPTracker:** emparelha Requests e Responses por `(client_ip, server_ip, client_port)`. Requests sao identificados pelo porto de destino 80 e pelo metodo HTTP presente no resumo. A Response correspondente e identificada pelo porto de origem 80 e pelo porto de destino que coincide com o porto efemero do Request.

---

## Filtros Avancados

### Dupla Camada de Filtragem

O sistema usa dois mecanismos de filtragem em serie:

1. **BPF (Berkeley Packet Filter)** — aplicado pelo kernel antes da copia para user-space. Reduz o numero de chamadas de sistema e o volume de dados processados pelo Python. Gerado automaticamente pelo `FilterManager.to_bpf()`.

2. **Filtro Python** — aplicado pelo `FilterManager.match()` sobre o `dict` parsed. Cobre casos que o BPF nao suporta (logica de estado, exclusao de sub-protocolos, expansao de grupos).

Os dois mecanismos sao equivalentes logicamente: qualquer pacote que o BPF deixa passar e que o filtro Python rejeita e descartado antes de chegar ao `ProtocolAnalyzer`. Nenhum pacote rejeitado pelo filtro chega ao tracker.

### Anti-Leakage por Grupos de Protocolo

O filtro conhece a relacao de continencia entre protocolos:

```
TCP  =>  {TCP, HTTP}
UDP  =>  {UDP, DNS, DHCP}
```

`--exclude-proto TCP` descarta tambem pacotes com `proto=HTTP` (que sao TCP no porto 80). `--proto UDP` aceita DNS e DHCP. Esta expansao e aplicada identicamente no filtro Python e na geracao do BPF, eliminando leakage entre camadas.

A invariante `accepted + dropped == total` e verificada por `assert` no `print_stats()` de cada sessao.

### Argumentos de Filtragem

| Argumento | Descricao |
|---|---|
| `--ip <addr>` | Aceitar apenas pacotes com este IP como origem ou destino |
| `--mac <addr>` | Aceitar apenas pacotes com este MAC como origem ou destino |
| `--proto <P>` | Aceitar apenas pacotes do protocolo P. Valores: `ARP`, `ICMP`, `ICMPV6`, `TCP`, `UDP`, `IPv4`, `IPv6`, `HTTP`, `DNS`, `DHCP` |
| `--port <n>` | Aceitar apenas pacotes com este porto como origem ou destino |
| `--exclude-ip <addr>` | Descartar todos os pacotes com este IP (inclusao e exclusao nao se misturam; exclusao tem prioridade absoluta) |
| `--exclude-proto <P>` | Descartar todos os pacotes do protocolo P (com expansao de grupo) |

Filtros de exclusao tem prioridade absoluta sobre filtros de inclusao. Se um pacote satisfaz um criterio de exclusao, e descartado independentemente de satisfazer criterios de inclusao.

Combinacoes contraditórias (ex: `--proto TCP --exclude-proto TCP`) sao detectadas na inicializacao e reportadas com aviso.

---

## Modos de Operacao e Logs

### Modo Live (consola)

Cada pacote aceite e impresso numa linha com cor semantica por protocolo:

```
No.    Time           Source               Destination          Protocol TTL   Length   Info
------------------------------------------------------------------------------------------------------
1      14:32:01.123   192.168.1.10         8.8.8.8              DNS      64    73B      [REQUEST] Query A example.com (id=4521)
       |_ txid=4521 NOERROR
2      14:32:01.187   8.8.8.8              192.168.1.10         DNS      118   105B     [REPLY] Response NOERROR (2 rr) id=4521
3      14:32:01.200   192.168.1.10         93.184.216.34        TCP      64    60B      [TCP REQUEST - SYN] seq=0 ack=0 win=65535
       |_ seq=100 ack=0 win=65535 MSS=1460 SACK
```

Cores por protocolo: ARP (amarelo), ICMP/ICMPv6 (ciano), TCP (verde), UDP (azul), HTTP (magenta), DNS (vermelho), DHCP (branco).

Tags semanticas `[REQUEST]` e `[REPLY]` sao injectadas visualmente no campo Info para ARP, ICMP, DNS, DHCP, HTTP e fases do handshake TCP.

A linha secundaria (`|_`) exibe campos criticos quando presentes: `seq/ack/win` para TCP, `frag_id/offset` para fragmentos, `icmp_id/seq` para ICMP, `txid/rcode` para DNS, `xid/type` para DHCP.

### Modo Log (ficheiro)

Activado com `--log <formato>` em simultaneo com a consola. Os tres formatos partilham o mesmo schema de campos.

**`--log txt`** — ficheiro legivel com cabecalho e linha secundaria de campos criticos. Identico ao output de consola sem cores ANSI.

**`--log csv`** — ficheiro CSV com cabecalho de colunas. Todas as colunas do schema estao presentes em todos os registos (celulas vazias para campos nao aplicaveis ao protocolo). Adequado para importacao em folhas de calculo ou ferramentas de analise.

**`--log json`** — ficheiro JSONL (JSON Lines). Cada linha e um objecto JSON completo, escrito e `flush()`-ado imediatamente apos cada pacote aceite. Um objecto de cabecalho com metadados (`_type`, `started`, `format`, `fields`) e escrito na abertura do ficheiro. A escrita incremental garante que um crash ou interrupcao forcada (`SIGKILL`) nao resulta em perda de dados: o ficheiro e valido ate ao ultimo pacote registado antes da interrupcao.

O mesmo comportamento de flush imediato aplica-se aos formatos `txt` e `csv`.

O nome base do ficheiro de saida e configuravel com `--output <nome>` (padrao: `captura`). A extensao e adicionada automaticamente (`.txt`, `.csv`, `.jsonl`).

---

## Exemplos de Utilizacao

**Listar interfaces disponiveis com IP e MAC:**

```bash
sudo python3 main.py --list-ifaces
```

**Captura live em eth0, todos os protocolos, modo consola:**

```bash
sudo python3 main.py -i eth0
```

**Captura de trafego TCP com analise stateful de handshakes e exportacao CSV:**

```bash
sudo python3 main.py -i eth0 --proto TCP --analyze --log csv --output sessao_tcp
```

Produz `sessao_tcp.csv` com todos os campos TCP (seq, ack, window, flags, options) e imprime eventos de handshake, progressao de dados e terminacao na consola.

**Filtrar por host especifico, excluir trafego TCP, exportar JSONL:**

```bash
sudo python3 main.py -i eth0 --ip 10.0.0.5 --exclude-proto TCP --log json --output host5_udp
```

Aceita apenas pacotes envolvendo `10.0.0.5` e descarta todos os que sejam TCP ou HTTP (expansao de grupo automatica). O ficheiro `host5_udp.jsonl` e resistente a crash por flush incremental.

**Analise offline de ficheiro pcap com tracking completo de todas as sessoes:**

```bash
sudo python3 main.py --pcap captura.pcap --analyze --log csv --output analise
```

Os timestamps no modo pcap correspondem ao tempo original de captura dos pacotes (campo `pkt.time`), nao ao momento de leitura.

**Captura limitada a 100 pacotes DNS com analise de pares Query/Response:**

```bash
sudo python3 main.py -i eth0 --proto DNS --analyze -n 100
```

**Captura em interface Wi-Fi com filtro por porto e exportacao de log em texto:**

```bash
sudo python3 main.py -i wlan0 --port 443 --log txt --output https_wlan
```

---

## Dependencias

```
python3 >= 3.9
scapy >= 2.5.0
```

Instalacao:

```bash
pip install scapy
```

Para captura em interfaces fisicas e emuladas (CORE) e necessario executar com `root`. Em ambientes sem suporte a `scapy.layers.dot11` (ex: sem `libpcap` compilado com suporte a monitor mode), o parser degrada graciosamente: a importacao e guarda com `try/except` e o campo `src_mac`/`dst_mac` e extraido de Ethernet quando disponivel.

---

## Limitacoes e Exclusoes Documentadas

O sniffer e executado no end-host para analisar estritamente trafego E2E visivel nesse no. Nao captura trafego entre outros hosts numa rede comutada a menos que a interface esteja em modo promiscuo ou monitor.

Os protocolos UDP (DNS e DHCP) sao lidos e parseados com extraccao completa de campos para os logs. O `ProtocolAnalyzer` inclui trackers de emparelhamento (DNSTracker, DHCPTracker) para correlacao de ciclos completos, mas estes trackers nao influenciam decisoes de filtragem. A prioridade de robustez de estado foi atribuida ao ciclo TCP (maquina de estados completa e direccional) e aos ciclos locais ARP/ICMP (emparelhamento por identificador de sessao).

TLS/HTTPS e detetado por porto (443) mas o conteudo nao e decifrado. O campo `payload_size` reflecte o tamanho do segmento cifrado.

O `HTTPTracker` e o `DNSTracker` nao implementam GC de pedidos pendentes sem resposta — sessoes sem Response ficam em memoria ate ao fim da captura. Em capturas longas com elevado volume de DNS ou HTTP, este comportamento deve ser considerado.

---

## Estrutura de Ficheiros

```
.
+-- main.py           ponto de entrada, parse de argumentos CLI
+-- capture.py        motor de captura (live e pcap)
+-- filters.py        decisao de drop (BPF + filtro Python)
+-- parser_proto.py   extracao de campos L2-L7
+-- analyzer.py       tracking stateful de sessoes e fases
+-- logger.py         escrita para disco (txt / csv / jsonl)
```
