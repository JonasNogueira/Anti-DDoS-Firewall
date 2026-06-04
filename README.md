# Anti-DDoS-Firewall

Este submódulo/branch implementa um **Firewall Anti-DDoS** operando na camada mais baixa do subsistema de rede do Linux (XDP - eXpress Data Path). O sistema é capaz de mitigar ataques volumétricos (Inundação/Flood TCP SYN) direto no Kernel Space, poupando a pilha IP e os recursos de CPU do sistema operacional.

## Requisitos da Lógica Implementada

- **Rate-Limiting por IP de Origem:** Janela de monitoramento de 1 segundo (`WINDOW_NS`).
- **Limite de Tráfego (X):** Máximo de 10 pacotes por segundo (`PPS_LIMIT`).
- **Lista de Bloqueio/Banimento Temporário (N):** Se o IP exceder o limite, ele é colocado em "castigo" por **10 segundos** (`BAN_TIME_NS`), tendo todos os seus pacotes descartados instantaneamente via `XDP_DROP`.

---

## Como Compilar e Rodar 

Abra o terminal do seu Ubuntu (Kernel 5.15+ exigido) na raiz do projeto e siga as instruções abaixo divididas por abas.

### Aba 1: Compilação e Injeção no Kernel
Nesta aba, vamos compilar o código fonte usando o Clang com suporte a CO-RE (`vmlinux.h`) e injetá-lo na interface de loopback (`lo`).

```bash
# 1. Remova binários antigos para evitar conflitos de cache
rm -f firewall_ratelimit.o

# 2. Compile o programa eBPF gerando as tabelas de símbolos BTF (-g)
clang -O2 -g -target bpf -c firewall_ratelimit.c -o firewall_ratelimit.o

# 3. Limpe qualquer instância ou arquivo de persistência anterior do BPF
sudo bpftool net detach xdp dev lo
sudo rm -f /sys/fs/bpf/firewall

# 4. Carregue o novo binário e fixe-o no sistema de arquivos virtual do BPF
sudo bpftool prog load firewall_ratelimit.o /sys/fs/bpf/firewall type xdp

# 5. Anexe o firewall oficialmente à interface de loopback (lo)
sudo bpftool net attach xdp pinned /sys/fs/bpf/firewall dev lo
```
Para verificar se o programa foi acoplado com sucesso, execute:

```bash
sudo bpftool net list
```

Você deverá ver uma linha indicando lo associada a um programa xdp generic.

### Aba 2: Monitoramento de Logs

Abra uma segunda aba/terminal para escutar o buffer de rastreamento do Kernel. Deixe essa tela aberta; ela exibirá o exato momento em que o atacante for banido.

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

### Aba 3: Simulação do Ataque e Validação

Abra uma terceira aba/terminal para testar a resiliência do firewall.
1. Teste de Tráfego Legítimo 

Execute um ping comum. O tráfego deve passar normalmente (XDP_PASS):

```bash
ping -c 4 127.0.0.1
```

2. Disparo do Ataque DDoS

Use o hping3 para simular uma inundação de pacotes TCP SYN estruturada na velocidade máxima do processador. Deixe rodar por apenas 2 a 3 segundos e pare o comando usando Ctrl + C:

```
sudo hping3 -S --flood 127.0.0.1
```

3. Validação da Lista de Bloqueio (Banimento por N Segundos)

Imediatamente após fechar o hping3, tente efetuar o ping novamente:

```bash
ping 127.0.0.1
```

Comportamento esperado:

Na Aba 2 (Logs), você verá o alerta disparado pelo kernel: IP BANIDO POR 10 SEGUNDOS: 127.0.0.1 (PPS: 11).

Na Aba 3 (Ataque), o comando ping ficará completamente congelado (100% de perda de pacotes ou menos pelo tempo curto de banimento, porém não será 0%), provando que o firewall colocou o localhost na lista de bloqueio. After exatamente 10 segundos do início do banimento, o ping voltará a responder sozinho.

### Como Desativar e Limpar o Sistema

Quando encerrar as validações, desfaça as alterações na placa de rede limpando a memória do kernel:

```bash
sudo bpftool net detach xdp dev lo
sudo rm -f /sys/fs/bpf/firewall
```

