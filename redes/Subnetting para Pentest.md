# 🌐 Subnetting: Entendendo CIDR, Máscara e Hosts com Comandos Ubuntu

## 1. Objetivo

Entender na prática como funcionam **endereços IP**, **máscaras de sub-rede** e **notação CIDR** usando comandos reais do Ubuntu. Ao final, você saberá interpretar rapidamente o tamanho de uma rede e planejar varreduras eficientes para pentest.

---

## 2. Ambiente

- **SO:** Ubuntu 22.04 LTS (ou qualquer versão)
- **Ferramentas:** Terminal padrão, `ipcalc`, `ifconfig`, `ip`
- **Instalação:** `sudo apt update && sudo apt install ipcalc`

---

## 3. Passo a Passo

### **A. Conceito Básico: Rede vs Host**

Um endereço IP tem **duas partes**:
- **Rede (Network):** identifica o segmento (como um condomínio)
- **Host:** identifica cada dispositivo (como uma casa)

**Exemplo:**
```
192.168.1.10
192.168.1 = Rede (condomínio)
10        = Host (casa dentro do condomínio)
```

Todos os dispositivos no mesmo condomínio compartilham o início:
```
192.168.1.5
192.168.1.10
192.168.1.100
192.168.1.200
```

**Visualize sua rede atual:**
```bash
$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>
      inet 192.168.X.X  netmask 255.255.255.0  broadcast 192.168.X.255
```
<img width="797" height="524" alt="image" src="https://github.com/user-attachments/assets/48094775-0620-4512-9044-813d04ac1e70" />

Aqui `192.168.X.0` é a **rede** e a máscara `255.255.255.0` define a divisão.

---

### **B. Máscara de Sub-rede: O Divisor**

A máscara diz ao computador **onde termina a rede e começa o host**.

**Exemplo:**
```
IP:      192.168.1.10
Máscara: 255.255.255.0

192   .  168   .  1   .  10
255   .  255   .  255  .  0
───────────────────────────
REDE    REDE    REDE    HOST
```

**Como funciona:**
- `255` em binário = `11111111` (todos os bits são **rede**)
- `0` em binário = `00000000` (todos os bits são **host**)

**Na prática:**
```bash
$ ip addr show
2: eth0: <BROADCAST,RUNNING,MULTICAST> mtu 1500
    inet 192.168.X.X/24 brd 192.168.X.255 scope global eth0
```
<img width="993" height="440" alt="image" src="https://github.com/user-attachments/assets/e14d7d8e-d0dc-453b-8a18-9f838523f8fd" />

O `/24` significa: **24 bits de rede, 8 bits de host** (equivalente a `255.255.255.0`)

---

### **C. CIDR: Notação Rápida**

Em vez de escrever `255.255.255.0`, usamos `/24`.

**Por quê?** Porque existem **24 bits iguais a 1** na máscara.

**Conversão visual:**
```
Máscara:    255.255.255.0
Binário:    11111111.11111111.11111111.00000000
            ^^^^^^^^ ^^^^^^^^ ^^^^^^^^ ^^^^^^^^
            8 bits   8 bits   8 bits   8 bits
            
Conta: 8 + 8 + 8 + 0 = 24 → /24
```

**Verifique com ipcalc:**
```bash
$ ipcalc 192.168.1.0/24
Address:   192.168.1.0
Netmask:   255.255.255.0
Network:   192.168.1.0/24
Usable IP range: 192.168.1.1 - 192.168.1.254
Broadcast address: 192.168.1.255
Usable IPs: 254
```

Viu? `/24` = `255.255.255.0` = **254 hosts utilizáveis**
<img width="708" height="200" alt="image" src="https://github.com/user-attachments/assets/fb542390-e4bc-4566-a2a5-600af1f3fb43" />

---

### **D. Calculando Quantos Hosts Cabem**

A fórmula é simples:
```
Hosts utilizáveis = 2^(32 - CIDR) - 2
```

Os 2 que subtraímos são:
- **Endereço de rede** (.0)
- **Endereço de broadcast** (.255)

**Exemplos práticos com ipcalc:**

#### `/24` (típico em redes locais)
```bash
$ ipcalc 192.168.1.0/24
Usable IPs: 254
```
- Cálculo: 2^(32-24) = 2^8 = 256, menos 2 = **254 hosts**

#### `/26` (subnet menor)
```bash
$ ipcalc 192.168.1.0/26
Address:   192.168.1.0
Usable IP range: 192.168.1.1 - 192.168.1.62
Broadcast address: 192.168.1.63
Usable IPs: 62
```
- Cálculo: 2^(32-26) = 2^6 = 64, menos 2 = **62 hosts**

#### `/30` (ponto-a-ponto)
```bash
$ ipcalc 192.168.1.0/30
Usable IP range: 192.168.1.1 - 192.168.1.2
Broadcast address: 192.168.1.3
Usable IPs: 2
```
- Cálculo: 2^(32-30) = 2^2 = 4, menos 2 = **2 hosts**

#### `/16` (rede grande - cuidado!)
```bash
$ ipcalc 10.0.0.0/16
Usable IPs: 65534
```
- Cálculo: 2^(32-16) = 2^16 = 65536, menos 2 = **65.534 hosts**

---

### **E. Tabela de Referência Rápida**

Memorize essas conversões:

| CIDR | Máscara | Hosts |
|------|---------|-------|
| /30 | 255.255.255.252 | 2 |
| /29 | 255.255.255.248 | 6 |
| /28 | 255.255.255.240 | 14 |
| /27 | 255.255.255.224 | 30 |
| /26 | 255.255.255.192 | 62 |
| /25 | 255.255.255.128 | 126 |
| /24 | 255.255.255.0 | 254 |
| /16 | 255.255.0.0 | 65.534 |

**Confirme qualquer uma:**
```bash
$ ipcalc 192.168.1.0/25
Usable IPs: 126  ✓
```

---

### **F. Aplicação Prática: Pentest**

Entender CIDR é **crítico** para varreduras eficientes.

#### Cenário 1: Rede Pequena (/24)
```bash
$ nmap -sn 192.168.1.0/24
Starting Nmap...
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
Nmap scan report for 192.168.1.50
Host is up (0.005s latency).
...
3 hosts up scanned in 0.34s
```
Para fins didáticos, iniciei uma máquina virtual com o Kali Linux para demonstrar como identificar os hosts presentes na rede 192.168.100.0/24.
<img width="804" height="248" alt="image" src="https://github.com/user-attachments/assets/936c9205-9ef9-4b8c-ab40-6d82698b1f0d" />
Como é possível observar, foi identificado o endereço 192.168.100.40, que corresponde ao IP da minha máquina virtual Kali Linux.
Isso acontece porque tanto o Ubuntu quanto o Kali estão conectados à mesma sub-rede 192.168.100.0/24 (Host-Only). Como compartilham a mesma rede, eles conseguem se comunicar entre si e, durante a varredura, ambos são detectados.

- **254 IPs para verificar** → scan rápido (~1s)
- **Comando faz sentido** ✓

#### Cenário 2: Rede Grande (/16)
```bash
$ time nmap -sn 10.0.0.0/16
...
real    2m34s
```

- **65.534 IPs para verificar** → scan lento (~2-3 min)
- **Muito barulho** (fácil ser detectado)
- **Estratégia melhor:**

```bash
# Limitar taxa de envio
nmap -sn -T2 10.0.0.0/16

# Ou dividir em subnets
nmap -sn 10.0.0.0/24
nmap -sn 10.0.1.0/24
nmap -sn 10.0.2.0/24
```

---

## 4. Resultado

Após seguir o passo-a-passo, você consegue:

✅ **Interpretar rápido:**
```bash
Vejo: 192.168.1.0/24
Penso: 24 bits de rede, 8 de host, máximo 254 hosts
Ação: Faço o scan nmap -sn 192.168.1.0/24
```

✅ **Converter CIDR ↔ Máscara instantaneamente:**
```bash
/24 ↔ 255.255.255.0
/25 ↔ 255.255.255.128
/26 ↔ 255.255.255.192
```

✅ **Calcular hosts em qualquer CIDR:**
```bash
$ ipcalc 10.50.0.0/22
Usable IPs: 1022  ← Sou rápido!
```

✅ **Planejar varreduras eficientes:**
- `/24` → Scan direto (rápido)
- `/16` → Dividir em múltiplos `/24` (discreto)
- `/30` → Apenas 2 hosts (específico para VPN/ponto-a-ponto)

---

## 5. O que Aprendi

### **Regra de Ouro:**

1. **CIDR (/24)** → Quantos bits pertencem à rede
2. **Máscara (255.255.255.0)** → Representação decimal do CIDR
3. **Rede** → Identifica o segmento (192.168.1.0)
4. **Host** → Identifica o dispositivo (192.168.1.50)

### **Relação Inversa:**
- **CIDR menor** (/16) = **Mais hosts** (65.534)
- **CIDR maior** (/30) = **Menos hosts** (2)

### **Na Prática:**
```bash
# Sempre que ver um CIDR, use ipcalc
$ ipcalc <IP/CIDR>

# Sempre que for fazer scan, pense no tamanho
# /24 = 254 hosts, tá bom fazer direto
# /16 = 65534 hosts, preciso limitar ou dividir
```

### **Para Certificações (CompTIA Security+, eJPT, PNPT):**
Decore a tabela de CIDR/Máscara/Hosts. Qualquer pergunta sobre redes usa isso.

---

## 🔗 Comandos Resumidos

```bash
# Ver sua rede atual
ifconfig
ip addr show

# Calcular tudo sobre um CIDR
ipcalc 192.168.1.0/24
ipcalc 10.0.0.0/16
ipcalc 192.168.0.0/22

# Scan de rede
nmap -sn 192.168.1.0/24
nmap -sn -T2 10.0.0.0/16  # mais lento (discreto)

# Ver tabela de roteamento
route -n
ip route show
```
