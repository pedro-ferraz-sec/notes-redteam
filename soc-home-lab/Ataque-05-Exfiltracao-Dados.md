# 🛡️ Ataque 5 — Exfiltração de Dados: Cadeia de Ataque Completa (Recon → Exfiltração → Detecção)
### Projeto de portfólio SOC / Blue Team — Pedro Ferraz

**Técnicas MITRE ATT&CK:** T1046 (Network Service Discovery) + T1190 (Exploit Public-Facing Application) + **T1048 (Exfiltration Over Alternative Protocol)**
**Ambiente:** laboratório isolado (Kali atacante · Metasploitable 2 alvo · Wazuh SIEM)
**Formato:** simulação de resposta a incidente — um ataque real foi gerado e investigado como um ticket de SOC.
**Ferramenta de recon:** [NetScan](https://github.com/matheusnsp/NetScan), por [@matheusnsp](https://github.com/matheusnsp) — scanner da comunidade usado na fase de reconhecimento.

---

## 0. Por que este cenário é diferente

Os ataques anteriores (1 a 4) focaram no **acesso inicial** — como alguém entra na máquina. Este foca no passo final e mais crítico de um ataque real: a **exfiltração** — o momento em que os dados saem da rede. É a diferença entre "alguém mexeu num servidor" e "a empresa está perdendo dados agora".

> **A frase que resume o aprendizado:**
> *Acesso inicial você detecta pelo que é anormal na ENTRADA. Exfiltração você detecta pelo que é anormal na SAÍDA.*

Por que exfiltração é difícil de detectar? Porque o dado saindo **parece tráfego normal** (um download, uma consulta). O atacante se esconde no barulho legítimo. Por isso ela é detectada por **comportamento e anomalia**, não por assinatura.

---

## 1. A arquitetura segura do lab (uma decisão de design)

Exfiltração é, por definição, dado **saindo da rede**. Mas a regra de ouro do lab é inegociável: **a máquina vulnerável nunca toca a internet.**

Como simular "dado saindo pra internet" sem dar internet de verdade ao alvo? O **Kali faz o papel do "servidor do atacante na internet"**. O dado sai do Metasploitable (vítima) e vai pro Kali (destino malicioso) — tudo dentro da rede isolada, nenhum pacote toca a internet real.

```
  Dentro da rede isolada (.100), SEM internet real:

  [ Metasploitable .50 ]  ──── dado roubado ────▶  [ Kali .40 ]
       a vítima                                   "servidor do atacante"
```

---

## 2. O ticket do incidente

> **TICKET #2051 — Prioridade ALTA**
> *Host 192.168.100.50 teve um pico de tráfego de SAÍDA de madrugada, para um destino interno incomum (192.168.100.40). O servidor normalmente não inicia conexões. Suspeita de exfiltração. Investigar: houve roubo de dados? O que foi levado? Houve reconhecimento anterior? Qual a extensão do comprometimento?*

O trabalho do analista: reconstruir a **cadeia de ataque inteira**, de trás pra frente.

---

## 3. FASE 1 — O ataque (lado ofensivo)

### 3.1 Reconhecimento com o NetScan

Antes de roubar, o atacante mapeia o alvo. Usei o **NetScan** (ferramenta da comunidade, por @matheusnsp) para o reconhecimento:

```bash
# No Kali — scan de portas e serviços, com saída em JSONL (formato para SIEM)
# --no-vuln porque o Kali está isolado (a checagem de CVE precisaria de internet)
python3 main.py 192.168.100.50 -p top100 --no-vuln -f jsonl,html -o ~/netscan-saida
```

O NetScan entregou o mapa do alvo: **16 portas abertas** e, crucialmente, apontou a porta de entrada:
- **Porta 21 — vsftpd 2.3.4 + "FTP permite login anônimo"** ← o canal de exfiltração
- Porta 23 — Telnet exposto
- Risco do host: ALTO (53/100), 3 más configurações

> 📸 PRINT AQUI: o resumo da varredura do NetScan (as 16 portas e o veredito "Risco ALTO").

> 💡 O NetScan gera relatório em **JSON Lines** (`tipo:config`, `tipo:diff`) — formato que o Wazuh consome direto. Isso será usado na detecção.

### 3.2 Enumeração e exfiltração via FTP

O NetScan revelou: **a porta 21 aceita FTP anônimo** (login sem senha). Esse é o canal de roubo.

**Lição de método — investigar, não adivinhar:** num cenário real, o atacante não sabe o nome do arquivo a roubar. Ele **enumera** o que existe:

```bash
# No Kali — conectar no FTP anônimo
ftp 192.168.100.50
# Login: anonymous / senha vazia (Enter)

# DENTRO do ftp> — enumerar antes de baixar:
pwd            # onde eu caí?
ls -la         # o que existe aqui?
get dados_clientes.txt   # baixar o arquivo DESCOBERTO (não adivinhado)
bye
```

> 📸 PRINT AQUI: a sessão FTP com o `ls -la` mostrando o `dados_clientes.txt`, seguido do `get` com "Transfer complete".

Resultado: o arquivo `dados_clientes.txt` (71 bytes, "dado confidencial") saiu do servidor-vítima para a máquina do atacante. **Exfiltração concluída.**

> 💡 **Armadilha vivida:** ao criar o arquivo, ele foi parar na home do usuário, mas o **FTP anônimo só serve o diretório do usuário `ftp`** (descoberto com `grep "^ftp:" /etc/passwd` → `/home/ftp`). Mesma lição do Samba (Ataque 4): o serviço só mostra o que está no diretório que ELE serve. A solução foi plantar o arquivo em `/home/ftp/`.

---

## 4. FASE 2 — A investigação (lado defensivo)

Virando analista: reconstruir o incidente a partir das evidências, sem "saber" o que aconteceu.

### 4.1 A evidência da exfiltração (a prova de ouro)

O FTP é iniciado pelo **xinetd**, mas o log da **aplicação** (vsftpd) é que conta a história completa:

```bash
# No Metasploitable
sudo tail -20 /var/log/vsftpd.log
```

O `vsftpd.log` revelou a exfiltração em detalhes:
```
Client "192.168.100.40", "RETR dados_clientes.txt"           ← o atacante PEDIU o arquivo
"150 Opening BINARY mode data connection ... (71 bytes)"     ← o servidor começou a enviar
[ftp] DOWNLOAD: Client "192.168.100.40", "/dados_clientes.txt", 71 bytes   ← CONFIRMA o roubo
"226 Transfer complete."                                     ← o dado saiu
```

> 📸 PRINT AQUI: o `vsftpd.log` com as linhas `RETR` e `DOWNLOAD` destacadas.

> 💡 **Lição de SOC — as duas camadas de log:** o **xinetd** é a camada de *conexão* ("alguém abriu o FTP"). O **vsftpd.log** é a camada de *aplicação* ("essa pessoa baixou ESTE arquivo"). Para detectar exfiltração, você precisa da camada de aplicação — a de conexão sozinha não conta o roubo.

### 4.2 A evidência do reconhecimento (o scan)

```bash
# No Metasploitable — procurar a rajada de conexões do scan
sudo grep "192.168.100.40" /var/log/syslog | head -40
```

A assinatura do scan apareceu: vários serviços (Telnet, SMTP...) recebendo conexão do **mesmo IP, no mesmo segundo**, com o SMTP registrando "lost connection after CONNECT" (conectou e saiu).

> 📸 PRINT AQUI: os logs mostrando as conexões em rajada no mesmo segundo (a assinatura do port scan).

> 💡 **Lição:** um port scan é um fantasma nos logs de aplicação — aparece só nos poucos serviços que logam conexão e some no resto. Por isso scan se detecta por **rede** (como no Ataque 2), não por log de aplicação.

### 4.3 O laudo

| Hipótese do ticket | Veredito | Evidência |
|---|---|---|
| Houve reconhecimento? | ✅ Sim | Conexões em rajada, mesmo IP, mesmo segundo |
| Houve acesso? | ✅ Sim | FTP anônimo acessado pelo .40 |
| Houve exfiltração? | ✅ **Sim** | `RETR` + `DOWNLOAD` de `dados_clientes.txt` → .40 |
| O que foi levado? | `dados_clientes.txt` (71 bytes) | O "dado confidencial" |
| Origem | 192.168.100.40 | Confirmada em todos os logs |

---

## 5. FASE 3 — A detecção (construindo a visibilidade)

### 5.1 Detecção da exfiltração (ponte + regra de texto)

O vsftpd escreve em arquivo local (não vai pro syslog sozinho) — mesma situação do Samba. Solução: a ponte que leva o log ao Wazuh.

```bash
# No Metasploitable — a ponte
sudo tail -f /var/log/vsftpd.log | logger -t vsftpd_monitor &
```

As regras (em `/var/ossec/etc/rules/local_rules.xml`):
```xml
<rule id="100040" level="6">
  <match>vsftpd_monitor</match>
  <description>Atividade FTP detectada no Metasploitable (servico legado/vulneravel)</description>
  <group>ftp,exfil,</group>
</rule>

<rule id="100041" level="10">
  <if_sid>100040</if_sid>
  <match>RETR</match>
  <description>Exfiltracao via FTP - download de arquivo detectado (comando RETR)</description>
  <group>ftp,exfil,attack,</group>
</rule>

<rule id="100042" level="12" frequency="4" timeframe="60">
  <if_matched_sid>100041</if_matched_sid>
  <same_source_ip />
  <description>Exfiltracao em massa via FTP - multiplos downloads do mesmo IP</description>
  <group>ftp,exfil,attack,</group>
</rule>
```

**A escolha do `RETR`:** é o comando que o cliente envia *pedindo* o arquivo — detecta a intenção no momento mais cedo possível, antes do dado terminar de sair. A regra usa cascata (`<if_sid>`): primeiro confirma que é log de FTP (100040), depois verifica se é um download (100041).

> 📸 PRINT AQUI: o `wazuh-logtest` casando a regra 100041 com a linha REAL do RETR ("Alert to be generated").

> 📸 PRINT AQUI: o alerta 100041 no dashboard, com o `full_log` mostrando o RETR, o IP do atacante (.40) e a vítima (.50).

### 5.2 Detecção do recon (ingestão de JSON — técnica nova)

O relatório JSONL do NetScan foi levado ao Wazuh e ingerido **nativamente como JSON**. No `ossec.conf`:
```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/netscan/netscan.jsonl</location>
</localfile>
```

As regras leem **campos JSON** diretamente:
```xml
<rule id="100045" level="5">
  <decoded_as>json</decoded_as>
  <field name="tipo">config</field>
  <description>NetScan: scan de reconhecimento analisou o alvo (achado de configuracao)</description>
  <group>recon,scan,netscan,</group>
</rule>

<rule id="100046" level="9">
  <if_sid>100045</if_sid>
  <field name="severidade">ALTA</field>
  <description>NetScan: scan encontrou ma configuracao de severidade ALTA no alvo</description>
  <group>recon,scan,netscan,attack,</group>
</rule>
```

> 💡 **A diferença do JSON:** nos ataques anteriores, sem decoder, a regra ancorava em `<match>` de texto. Com `<log_format>json</log_format>`, o Wazuh **quebra cada linha em campos automaticamente** (`data.tipo`, `data.severidade`) — e a regra lê `<field name="severidade">ALTA</field>` diretamente. É a diferença entre "procurar uma palavra no texto" e "ler o valor de uma coluna". Logs em JSON são o padrão moderno (cloud, APIs, ferramentas de segurança).

> 📸 PRINT AQUI: o `wazuh-logtest` com a **Phase 2** listando os campos JSON extraídos (`severidade`, `tipo`, etc.) e casando a regra 100046.

> 📸 PRINT AQUI: os alertas 100045 e 100046 no dashboard (o NetScan detectado no SIEM).

---

## 6. BÔNUS — Troubleshooting operacional (o que nenhum tutorial mostra)

Durante a montagem, o lab apresentou problemas operacionais reais — e resolvê-los é tão valioso quanto o ataque.

### 6.1 Disco cheio no SIEM
O Wazuh parou de gravar: `No space left on device`. Diagnóstico com `df -h` revelou que não era o disco (`/` em 74%), e sim o **`/tmp` em 100%** — porque `/tmp` era um **`tmpfs` (vive na RAM)**, pequeno e volátil.
> **Lição:** nunca coloque arquivos monitorados por um serviço em `/tmp` quando ele é tmpfs. Movido para `/var/log/netscan/` (disco de verdade).

### 6.2 O loop fatal que encheu o disco
Um comando `cat arquivo | tee -a arquivo` (ler e escrever o **mesmo** arquivo) criou um **loop infinito** que inflou o relatório de 3 KB para **8 GB**, lotando o disco.
> **Lição:** nunca leia e escreva o mesmo arquivo ao mesmo tempo. Use sempre um arquivo intermediário diferente. Esse erro já derrubou servidores de produção.

### 6.3 O alert storm (tempestade de alertas)
13 linhas de log geraram **650.000 alertas** no dashboard — porque o arquivo inflado de 8 GB foi todo reprocessado antes de ser apagado.
> **Lição:** ao ver um número absurdo de alertas, a primeira ação é **olhar a janela de tempo** — "isso está acontecendo AGORA ou é histórico?". Estreitar o filtro de tempo (de "10 min" para "2 min") separou o pico passado do estado atual, e confirmou que o loop já tinha parado. Reconhecer e contextualizar um alert storm é habilidade de SOC real.

> 📸 PRINT AQUI (opcional, forte): o dashboard com os 650 mil hits (a "parede" do alert storm) e depois estabilizado em 42.

---

## 7. A cadeia de ataque completa (resumo visual)

```
RECON ──────────────▶ ENUMERAÇÃO ────────▶ EXFILTRAÇÃO
NetScan (scan)          FTP anônimo           RETR do arquivo
   ↓ 🚨                      ↓                      ↓ 🚨
regra 100046            (investigação)         regra 100041
(severidade ALTA)                              (download detectado)
```

| Regra | Nível | Detecta | Técnica |
|---|---|---|---|
| 100040 | 6 | Atividade FTP | `<match>` de texto (ponte) |
| **100041** | 10 | **Exfiltração (RETR)** | `<if_sid>` + `<match>` |
| 100042 | 12 | Exfiltração em massa | Correlação |
| 100045 | 5 | Scan rodou | **JSON** (`<decoded_as>`) |
| **100046** | 9 | **Scan achou algo grave** | JSON + `<field>` |

---

## 8. Conceitos demonstrados (para entrevista)

- Cadeia de ataque completa: reconhecimento → enumeração → exfiltração (T1046 → T1190 → T1048)
- Exfiltração detectada pela SAÍDA (anomalia de comportamento, não assinatura)
- Investigação por enumeração (`pwd`, `ls -la`) em vez de adivinhação
- As duas camadas de log: conexão (xinetd) vs. aplicação (vsftpd.log)
- Ponte `tail -f | logger` para levar log de serviço legado ao SIEM
- **Ingestão nativa de JSON no Wazuh** (`<log_format>json</log_format>`, `<decoded_as>`, `<field>`)
- Regra em cascata com `<if_sid>`
- Integração de ferramenta de terceiros ao SIEM (NetScan → JSONL → Wazuh)
- **Troubleshooting operacional de SIEM:** disco cheio, tmpfs vs. disco, loop de arquivo, alert storm
- Diagnóstico com `df -h` / `du -h` / `wc -l`
- Diferença `Connection refused` vs. `timeout`
- `sudo cmd > arquivo` não escreve como root — usar `sudo tee`

---

## 9. Comandos de referência

```
# --- RECON (Kali) ---
python3 main.py 192.168.100.50 -p top100 --no-vuln -f jsonl,html -o ~/netscan-saida

# --- EXFILTRAÇÃO (Kali) ---
ftp 192.168.100.50          # anonymous / senha vazia
  pwd ; ls -la ; get dados_clientes.txt ; bye

# --- INVESTIGAÇÃO (Metasploitable) ---
sudo tail -20 /var/log/vsftpd.log
grep "^ftp:" /etc/passwd                     # onde o FTP anônimo aterrissa
sudo grep "192.168.100.40" /var/log/syslog | head -40

# --- DETECÇÃO: exfiltração (ponte no Metasploitable) ---
sudo tail -f /var/log/vsftpd.log | logger -t vsftpd_monitor &

# --- DETECÇÃO: recon (ossec.conf no Wazuh) ---
# <localfile><log_format>json</log_format><location>/var/log/netscan/netscan.jsonl</location></localfile>

# --- TESTAR E APLICAR (Wazuh) ---
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager

# --- TROUBLESHOOTING DE DISCO (Wazuh) ---
df -h                                        # tmpfs vs disco real
sudo du -h --max-depth=1 /var | sort -rh | head
wc -l arquivo.jsonl                          # confirmar tamanho real
# NUNCA: cat arquivo | tee -a arquivo  (loop infinito!)
```

---

## Créditos

Ferramenta de reconhecimento: **[NetScan](https://github.com/matheusnsp/NetScan)**, desenvolvida por **[@matheusnsp](https://github.com/matheusnsp)**. Obrigado pela ferramenta da comunidade.

---

> ⚠️ **Antes de publicar:** confira que os prints não mostram dados reais (IP público, senhas, nome de máquina identificável). Os IPs de laboratório (192.168.x.x) são seguros de publicar.

*Projeto realizado em laboratório isolado e controlado, exclusivamente para estudo de detecção e defesa.*
