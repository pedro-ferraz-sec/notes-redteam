# 🛡️ Ataque 1 — Força Bruta SSH: Detecção + Resposta Automática
### Projeto de portfólio SOC / Blue Team — Pedro Ferraz

**Ambiente:** laboratório isolado e controlado (Kali atacante · Ubuntu alvo · Wazuh SIEM)
**Técnica MITRE ATT&CK:** T1110 — Brute Force
**Objetivo:** detectar um ataque de força bruta SSH e **bloquear o atacante automaticamente**.

---

## 1. O que é este ataque

**Força bruta** é a tentativa de adivinhar uma senha testando milhares de combinações automaticamente. No SSH, o atacante bombardeia o serviço com usuário + senhas de uma wordlist até acertar (ou desistir).

- **Ferramenta de ataque:** Hydra (no Kali)
- **Wordlist:** rockyou.txt (~14 milhões de senhas)
- **Alvo:** serviço SSH (porta 22) do Ubuntu

> Assinatura do ataque: muitas falhas de autenticação, do **mesmo IP**, em **curto período**, contra o **mesmo serviço**. (Lembre: um evento é um ponto; um ataque é um padrão.)

---

## 2. O ataque (no Kali)

```
rm -f ./hydra.restore
hydra -l x -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.100.30
```
- `-l x` → usuário alvo
- `-P ...rockyou.txt` → lista de senhas
- `-t 4` → 4 conexões em paralelo

<img width="1075" height="202" alt="Captura de tela 2026-10-17 173725" src="https://github.com/user-attachments/assets/0f6b3d3f-647d-4c35-b8a5-d2adfb3bd614" />

---

## 3. A detecção (no Wazuh)

As falhas chegam ao SIEM como eventos **5760** ("sshd: authentication failed", nível 5) — as falhas individuais.

<img width="1255" height="1218" alt="Captura de tela 2026-10-17 174643" src="https://github.com/user-attachments/assets/0f356559-127b-4759-a8cf-c140166bce1b" />

---

## 4. O obstáculo real (e a lição mais valiosa)

A regra nativa do Wazuh para força bruta (**40111**, "Multiple authentication failures") **não disparou** — e descobrir o porquê foi o aprendizado central deste projeto.

**Causa:** o SSH moderno tem defesas nativas que sabotaram a correlação:
- `MaxAuthTries` — limita tentativas por conexão e derruba a conexão ao passar do limite.
- `srclimit_penalise` — pune o IP atacante com segundos de penalidade a cada falha, deixando o ataque cada vez mais lento.

Resultado: o Hydra só conseguia gerar ~6–14 falhas por **minuto**, espalhadas em conexões diferentes. A regra 40111 exige 8 falhas em 120 segundos no mesmo contexto — e esse volume nunca se formava. **O alvo estava tão bem defendido que o ataque nem chegava a ser "grande o suficiente" para a regra de correlação.**

> Lição: regras nativas nem sempre casam com o seu ambiente. O trabalho do analista é **calibrar a detecção à realidade** — e isso exige escrever a própria regra.

---

## 5. A solução: regra customizada (escrita por mim)

Arquivo: `/var/ossec/etc/rules/local_rules.xml`

```xml
<rule id="100002" level="10" frequency="5" timeframe="120">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>Forca bruta SSH detectada - 5 falhas do mesmo IP - origem: $(srcip)</description>
  <group>authentication_failures,</group>
</rule>
```

Os **três parafusos** de uma regra de detecção, calibrados ao ambiente:
- **Limiar:** `frequency="5"` → 5 falhas (mais baixo que os 8 da nativa, ajustado à lentidão imposta pelo SSH)
- **Janela de tempo:** `timeframe="120"` → em 120 segundos
- **Agrupador:** `same_source_ip` → do mesmo IP de origem

Validação antes de aplicar (boa prática — nunca reiniciar sem testar):
```
sudo /var/ossec/bin/wazuh-logtest
```

---

## 6. A resposta automática (Active Response)

Arquivo: `/var/ossec/etc/ossec.conf` (no **servidor** Wazuh)

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002</rules_id>
  <timeout>180</timeout>
</active-response>
```
- `firewall-drop` → bloqueia o IP no firewall (iptables) do alvo
- `location local` → a ação roda na máquina que gerou o alerta
- `rules_id 100002` → **gatilho: a minha regra customizada**
- `timeout 180` → bloqueia por 180s e libera automaticamente

Proteção contra auto-bloqueio (whitelist no `<global>`): IPs do servidor e da rede de gestão nunca são bloqueados.

---

## 7. O resultado — ciclo completo

Prova no `/var/ossec/logs/active-responses.log`:

```
19:26:22  "command":"add"    ... rule id 100002 ... origem: 192.168.100.40   ← BLOQUEOU
19:29:23  "command":"delete" ... Ended                                       ← LIBEROU (180s depois)
```

Do lado do atacante, o Hydra passou a receber:
```
[ERROR] could not connect to ssh://192.168.100.30:22 - Timeout connecting
```
O Kali foi **cortado no firewall** — não alcançava mais o alvo.

```
Kali ataca → regra 100002 dispara (5 falhas/120s/mesmo IP)
          → firewall-drop bloqueia o IP (add)
          → Hydra recebe "Timeout connecting"
          → após 180s, libera sozinho (delete)
```

<img width="1016" height="280" alt="Captura de tela 2026-10-17 193843" src="https://github.com/user-attachments/assets/48d62e23-839e-4f22-9bc5-086d1bf24fea" />

---

## 8. Conceitos demonstrados

- Detecção de força bruta via correlação de eventos (limiar + janela + agrupador)
- Escrita e teste de regra customizada no Wazuh (`local_rules.xml`, `wazuh-logtest`)
- Arquitetura servidor/agente de um SIEM (onde cada configuração mora)
- Active Response: bloqueio automático de IP com timeout e whitelist de segurança
- Troubleshooting guiado por evidência (logs, não suposições)
- Entendimento das defesas nativas do SSH (`MaxAuthTries`, `srclimit_penalise`)
- Mapeamento ao MITRE ATT&CK (T1110 Brute Force)

---

## Comandos de referência

```
# Ataque (Kali)
hydra -l x -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.100.30

# Testar regra (servidor)
sudo /var/ossec/bin/wazuh-logtest

# Aplicar (servidor)
sudo systemctl restart wazuh-manager

# Verificar resposta (alvo)
sudo cat /var/ossec/logs/active-responses.log
sudo iptables -L -n | grep 192.168.100.40
```

*Projeto realizado em laboratório isolado e controlado, exclusivamente para estudo de detecção e defesa.*
