# 🛡️ Ataque 2 — Port Scan: Detecção baseada em Rede no Wazuh
### Projeto de portfólio SOC / Blue Team — Pedro Ferraz

**Técnica MITRE ATT&CK:** T1046 — Network Service Discovery (Reconhecimento)
**Ambiente:** laboratório isolado (Kali atacante · Ubuntu alvo · Wazuh SIEM)
**Objetivo:** detectar uma varredura de portas (port scan) — um ataque que, diferente da força bruta, não deixa rastro nos logs de aplicação.

---

## 1. O que é este ataque

**Port scan** é o reconhecimento: antes de invadir, o atacante varre o alvo para descobrir **quais portas estão abertas e quais serviços rodam**. É quase sempre o primeiro passo de um ataque real.

Ferramenta: **Nmap** (no Kali).

<img width="873" height="259" alt="Captura de tela 2026-10-21 090645" src="https://github.com/user-attachments/assets/cce70b78-f31e-43ca-ae05-cd3e4bb8e852" />

---

## 2. O desafio que torna este ataque especial

A força bruta (meu Ataque 1) deixa rastro claro: cada tentativa falha vira um "Failed password" no log do SSH. **O port scan não.**

Um scan toca cada porta uma vez e vai embora. Portas fechadas nem são logadas pelo sistema. Ou seja: é **tráfego de rede puro**, e os logs de aplicação que o SIEM lê por padrão não registram nada.

Testei primeiro a abordagem simples (deixar o Wazuh observar com a configuração padrão). Resultado: o scan de 65.535 portas passou **invisível**. Nenhum alerta.

> Lição: nem todo ataque deixa rastro no lugar óbvio. Para ver um ataque de rede, o defensor precisa dar ao SIEM uma **fonte de rede**.

---

## 3. A solução: dar olhos de rede ao SIEM

Ativei o log do **firewall (UFW)** no alvo. Agora cada conexão bloqueada é registrada — e a varredura do Nmap gera centenas dessas linhas:

```
[UFW BLOCK] SRC=192.168.100.40 DST=192.168.100.30 DPT=23 SYN
[UFW BLOCK] SRC=192.168.100.40 DST=192.168.100.30 DPT=53 SYN
[UFW BLOCK] SRC=192.168.100.40 DST=192.168.100.30 DPT=80 SYN
...
```

A assinatura do scan fica clara: **uma origem → muitas portas de destino → em altíssima velocidade.**

Depois apontei o agente Wazuh para ler esse log do firewall (`/var/log/ufw.log`).

<img width="2238" height="967" alt="Captura de tela 2026-10-20 212445" src="https://github.com/user-attachments/assets/5f22469b-f38e-41dc-bbeb-28d5e2a4b3aa" />

---

## 4. O obstáculo técnico (e a lição)

Mesmo lendo o log, o Wazuh **não gerava alerta**. Usei a ferramenta de teste do próprio Wazuh (`wazuh-logtest`) e descobri o porquê: o decoder nativo não conseguia extrair os campos da linha do UFW — então nenhuma regra casava e o evento era descartado.

> Lição: o SIEM pode estar "vendo" o dado e ainda assim não reconhecê-lo. O trabalho do analista é escrever a regra que faz a conexão.

---

## 5. A solução final: minha regra de detecção

Escrevi duas regras que casam direto com o texto do log (sem depender do decoder):

**Regra base** — detecta uma conexão bloqueada:
```xml
<rule id="100010" level="5">
  <match>[UFW BLOCK]</match>
  <description>UFW: conexao bloqueada pelo firewall</description>
</rule>
```

**Regra de correlação** — detecta o PADRÃO de scan:
```xml
<rule id="100011" level="10" frequency="15" timeframe="10">
  <if_matched_sid>100010</if_matched_sid>
  <same_source_ip />
  <description>Port scan detectado - 15+ conexoes bloqueadas do mesmo IP em 10s</description>
</rule>
```

Os três pilares de uma regra de detecção, agora aplicados à rede:
- **Limiar:** 15 conexões bloqueadas
- **Janela:** em 10 segundos
- **Agrupador:** do mesmo IP de origem

15 conexões bloqueadas em 10s do mesmo IP não é usuário legítimo — é varredura.

Testei com `wazuh-logtest` antes de aplicar (boa prática).

<img width="909" height="635" alt="Captura de tela 2026-10-20 214755" src="https://github.com/user-attachments/assets/b0becef9-6310-4f5f-a940-52e5ad0c1b9d" />

---

## 6. O resultado

O scan gerou 396 conexões bloqueadas, e minha regra capturou todas elas no SIEM — transformando um ataque ‘invisível’ em 396 eventos visíveis e rastreáveis, todos ligados ao IP do atacante.
<img width="1728" height="1127" alt="Captura de tela 2026-10-20 214949" src="https://github.com/user-attachments/assets/552ca15b-0c67-4c83-9adc-874666e910b6" />

---

## 7. Conceitos demonstrados

- Diferença entre detecção por log de aplicação e por **log de rede/firewall**
- Configuração de coleta de log customizada no agente Wazuh (ossec.conf)
- Diagnóstico com `wazuh-logtest` (as 3 fases: pre-decoding → decoding → rules)
- Entendimento de decoders vs. regras no Wazuh
- Escrita de regra que casa por texto (robusta, independente de decoder)
- Correlação de eventos (limiar + janela + agrupador)
- Mapeamento ao MITRE ATT&CK (T1046 — Network Service Discovery)

---

*Projeto realizado em laboratório isolado e controlado, exclusivamente para estudo de detecção e defesa.*
