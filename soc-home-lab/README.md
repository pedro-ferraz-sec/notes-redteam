# 🧪 SOC Home Lab

Laboratório de SOC / Blue Team montado do zero para simular, detectar e investigar ataques reais — o mesmo ciclo do dia a dia de um analista de segurança.

---

## 🎯 Objetivo

Construir um ambiente controlado onde cada ataque é **executado, detectado no SIEM, investigado e documentado**, mapeando as técnicas ao framework MITRE ATT&CK.

---

## 🖥️ Arquitetura

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│    Kali     │ ───▶ │    Ubuntu       │ ───▶ │    Wazuh    │
│  (atacante) │      │    (alvos)       │      │   (SIEM)    │
└─────────────┘      └──────────────────┘      └─────────────┘
    ataque              telemetria                detecção
                     (Sysmon / logs)           e correlação
```

VMs isoladas em rede própria, sem contato com ambiente de produção.

---

## 🔁 Ciclo de trabalho

**Executo** → **Detecto no SIEM** → **Investigo** → **Mapeio ao MITRE ATT&CK** → **Documento**

---

## 📌 Etapas

| Etapa | Foco | Status |
| --- | --- | --- |
| 1 | Rede e reconhecimento | ✅ |
| 2 | Coleta de logs e ataque de credenciais | ✅ |
| 3 | SIEM Wazuh — detecção automática | ✅ |
| 4 | Resposta a incidentes + MITRE ATT&CK | 🔄 |

---

## 🛠️ Stack

`Kali Linux` `Ubuntu` `Wazuh SIEM` `Sysmon` `Wireshark` `OSINT` `MITRE ATT&CK`

---

## 📄 Cenários documentados

Cada cenário segue o mesmo formato: contexto → execução do ataque → detecção no Wazuh → análise → técnica MITRE correspondente.

> Em construção — novos cenários adicionados conforme o laboratório evolui.
