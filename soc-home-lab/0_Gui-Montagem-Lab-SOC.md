# 🧪 Como montar um Laboratório de SOC / Blue Team do zero

> Guia passo a passo para montar um laboratório de cibersegurança em casa, usando **VMware**, **Kali Linux** (atacante), **Ubuntu** + **Wazuh** (SIEM/defesa) e **Metasploitable 2** (alvo vulnerável) — tudo em uma rede **isolada e segura**, sem risco para a sua rede real.

**Nível:** iniciante — não assume conhecimento prévio de virtualização.
**Tempo estimado:** 2 a 4 horas (a maior parte é download e instalação).

---

## 📑 Índice

1. [O que é esse lab e por que montar](#1-o-que-é-esse-lab-e-por-que-montar)
2. [As peças (o que cada máquina faz)](#2-as-peças)
3. [A arquitetura de rede (a parte mais importante)](#3-a-arquitetura-de-rede)
4. [Pré-requisitos e downloads](#4-pré-requisitos-e-downloads)
5. [Passo 1 — Instalar o VMware](#passo-1--instalar-o-vmware)
6. [Passo 2 — Criar as redes virtuais](#passo-2--criar-as-redes-virtuais)
7. [Passo 3 — Criar as VMs](#passo-3--criar-as-vms)
8. [Passo 4 — Configurar os IPs fixos](#passo-4--configurar-os-ips-fixos)
9. [Passo 5 — Instalar o Wazuh](#passo-5--instalar-o-wazuh)
10. [Passo 6 — Testar o isolamento (o teste de segurança)](#passo-6--testar-o-isolamento)
11. [Passo 7 — Validar que está tudo conversando](#passo-7--validar-que-está-tudo-conversando)
12. [Próximos passos](#próximos-passos)
13. [Erros comuns](#erros-comuns)

---

## 1. O que é esse lab e por que montar

Um laboratório de SOC é um ambiente controlado onde você **ataca de um lado e detecta do outro** — sem tocar em nada real. Ele é a forma mais honesta de aprender cibersegurança: você não decora, você vê o ataque acontecer e vê (ou não vê) o alerta nascer no SIEM.

Com esse lab você consegue praticar:
- Reconhecimento e exploração (lado ofensivo / Red Team)
- Monitoramento, detecção e resposta a incidentes (lado defensivo / Blue Team / SOC)
- Escrita de regras de detecção, correlação de eventos e resposta automática

<img width="1536" height="1024" alt="Topologia de Rede do Laboratório Cibernético" src="https://github.com/user-attachments/assets/66183753-ab7b-4d9e-bff5-a18547981b23" />

---

## 2. As peças

| Máquina | Papel | Por quê |
|---|---|---|
| **Kali Linux** | Atacante (Red Team) | Traz as ferramentas de ataque prontas (Nmap, Metasploit, Hydra...) |
| **Ubuntu Server** | SIEM / Defesa (Blue Team) | Hospeda o **Wazuh**, o cérebro que coleta logs e gera alertas |
| **Metasploitable 2** | Alvo vulnerável | Máquina propositalmente cheia de falhas, feita para treino |
| **(opcional) Ubuntu Desktop** | Alvo "normal" | Um host comum para simular um usuário da rede |

> 💡 O Wazuh pode ser instalado no Ubuntu Server. O Metasploitable 2 é uma VM pronta — você baixa e importa, não instala.

---

## 3. A arquitetura de rede

**Esta é a parte que mais importa e a que mais gente erra.** Uma máquina propositalmente vulnerável (o Metasploitable) **NUNCA pode tocar a internet.** Se tocar, ela pode ser invadida de verdade, de fora, e virar porta de entrada na sua rede doméstica.

A solução é usar **duas redes separadas**:

```
┌─────────────────────────────────────────────────────────┐
│   REDE DE ATAQUE — isolada (192.168.100.0/24)           │
│   SEM acesso à internet                                 │
│                                                         │
│   [ Kali .40 ]   [ Metasploitable .50 ]   [ Wazuh .10 ] │
│       atacante         alvo vulnerável    ↑ coleta logs │
└───────────────────────────────────────────────┼─────────┘
                                                 │
┌────────────────────────────────────────────────┼────────┐
│   REDE DE GERÊNCIA — com NAT (acesso à internet)        │
│   usada SÓ pelo Wazuh, kali, para baixar atualizações.  │
└─────────────────────────────────────────────────────────┘
```

Repare: o **Wazuh tem duas placas de rede** ("duas pernas"). Uma fica na rede isolada (recebe os logs das máquinas de treino) e a outra na rede de gerência (só pra baixar updates). As máquinas de ataque e alvo ficam **só** na rede isolada, sem saída pra internet.

| Máquina | IP (rede isolada) | Internet? |
|---|---|---|
| Wazuh (SIEM) | 192.168.100.10 | Sim, só pela 2ª placa (gerência) |
| Kali (atacante) | 192.168.100.40 | **Não** |
| Metasploitable (alvo) | 192.168.100.50 | **Não** |

> 💡 Os IPs acima são exemplos. Use a faixa que preferir — o importante é o conceito das duas redes.

---

## 4. Pré-requisitos e downloads

**Hardware recomendado:** 16 GB de RAM (dá pra rodar com 8 GB, apertado), 100 GB de disco livre, processador com virtualização (VT-x/AMD-V) ativada na BIOS.

**O que baixar (tudo gratuito):**
- **VMware Workstation Player** (Windows/Linux) ou **VMware Fusion** (Mac) — site oficial da Broadcom/VMware
- **Kali Linux** — imagem pré-configurada para VMware (site oficial kali.org → "Virtual Machines")
- **Ubuntu Server** — iso (site oficial ubuntu.com)
- **Metasploitable 2** — VM pronta (SourceForge, projeto oficial Rapid7)
- **Wazuh** — não precisa baixar separado; instala via script no Ubuntu

> ⚠️ Baixe **sempre** das fontes oficiais. VM de "repositório qualquer" pode vir adulterada.

---

## Passo 1 — Instalar o VMware

1. Baixe o instalador do VMware Workstation Player do site oficial.
2. Execute e siga o assistente (Avançar → Avançar → Concluir).
3. Reinicie se ele pedir.

<img width="1464" height="1027" alt="Captura de tela 2026-11-04 145751" src="https://github.com/user-attachments/assets/937eb4dc-f858-4cea-9972-9cbc5e41bc14" />


> ⚠️ Se o VMware reclamar de virtualização desativada, entre na BIOS/UEFI do seu PC e ative **VT-x** (Intel) ou **AMD-V** (AMD).

---

## Passo 2 — Criar as redes virtuais

Antes de criar as VMs, vamos preparar as duas redes. No VMware isso fica no **Virtual Network Editor** (Editor de Rede Virtual).

1. Abra o **Virtual Network Editor** (no Player, pode precisar abrir como administrador).
2. Crie uma rede **Host-only** (apenas-host) — essa será a **rede de ataque isolada**. Chame de algo como `VMnet1`. **Desmarque** a opção de usar DHCP/NAT, pra ela ficar sem internet.
3. Deixe a rede **NAT** padrão (`VMnet8`) como está — essa será a **rede de gerência** do Wazuh.

<img width="595" height="227" alt="Captura de tela 2026-11-04 145956" src="https://github.com/user-attachments/assets/035ec9ba-f38e-45eb-93fe-d985be3c8d4a" />

> 💡 **O conceito:** "Host-only" = rede fechada, só entre as VMs, sem internet. "NAT" = as VMs saem pra internet através do seu PC. Por isso a isolada é Host-only e a de gerência é NAT.

---

## Passo 3 — Criar as VMs

### Kali e Ubuntu
1. No VMware: **Create a New Virtual Machine** → aponte para a ISO do Ubuntu (ou importe a imagem pronta do Kali).
2. Siga a instalação normal do sistema.
3. Na configuração da VM (**Settings → Network Adapter**), conecte a placa de rede à **rede isolada (VMnet1)**.

### Metasploitable 2 (é só importar)
1. Descompacte o arquivo baixado.
2. No VMware: **Open a Virtual Machine** → selecione o arquivo `.vmx` do Metasploitable.
3. Em **Settings → Network Adapter**, conecte à **rede isolada (VMnet1)**.
4. Login padrão: usuário `msfadmin` / senha `msfadmin`.

### Wazuh (as duas placas)
O Ubuntu que vai rodar o Wazuh precisa de **duas placas de rede**:
1. Em **Settings → Add → Network Adapter**, adicione uma segunda placa.
2. **Placa 1 →** rede isolada (VMnet1) — pra receber logs.
3. **Placa 2 →** rede NAT (VMnet8) — pra baixar updates.

---

## Passo 4 — Configurar os IPs fixos

Máquina de lab precisa de **IP fixo** — senão o IP muda a cada reboot e nada se encontra mais. Como a rede isolada não tem DHCP, o IP é definido manualmente.

### No Ubuntu/Wazuh (sistema moderno → netplan)
Edite um arquivo em `/etc/netplan/`:
```yaml
network:
  version: 2
  ethernets:
    ens38:                    # o nome da placa isolada (confira com: ip a)
      dhcp4: no
      addresses:
        - 192.168.100.10/24
```
Aplique com:
```
sudo netplan apply
```

### No Metasploitable (sistema antigo → /etc/network/interfaces)
```
auto eth0
iface eth0 inet static
    address 192.168.100.50
    netmask 255.255.255.0
```
Reinicie a rede ou a VM.

<img width="969" height="376" alt="Captura de tela 2026-11-04 152719" src="https://github.com/user-attachments/assets/41967f1e-18ad-4bec-9132-98219c99c08a" />

> ⚠️ **Erro clássico:** usar `ifconfig ... up` ou `ip addr add` direto no terminal. Isso funciona, mas **some no reboot**. Pra IP permanente, tem que editar o arquivo de configuração (netplan ou interfaces).

---

## Passo 5 — Instalar o Wazuh

No Ubuntu que será o SIEM, rode o instalador automático oficial do Wazuh:
```
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
Ao final, o script mostra o usuário e a senha de acesso ao painel. Acesse pelo navegador:
```
https://192.168.100.10
```

<img width="1473" height="1058" alt="Captura de tela 2026-10-03 162754" src="https://github.com/user-attachments/assets/7d595cce-8cd6-43f1-a12a-7a37f6f284be" />

---

## Passo 6 — Testar o isolamento (o teste de segurança)

**Este é o passo que não pode ser pulado.** Antes de qualquer ataque, confirme que as máquinas vulneráveis **não** alcançam a internet.

No Kali e no Metasploitable, rode:
```
ping -c 2 8.8.8.8
```
**O resultado TEM que FALHAR** (sem resposta / 100% packet loss). Se falhar, o isolamento está correto. ✅

Depois, confirme que as máquinas se enxergam **entre si** na rede isolada:
```
# do Kali, pingar o alvo e o SIEM:
ping -c 2 192.168.100.50
ping -c 2 192.168.100.10
```
Esses **devem** responder. ✅

<img width="862" height="173" alt="Captura de tela 2026-11-04 151724" src="https://github.com/user-attachments/assets/987990db-3890-46fc-8ca1-2c364e74f256" />

---

## Passo 7 — Validar que está tudo conversando

Agora o teste final: fazer um log chegar ao Wazuh.

- Se o alvo aceitar o **agente Wazuh**, instale-o apontando para o IP do SIEM.
- Se for um sistema legado (como o Metasploitable, de 2012, que não aceita o agente moderno), use **monitoramento sem agente via syslog**: o alvo envia os logs pela rede (UDP/514) e o Wazuh escuta.

No painel do Wazuh, confira em **Agents / Endpoints** se a máquina aparece como ativa, ou procure os eventos chegando no dashboard.

<img width="1493" height="1109" alt="Captura de tela 2026-10-03 165215" src="https://github.com/user-attachments/assets/736a90c6-8396-4b07-b939-143a1d454019" />

Se o log chega ao Wazuh, **o lab está pronto.** 🎉

---

## Próximos passos

Com o lab de pé, o aprendizado de verdade começa. Sugestão de progressão:
1. **Força bruta SSH** com Hydra → detectar e responder automaticamente
2. **Port scan** com Nmap → detectar pelo log do firewall
3. **Exploração de serviço vulnerável** (ex.: vsftpd, Samba no Metasploitable) → investigar como um incidente de SOC
4. **Escrever suas próprias regras** de detecção no Wazuh

> 💡 A meta não é só "rodar o ataque", é entender **por que** ele aparece (ou não) no SIEM, e aprender a dar visibilidade quando ele não aparece.

---

## Erros comuns

| Erro | O que acontece | Como evitar |
|---|---|---|
| Alvo vulnerável na rede NAT | Máquina de treino exposta à internet — risco real | Sempre Host-only para alvos; teste com `ping 8.8.8.8` (tem que falhar) |
| IP configurado no terminal | Some no reboot, nada se encontra | Editar netplan / interfaces para IP permanente |
| Virtualização desativada | VMware não inicia as VMs | Ativar VT-x / AMD-V na BIOS |
| Nome da placa errado no netplan | `netplan apply` não funciona | Confirmar o nome com `ip a` antes |
| Baixar VM de fonte não-oficial | Imagem pode vir adulterada | Sempre do site oficial |

---

## 🖼️ Diagrama da topologia

```
                    INTERNET
                       │
                   [ NAT ]  ← rede de gerência (só o Wazuh usa)
                       │
                  ┌────────┐
                  │ WAZUH  │  (2 placas de rede)
                  │  SIEM  │
                  └────┬───┘
                       │  ← rede de ATAQUE isolada (sem internet)
          ┌────────────┼────────────┐
     ┌────────┐                ┌──────────────┐
     │  KALI  │ ──── ataca ──→ │ METASPLOITABLE│
     │atacante│                │  alvo (falho) │
     └────────┘                └──────────────┘
         └──── logs vão pro Wazuh ────┘
```
<img width="1536" height="1024" alt="Topologia de Laboratório Cibernético" src="https://github.com/user-attachments/assets/b0c5594a-74d8-4e56-9a4e-6bbe33318638" />

*Guia escrito para fins educacionais. Laboratório isolado e controlado, exclusivamente para estudo de ataque e defesa em ambiente próprio.*

