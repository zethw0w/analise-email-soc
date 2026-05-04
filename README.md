# Analise de E-mail Malicioso — SOC Lab

Investigacao de 28 e-mails do dataset `email_lab_dataset` (FIAP) simulando triagem SOC nos niveis N1, N2 e N3/IR.

## Resultado

| Classificacao | Quantidade |
|---|---|
| Malicioso (Phishing/Spoofing) | 26 |
| Malicioso (Phishing + Malware) | 1 |
| Legitimo | 1 |
| **Total** | **28** |

## Arquivos

| Arquivo | Descricao |
|---|---|
| `analyze_emails.py` | Parser dos `.eml` — extrai headers, autenticacao, URLs e classifica |
| `generate_report.py` | Gera o PDF do relatorio a partir do CSV |
| `analise_emails_iocs.csv` | Tabela completa: arquivo, From, Return-Path, IP, SPF/DKIM/DMARC, URLs, classificacao |
| `relatorio_investigacao_email.pdf` | Relatorio formal com passo a passo da investigacao |

## Como reproduzir

```powershell
pip install reportlab
python analyze_emails.py    # gera o CSV
python generate_report.py   # gera o PDF
```


> Ajuste `DATASET_DIRS` em `analyze_emails.py` se mover o dataset.

## Passo a passo da investigacao (resumo)

1. **Coleta** — extrair `email_lab_dataset.zip` (senha `blueTeam`) em pasta isolada read-only.
2. **Triagem N1** — comparar `From` x `Return-Path`, checar urgencia no `Subject`, identificar typosquatting.
3. **Analise N2 (header)** — ler cadeia `Received` (de baixo pra cima = origem real); validar `SPF` / `DKIM` / `DMARC` em `Authentication-Results`.
4. **Analise de URL** — extrair links do corpo HTML; identificar dominio efetivo (eTLD+1) lendo da direita pra esquerda.
5. **Analise de anexo** — flagar extensoes perigosas (.htm, .html, .exe, .scr, .js, .vbs, .hta, .docm, .xlsm, .lnk).
6. **Consolidacao de IOCs** — IPs, dominios, padroes de subject prontos para SIEM/firewall/proxy.
7. **Resposta** — quarentena, bloqueio de IOCs, reset de credenciais, varredura EDR, ativar DMARC `p=reject` no dominio proprio.

## Achados de destaque

- **caso1.eml** — phishing SilvaoPost via servico publico anonimo `emkei.lv`; anexo `.htm` em base64 = credential harvester (`document.write(unescape(atob(b64)))`); flag CTF embutida no header `X-Custom-Header` decodifica para `FIAP{easy_headers}`.
- **e-mail_estudo_de_caso.eml** — Itau spoof com origem `192.168.0.45` (RFC1918, impossivel em SMTP publico).
- **header_fake.eml** — Apple spoof com origem `203.0.113.5` (TEST-NET-3, RFC 5737).
- **email_1 a email_24** — campanha massiva automatizada, padrao `evil{N}.com` / `malicious{N}.com` / `185.199.{N}.10`.
- **secreto.eml** — unico e-mail legitimo (Proton Mail, SPF/DKIM/DMARC = pass), serve de baseline.

## IOCs principais

```
IPs:      185.199.1-24.10, 109.205.120.0, 192.168.0.45, 203.0.113.5, 10.0.0.23
Dominios: evil.com, evil1-24.com, fake-domain1-24.com, malicious1-24.com,
          itau-cliente.com, apple-support.com, fakeapple.com,
          silvao.br (spoofado), postsilvao.br, emkei.lv, evilparrot.thm
```

## Aviso

Todos os IOCs sao do laboratorio FIAP. A faixa `185.199.x.x` na vida real pertence ao GitHub Pages — validar contexto antes de aplicar bloqueios em producao.
