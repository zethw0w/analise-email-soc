"""Gera o PDF do relatorio de investigacao a partir do CSV."""

from __future__ import annotations

import csv
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

BASE = Path(__file__).parent
CSV_FILE = BASE / "analise_emails_iocs.csv"
PDF_FILE = BASE / "relatorio_investigacao_email.pdf"


def styles() -> dict:
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(
        name="Body", parent=s["BodyText"],
        alignment=TA_JUSTIFY, fontSize=10, leading=14, spaceAfter=6,
    ))
    s.add(ParagraphStyle(
        name="H1custom", parent=s["Heading1"],
        textColor=colors.HexColor("#0B3D91"), spaceAfter=10,
    ))
    s.add(ParagraphStyle(
        name="H2custom", parent=s["Heading2"],
        textColor=colors.HexColor("#0B3D91"), spaceBefore=14, spaceAfter=6,
    ))
    s.add(ParagraphStyle(
        name="CodeBlock", parent=s["BodyText"],
        fontName="Courier", fontSize=8.5, leading=11, leftIndent=12,
        backColor=colors.HexColor("#F2F2F2"), spaceAfter=8,
    ))
    s.add(ParagraphStyle(
        name="StepHead", parent=s["Heading3"],
        textColor=colors.HexColor("#1F4E79"), spaceBefore=8, spaceAfter=4,
    ))
    return s


def load_rows() -> list[dict]:
    with CSV_FILE.open("r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def summary_table(rows: list[dict], st) -> Table:
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["classificacao"]] = counts.get(r["classificacao"], 0) + 1
    data = [["Classificação", "Quantidade"]]
    for k in sorted(counts):
        data.append([k, str(counts[k])])
    data.append(["TOTAL", str(len(rows))])
    t = Table(data, colWidths=[10 * cm, 4 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B3D91")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#FFD966")),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2),
         [colors.white, colors.HexColor("#F4F6FB")]),
    ]))
    return t


def emails_table(rows: list[dict]) -> Table:
    data = [["#", "Arquivo", "From", "IP", "SPF", "DKIM", "DMARC", "Classificação"]]
    for i, r in enumerate(rows, 1):
        sender = r["from"][:35] + "…" if len(r["from"]) > 36 else r["from"]
        cls = r["classificacao"]
        if "Malware" in cls:
            cls_short = "Phish+Malware"
        elif "Legitimo" in cls:
            cls_short = "Legitimo"
        elif "Phishing" in cls:
            cls_short = "Phishing"
        else:
            cls_short = cls
        data.append([
            str(i), r["arquivo"], sender or "-", r["ip_origem"] or "-",
            r["spf"] or "-", r["dkim"] or "-", r["dmarc"] or "-", cls_short,
        ])
    t = Table(data, colWidths=[0.7 * cm, 3.2 * cm, 5.2 * cm, 2.6 * cm,
                               1.2 * cm, 1.2 * cm, 1.4 * cm, 2.7 * cm],
              repeatRows=1)
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B3D91")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("FONTSIZE", (0, 1), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 1), (0, -1), "CENTER"),
        ("ALIGN", (4, 1), (6, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#F4F6FB")]),
    ])
    for i, r in enumerate(rows, 1):
        cls = r["classificacao"]
        if "Malware" in cls:
            style.add("BACKGROUND", (-1, i), (-1, i), colors.HexColor("#C00000"))
            style.add("TEXTCOLOR", (-1, i), (-1, i), colors.white)
        elif "Legitimo" in cls:
            style.add("BACKGROUND", (-1, i), (-1, i), colors.HexColor("#548235"))
            style.add("TEXTCOLOR", (-1, i), (-1, i), colors.white)
        elif "Phishing" in cls or "Spoof" in cls:
            style.add("BACKGROUND", (-1, i), (-1, i), colors.HexColor("#ED7D31"))
            style.add("TEXTCOLOR", (-1, i), (-1, i), colors.white)
    t.setStyle(style)
    return t


def iocs_table() -> Table:
    data = [
        ["Tipo", "IOC", "Origem"],
        ["IP", "185.199.1.10 a 185.199.24.10", "email_1 a email_24"],
        ["IP", "109.205.120.0", "caso1.eml (emkei.lv)"],
        ["IP", "192.168.0.45 (RFC1918)", "e-mail_estudo_de_caso.eml"],
        ["IP", "203.0.113.5 (TEST-NET)", "header_fake.eml"],
        ["IP", "10.0.0.23 (RFC1918)", "header_fake.eml (interno)"],
        ["Domínio", "evil.com / evil1-24.com", "email_1 a email_24 (Return-Path)"],
        ["Domínio", "fake-domain1-24.com", "email_1 a email_24 (From)"],
        ["Domínio", "malicious1-24.com", "email_1 a email_24 (URL)"],
        ["Domínio", "itau-cliente.com", "Typosquatting Itaú"],
        ["Domínio", "apple-support.com / fakeapple.com", "Typosquatting Apple"],
        ["Domínio", "silvao.br / postsilvao.br", "Spoof SilvaoPost"],
        ["Domínio", "emkei.lv", "Mailer público anônimo"],
        ["Domínio", "evilparrot.thm", "Credential harvester (caso1)"],
        ["Subject", "Urgent Action Required #*", "Padrão massivo"],
        ["Subject", "URGENTE: Revalidação de Token", "Itaú spoof"],
        ["Subject", "URGENT: SilvaoPost Account Update", "caso1.eml"],
        ["Subject", "[Alerta de segurança] Apple", "header_fake.eml"],
    ]
    t = Table(data, colWidths=[2.5 * cm, 8 * cm, 6.5 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#C00000")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#FBE5D6")]),
    ]))
    return t


def build_pdf() -> None:
    rows = load_rows()
    s = styles()
    doc = SimpleDocTemplate(
        str(PDF_FILE), pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title="Relatório SOC — Análise de E-mail Malicioso",
        author="Eric Kinoshita",
    )
    story: list = []

    story.append(Paragraph("Relatório de Investigação SOC", s["H1custom"]))
    story.append(Paragraph("Análise de E-mails Maliciosos — Dataset email_lab_dataset",
                           s["Heading2"]))
    story.append(Paragraph("<b>Analista:</b> Eric Kinoshita &nbsp;&nbsp;|&nbsp;&nbsp; "
                           "<b>Data:</b> 2026-05-04 &nbsp;&nbsp;|&nbsp;&nbsp; "
                           "<b>Total de amostras:</b> 28 .eml", s["Body"]))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("1. Sumário Executivo", s["H2custom"]))
    story.append(Paragraph(
        "Foram analisados <b>28 e-mails</b> em formato <i>.eml</i>, coletados de um "
        "dataset de laboratório. A análise envolveu inspeção manual de cabeçalhos, "
        "validação de SPF/DKIM/DMARC, extração de URLs e identificação de anexos. "
        "Dos 28 e-mails: <b>27 são maliciosos</b> (26 phishing/spoofing e 1 com "
        "anexo malware) e <b>1 é legítimo</b> (controle, Proton Mail). A campanha "
        "demonstra técnicas combinadas de spoofing de marca, typosquatting de domínio "
        "e linguagem de urgência.", s["Body"]))
    story.append(summary_table(rows, s))
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("2. Metodologia — Passo a Passo da Investigação",
                           s["H2custom"]))

    steps = [
        ("Passo 1 — Coleta e preservação",
         "Os arquivos foram extraídos do ZIP <i>email_lab_dataset.zip</i> "
         "(senha: <b>blueTeam</b>) e mantidos em pasta isolada <i>read-only</i>. "
         "Nenhum link ou anexo foi executado; toda análise é estática."),
        ("Passo 2 — Triagem inicial (SOC N1)",
         "Para cada <i>.eml</i> verificamos: (a) coerência entre <b>From</b> e "
         "<b>Return-Path</b>; (b) presença de linguagem de urgência no <b>Subject</b>; "
         "(c) qualidade visual do remetente (typosquatting). E-mails que falham em "
         "qualquer um destes pontos vão para análise técnica."),
        ("Passo 3 — Análise técnica de cabeçalho (SOC N2)",
         "Inspeção da cadeia <b>Received</b> (de baixo para cima = origem real até "
         "destino) e do bloco <b>Authentication-Results</b>. Critérios: "
         "<b>SPF=fail/softfail</b>, <b>DKIM=fail/none</b>, <b>DMARC=fail</b> indicam "
         "spoofing. IPs em faixas RFC1918 (10/8, 172.16/12, 192.168/16) ou "
         "TEST-NET (192.0.2/24, 198.51.100/24, 203.0.113/24) em servidores "
         "públicos são impossíveis e confirmam forja."),
        ("Passo 4 — Análise de URL",
         "URLs do corpo HTML são extraídas via regex e o <b>domínio efetivo</b> "
         "(eTLD+1) é avaliado da direita para a esquerda. Exemplo: em "
         "<i>secure-login.microsoft.verify-user.ru</i>, o domínio real é "
         "<i>verify-user.ru</i> — tudo antes é subdomínio sob controle do atacante."),
        ("Passo 5 — Análise de anexo (SOC N2/N3)",
         "Anexos são identificados via <b>Content-Disposition: attachment</b>. "
         "Extensões perigosas (.htm, .html, .exe, .scr, .js, .vbs, .hta, "
         ".docm, .xlsm, .lnk) elevam para classificação <b>malware</b>. No caso "
         "<i>caso1.eml</i>, o anexo <i>SilvaoPostACTIONREQUIRED.htm</i> em base64 "
         "contém JavaScript que decodifica e injeta um formulário falso de "
         "captura de credenciais (<i>document.write(unescape(atob(b64)))</i>)."),
        ("Passo 6 — Consolidação de IOCs",
         "Indicadores extraídos (IPs, domínios, padrões de subject) são compilados "
         "para alimentar regras de bloqueio em firewall, proxy, SIEM e mail "
         "gateway, conforme tabela na seção 5."),
        ("Passo 7 — Resposta e contenção (SOC N3 / IR)",
         "Ações recomendadas: (1) quarentena dos e-mails ativos via "
         "<i>Compliance Search</i> (M365) ou equivalente; (2) bloqueio de IPs e "
         "domínios; (3) reset de credenciais e revogação de tokens MFA dos "
         "usuários que clicaram; (4) varredura EDR nos endpoints expostos; "
         "(5) ativação de DMARC <b>p=reject</b> no domínio próprio para impedir "
         "spoofing inverso."),
    ]
    for title, body in steps:
        story.append(Paragraph(title, s["StepHead"]))
        story.append(Paragraph(body, s["Body"]))

    story.append(PageBreak())
    story.append(Paragraph("3. Tabela Completa de E-mails Analisados", s["H2custom"]))
    story.append(Paragraph(
        "Resultado da execução do script <i>analyze_emails.py</i> sobre o dataset. "
        "Cores: <font color='#C00000'><b>vermelho</b></font> = phishing+malware, "
        "<font color='#ED7D31'><b>laranja</b></font> = phishing/spoofing, "
        "<font color='#548235'><b>verde</b></font> = legítimo.", s["Body"]))
    story.append(emails_table(rows))

    story.append(PageBreak())
    story.append(Paragraph("4. Achados de Destaque", s["H2custom"]))

    story.append(Paragraph("4.1. caso1.eml — Phishing com Credential Harvester",
                           s["StepHead"]))
    story.append(Paragraph(
        "E-mail spoofando <b>SilvaoPost</b> (silvao.br), enviado pelo serviço "
        "público <b>emkei.lv</b> (109.205.120.0) — comum para fraudes anônimas. "
        "Reply-To aponta para <i>postsilvao.br</i>, não para o From, capturando "
        "respostas em domínio do atacante. Anexo <i>.htm</i> em base64 decodifica "
        "para JS que escreve formulário falso e envia credenciais via POST. "
        "Header customizado <i>X-Custom-Header: RklBUHtlYXN5X2hlYWRlcnN9Cg==</i> "
        "decodifica em base64 para a flag <b>FIAP{easy_headers}</b>.", s["Body"]))

    story.append(Paragraph("4.2. e-mail_estudo_de_caso.eml — Itaú Spoof",
                           s["StepHead"]))
    story.append(Paragraph(
        "Falsifica o Banco Itaú via typosquatting <b>itau-cliente.com</b>. "
        "A linha <i>Received</i> registra origem <b>192.168.0.45</b> — IP "
        "privado (RFC 1918) que jamais aparece em tráfego SMTP legítimo na "
        "internet pública. SPF=fail e DKIM=fail confirmam.", s["Body"]))

    story.append(Paragraph("4.3. header_fake.eml — Apple Spoof",
                           s["StepHead"]))
    story.append(Paragraph(
        "Spoof Apple via <b>apple-support.com</b> + <b>mail.fakeapple.com</b>. "
        "IP <b>203.0.113.5</b> pertence à faixa <b>TEST-NET-3 (RFC 5737)</b>, "
        "reservada para documentação — qualquer e-mail com origem nessa faixa "
        "é, por definição, forjado. SPF=softfail, DKIM=fail.", s["Body"]))

    story.append(Paragraph("4.4. email_1 a email_24 — Campanha em massa",
                           s["StepHead"]))
    story.append(Paragraph(
        "24 e-mails idênticos em padrão, variando apenas o índice N. From "
        "<i>support{N}@fake-domain{N}.com</i>, Return-Path "
        "<i>attacker{N}@evil.com</i>, IP <i>185.199.{N}.10</i>, URL "
        "<i>http://malicious{N}.com/login</i>. Todos com SPF=fail, DKIM=none, "
        "DMARC=fail. Caracteriza simulação de campanha automatizada para "
        "treinamento de detecção em volume.", s["Body"]))

    story.append(Paragraph("4.5. secreto.eml — Controle (legítimo)",
                           s["StepHead"]))
    story.append(Paragraph(
        "Único e-mail legítimo do dataset. Enviado via Proton Mail "
        "(185.70.43.24), com SPF=pass, DKIM=pass, DMARC=pass, ARC-Seal "
        "validado pelo Google. Serve de baseline para comparação com as "
        "demais amostras.", s["Body"]))

    story.append(PageBreak())
    story.append(Paragraph("5. IOCs Consolidados", s["H2custom"]))
    story.append(Paragraph(
        "Lista pronta para importação em SIEM, firewall, proxy ou plataformas "
        "de Threat Intelligence. Recomenda-se validar IPs antes de aplicar em "
        "produção (a faixa 185.199.x.x na vida real pertence ao GitHub "
        "Pages — neste laboratório é fictícia).", s["Body"]))
    story.append(iocs_table())

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("6. Query de Detecção (Splunk)", s["H2custom"]))
    splunk = (
        "index=email sourcetype=mail<br/>"
        "| eval auth_failed=if(<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;match(spf,\"fail\") OR<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;match(dkim,\"fail\") OR<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;match(dmarc,\"fail\"), 1, 0)<br/>"
        "| eval suspicious_subject=if(<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;match(Subject,\"(?i)urgent|urgente|alerta|"
        "verify|invoice|payment|token|bloquear\"), 1, 0)<br/>"
        "| where auth_failed=1 OR suspicious_subject=1<br/>"
        "| stats count BY sender, src_ip, recipient<br/>"
        "| sort - count"
    )
    story.append(Paragraph(splunk, s["CodeBlock"]))

    story.append(Paragraph("7. Conclusão", s["H2custom"]))
    story.append(Paragraph(
        "O dataset confirma os principais vetores de phishing observados em "
        "ambientes corporativos: <b>autenticação SMTP ausente ou falhando</b>, "
        "<b>typosquatting de marcas confiáveis</b>, <b>linguagem de urgência</b> "
        "e <b>credential harvesters</b> entregues como anexo HTML. A defesa "
        "efetiva exige camadas combinadas: políticas DMARC restritivas, "
        "sandbox de anexos, treinamento de usuários e bloqueio proativo dos "
        "IOCs identificados. O modelo de classificação aplicado neste relatório "
        "(SPF/DKIM/DMARC + análise de domínio + inspeção de anexo) acertou "
        "100% das 28 amostras quando confrontado com a inspeção manual.",
        s["Body"]))

    doc.build(story)
    print(f"OK: PDF gerado -> {PDF_FILE}")


if __name__ == "__main__":
    build_pdf()
