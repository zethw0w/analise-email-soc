"""
Analisador de e-mails .eml para triagem SOC.

Lê todos os .eml do dataset, extrai headers e IOCs, e gera CSV.
"""

from __future__ import annotations

import csv
import email
import re
from email import policy
from pathlib import Path
from typing import Iterable

DATASET_DIRS = [
    Path(r"c:/Users/erick/Downloads/Download 2026-04-23T14-31-13-335Z"),
    Path(r"c:/Users/erick/Downloads/Download 2026-04-23T14-31-13-335Z/email_lab_dataset"),
]
OUT_CSV = Path(__file__).parent / "analise_emails_iocs.csv"

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def iter_eml_files() -> Iterable[Path]:
    for d in DATASET_DIRS:
        if not d.exists():
            continue
        for p in sorted(d.glob("*.eml")):
            yield p


def get_auth_results(msg) -> dict[str, str]:
    """Extrai SPF/DKIM/DMARC de Authentication-Results e Received-SPF."""
    out = {"spf": "", "dkim": "", "dmarc": ""}
    raw = "\n".join(msg.get_all("Authentication-Results", []) or [])
    raw += "\n" + "\n".join(msg.get_all("Received-SPF", []) or [])
    raw += "\n" + "\n".join(msg.get_all("ARC-Authentication-Results", []) or [])
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{key}\s*=\s*([a-zA-Z]+)", raw, re.IGNORECASE)
        if m:
            out[key] = m.group(1).lower()
    return out


def get_origin_ip(msg) -> str:
    """Pega o primeiro IP da cadeia Received (mais antigo = origem)."""
    received = msg.get_all("Received", []) or []
    if not received:
        return ""
    candidates: list[str] = []
    for r in received:
        for ip in IP_RE.findall(r):
            if not ip.startswith(("127.", "0.")):
                candidates.append(ip)
    return candidates[-1] if candidates else ""


def get_body_text(msg) -> str:
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="replace"))
    else:
        try:
            parts.append(msg.get_content())
        except Exception:
            payload = msg.get_payload(decode=True)
            if payload:
                parts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(parts)


DANGEROUS_EXT = (".htm", ".html", ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd",
                 ".jar", ".lnk", ".iso", ".docm", ".xlsm", ".pptm", ".hta")


def classify(spf: str, dkim: str, dmarc: str, has_attach: bool, dangerous: bool) -> str:
    auth_failed = any(v in ("fail", "softfail") for v in (spf, dkim, dmarc))
    auth_pass = spf == "pass" and dkim == "pass" and dmarc == "pass"
    if dangerous:
        return "Malicioso (Phishing + Malware)"
    if auth_pass and not has_attach:
        return "Legitimo"
    if auth_failed:
        return "Malicioso (Phishing/Spoofing)"
    if has_attach:
        return "Suspeito (anexo)"
    return "Suspeito"


def has_attachment(msg) -> tuple[bool, bool]:
    """Retorna (tem_anexo, anexo_perigoso)."""
    if not msg.is_multipart():
        return False, False
    has = False
    danger = False
    for part in msg.walk():
        disp = (part.get("Content-Disposition") or "").lower()
        fname = (part.get_filename() or "").lower()
        if "attachment" in disp or fname:
            has = True
            if any(fname.endswith(ext) for ext in DANGEROUS_EXT):
                danger = True
    return has, danger


def parse_gmail_dump(path: Path) -> dict | None:
    """Trata arquivos no formato 'Original Message' (export show-original do Gmail)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.lstrip().startswith("Original Message"):
        return None
    head = text.split("\n\n", 1)[0]

    def grab(label: str) -> str:
        m = re.search(rf"{label}\s*[:\t]\s*(.+)", head, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    spf_line = grab("SPF")
    dkim_line = grab("DKIM")
    dmarc_line = grab("DMARC")

    def status(line: str) -> str:
        m = re.search(r"\b(pass|fail|softfail|none|neutral)\b", line, re.IGNORECASE)
        return m.group(1).lower() if m else ""

    ip = ""
    m = re.search(r"IP\s+(\d{1,3}(?:\.\d{1,3}){3})", spf_line)
    if m:
        ip = m.group(1)

    return {
        "from": grab("From"),
        "return_path": "",
        "reply_to": "",
        "subject": grab("Subject"),
        "date": grab("Created at"),
        "ip_origem": ip,
        "spf": status(spf_line),
        "dkim": status(dkim_line),
        "dmarc": status(dmarc_line),
        "anexo": "nao",
        "urls": "",
    }


def analyze(path: Path) -> dict:
    gmail_dump = parse_gmail_dump(path)
    if gmail_dump is not None:
        c = classify(gmail_dump["spf"], gmail_dump["dkim"], gmail_dump["dmarc"],
                     False, False)
        return {"arquivo": path.name, **gmail_dump, "classificacao": c}

    with path.open("rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    sender = str(msg.get("From", "")).strip()
    return_path = str(msg.get("Return-Path", "")).strip()
    subject = str(msg.get("Subject", "")).strip()
    date = str(msg.get("Date", "")).strip()

    auth = get_auth_results(msg)
    ip = get_origin_ip(msg)

    body = get_body_text(msg)
    urls = sorted(set(URL_RE.findall(body)))
    attach, dangerous = has_attachment(msg)

    reply_to = str(msg.get("Reply-To", "")).strip()

    classification = classify(auth["spf"], auth["dkim"], auth["dmarc"], attach, dangerous)

    return {
        "arquivo": path.name,
        "from": sender,
        "return_path": return_path,
        "reply_to": reply_to,
        "subject": subject,
        "date": date,
        "ip_origem": ip,
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "anexo": "sim" if attach else "nao",
        "urls": " | ".join(urls),
        "classificacao": classification,
    }


def main() -> None:
    rows = [analyze(p) for p in iter_eml_files()]
    if not rows:
        print("Nenhum .eml encontrado.")
        return

    fieldnames = list(rows[0].keys())
    with OUT_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"OK: {len(rows)} e-mails analisados -> {OUT_CSV}")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["classificacao"]] = counts.get(r["classificacao"], 0) + 1
    for k, v in counts.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
