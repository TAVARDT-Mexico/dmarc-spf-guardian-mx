#!/usr/bin/env python3
import sys
import re
import json
import ssl
import subprocess
import argparse
import urllib.request

def query_txt_records(domain):
    records = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "TAVARDT-Guardian"})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for a in data.get("Answer", []):
                val = a.get("data", "").strip('"')
                if val:
                    records.append(val)
    except Exception:
        pass

    if records:
        return records

    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, timeout=5)
        raw = proc.stdout.decode("latin1", errors="ignore")
        for line in raw.splitlines():
            line_str = line.strip()
            if "text =" in line_str:
                val = line_str.split("text =", 1)[1].strip().strip('"')
                records.append(val)
            elif line_str.startswith('"') and line_str.endswith('"'):
                records.append(line_str.strip('"'))
    except Exception:
        pass

    return records

def parse_dmarc(records):
    for r in records:
        if "v=DMARC1" in r:
            tags = {}
            for part in r.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            return {"raw": r, "tags": tags}
    return None

def parse_spf(records):
    for r in records:
        if r.startswith("v=spf1") or "v=spf1 " in r:
            parts = r.split()
            qual = "none"
            for p in parts:
                if p in ["-all", "~all", "?all", "+all"]:
                    qual = p
            return {"raw": r, "parts": parts, "qualifier": qual}
    return None

def check_dkim(domain, selector):
    query = f"{selector}._domainkey.{domain}"
    records = query_txt_records(query)
    for r in records:
        if "v=DKIM1" in r or "p=" in r:
            return {"found": True, "raw": r, "query": query}
    return {"found": False, "raw": None, "query": query}

def evaluate(dmarc, spf, dkim):
    score = 0
    recs = []

    if not dmarc:
        recs.append("Registro DMARC no encontrado. El dominio no cuenta con protección contra suplantación.")
    else:
        tags = dmarc.get("tags", {})
        p = tags.get("p", "").lower()
        if p == "reject":
            score += 45
        elif p == "quarantine":
            score += 35
            recs.append("Política DMARC en p=quarantine. Se recomienda transicionar a p=reject para máxima seguridad.")
        elif p == "none":
            score += 15
            recs.append("Política DMARC en p=none (únicamente monitoreo). Migre a p=quarantine o p=reject.")
        else:
            recs.append("Política DMARC en p=none (únicamente monitoreo). Migre a p=quarantine o p=reject.")

        if "rua" in tags:
            score += 10
        else:
            recs.append("Etiqueta rua ausente en DMARC. No se recibirán reportes de fallos de autenticación.")

    if not spf:
        recs.append("Registro SPF no encontrado. Servidores no autorizados pueden emitir correos a nombre de su empresa.")
    else:
        qual = spf.get("qualifier", "")
        if qual == "-all":
            score += 30
        elif qual == "~all":
            score += 20
            recs.append("Calificador SPF en ~all (softfail). Migre gradualmente a -all (hardfail).")
        elif qual == "?all":
            score += 10
            recs.append("Calificador SPF en ?all (neutro). Se recomienda configurar -all o ~all.")
        elif qual == "+all":
            score += 0
            recs.append("Calificador SPF en +all. Permite que cualquier servidor en Internet emita correos.")
        else:
            score += 10

    if dkim and dkim.get("found"):
        score += 15
    else:
        recs.append("Registro DKIM no encontrado para el selector verificado.")

    score = min(score, 100)
    if score >= 85:
        status = "En Cumplimiento (Políticas Estrictas Activas)"
    elif score >= 50:
        status = "Atención (Políticas Permisivas o Incompletas)"
    else:
        status = "Crítico (Vulnerable a Phishing y Suplantación)"

    return score, status, recs

def main():
    parser = argparse.ArgumentParser(description="TAVARDT México: Auditor de Seguridad de Correo (DMARC, SPF, DKIM)")
    parser.add_argument("domain", help="Target domain to inspect")
    parser.add_argument("--selector", default="default", help="DKIM selector to verify")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    domain = args.domain.strip()
    dmarc = parse_dmarc(query_txt_records(f"_dmarc.{domain}"))
    spf = parse_spf(query_txt_records(domain))
    dkim = check_dkim(domain, args.selector)
    score, status, recs = evaluate(dmarc, spf, dkim)

    if args.json:
        payload = {
            "domain": domain,
            "security_score": score,
            "status": status,
            "dmarc": dmarc,
            "spf": spf,
            "dkim": dkim,
            "recommendations": recs
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    border = "=" * 76
    print(border)
    print(f" TAVARDT MÉXICO: AUDITOR DE SEGURIDAD DE CORREO (DMARC, SPF, DKIM)")
    print(border)
    print(f" Domain: {domain}")
    print(f" Puntuación de Seguridad: {score}/100")
    print(f" Diagnóstico General: {status}")
    print("-" * 76)
    print(f" Registro DMARC: {dmarc['raw'] if dmarc else 'N/A'}")
    print(f" Registro SPF: {spf['raw'] if spf else 'N/A'}")
    print(f" Registro DKIM ({args.selector}): {dkim['raw'] if dkim.get('found') else 'N/A'}")
    print("-" * 76)
    print(f" Recomendaciones Técnicas:")
    if recs:
        for r in recs:
            print(f"   * {r}")
    else:
        print(f"   * Configuração robusta. Nenhuma vulnerabilidade crítica identificada.")
    print(border)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python guardian.py <domain> [--selector <name>] [--json]")
        sys.exit(1)
    main()
