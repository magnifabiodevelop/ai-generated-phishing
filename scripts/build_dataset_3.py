#!/usr/bin/env python3
import csv
import hashlib
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import pandas as pd
from bs4 import BeautifulSoup


# -------------------------
# Config / Regex sanitizzazione
# -------------------------
RE_URL = re.compile(r"\bhttps?://\S+|\bwww\.\S+", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", re.IGNORECASE)
RE_IBAN_IT = re.compile(r"\bIT\d{2}[A-Z]\d{10}[0-9A-Z]{12}\b", re.IGNORECASE)
RE_PHONE = re.compile(r"\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{5,}\b")
RE_LONGNUM = re.compile(r"\b\d{5,}\b")
RE_AMOUNT = re.compile(r"(?:(?:€|\$|£)\s?\d[\d\.,]*)|(?:\d[\d\.,]*\s?(?:€|\$|£))")
WS_RE = re.compile(r"[ \t]+")

TEXT_COL_CANDIDATES = ["body", "text", "content", "body_text", "Email Text", "EmailText", "message", "email"]
SUBJECT_COL_CANDIDATES = ["subject", "Subject", "subj", "title"]
LABEL_COL_CANDIDATES = ["label", "Label", "class", "Class", "target", "Target", "y"]

PHISH_VALUES = {"1", "phish", "phishing", "spam", "true", "yes"}
NONPHISH_VALUES = {"0", "ham", "legit", "legitimate", "false", "no", "nonphish", "non-phish", "benign"}

# -------------------------
# Prefissi file (nuovo schema)
# -------------------------
# AI-Generated
PREFIX_AI_PHISH = "A_P_"      # AI phishing
PREFIX_AI_LEGIT = "A_L_"      # AI legit (ham)
# Manual
PREFIX_MAN_PHISH = "M_P_"     # manual phishing
PREFIX_MAN_LEGIT = "M_L_"     # manual legit
PREFIX_MAN_MIX = "M_P_L_"     # manual phishing + legit (serve label)


# -------------------------
# Utilities
# -------------------------
def html_to_text(s: str) -> str:
    if not isinstance(s, str):
        return ""
    # euristica: se contiene tag
    if "<" in s and ">" in s:
        soup = BeautifulSoup(s, "lxml")
        for tag in soup(["script", "style"]):
            tag.decompose()
        return soup.get_text("\n")
    return s


def normalize_ws(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = WS_RE.sub(" ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def sanitize_text(text: str) -> str:
    text = html_to_text(text)
    text = normalize_ws(text)

    # sostituzioni
    text = RE_URL.sub("[URL]", text)
    text = RE_EMAIL.sub("[EMAIL]", text)
    text = RE_IBAN_IT.sub("[IBAN]", text)
    text = RE_AMOUNT.sub("[AMOUNT]", text)
    text = RE_PHONE.sub("[PHONE]", text)
    text = RE_LONGNUM.sub("[NUM]", text)

    return normalize_ws(text)


def pick_col(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    lower_map = {c.lower(): c for c in df.columns}
    for c in candidates:
        if c in df.columns:
            return c
        if c.lower() in lower_map:
            return lower_map[c.lower()]
    return None


def norm_label(v) -> str:
    if pd.isna(v):
        return ""
    return str(v).strip().lower()


def sha16(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


@dataclass
class MailRow:
    origin: str              # "ai" / "manuale"
    cls: str                 # "phishing" / "non-phishing" / "unknown"
    source_file: str
    row_idx: int
    subject: str
    body: str
    hash_norm: str


def build_body(subject: str, body: str) -> str:
    subject = subject.strip()
    body = body.strip()
    if subject:
        return f"Subject: {subject}\n\n{body}"
    return body


def classify_from_label(label_raw: str) -> str:
    if label_raw in PHISH_VALUES:
        return "phishing"
    if label_raw in NONPHISH_VALUES:
        return "non-phishing"
    return "unknown"


# -------------------------
# CSV loading per prefisso
# -------------------------
def load_csv_records(csv_path: Path) -> List[MailRow]:
    name = csv_path.name

    # Determina origin e tipo file in base al prefisso
    if name.startswith(PREFIX_AI_PHISH):
        origin = "ai"
        forced_class = "phishing"
        needs_label = False
    elif name.startswith(PREFIX_AI_LEGIT):
        origin = "ai"
        forced_class = "non-phishing"
        needs_label = False
    elif name.startswith(PREFIX_MAN_MIX):
        origin = "manuale"
        forced_class = None
        needs_label = True
    elif name.startswith(PREFIX_MAN_PHISH):
        origin = "manuale"
        forced_class = "phishing"
        needs_label = False
    elif name.startswith(PREFIX_MAN_LEGIT):
        origin = "manuale"
        forced_class = "non-phishing"
        needs_label = False
    else:
        # file non riconosciuto: lo ignoriamo
        return []

    df = pd.read_csv(csv_path)
    text_col = pick_col(df, TEXT_COL_CANDIDATES)
    if text_col is None:
        raise ValueError(f"[{csv_path}] Nessuna colonna testo trovata. Colonne: {list(df.columns)}")

    subj_col = pick_col(df, SUBJECT_COL_CANDIDATES)
    lbl_col = pick_col(df, LABEL_COL_CANDIDATES) if needs_label else None

    if needs_label and lbl_col is None:
        raise ValueError(f"[{csv_path}] Prefisso {PREFIX_MAN_MIX} ma nessuna colonna label trovata tra {LABEL_COL_CANDIDATES}")

    out: List[MailRow] = []
    for idx, r in df.iterrows():
        subject_raw = str(r.get(subj_col, "")) if subj_col else ""
        body_raw = str(r.get(text_col, ""))

        subject = sanitize_text(subject_raw)
        body = sanitize_text(body_raw)
        if not body:
            continue

        if forced_class is not None:
            cls = forced_class
        else:
            cls = classify_from_label(norm_label(r.get(lbl_col, "")))

        # Normalizza per dedup
        norm = normalize_ws((subject + " " + body).lower())
        h = sha16(norm)

        out.append(
            MailRow(
                origin=origin,
                cls=cls,
                source_file=name,
                row_idx=int(idx),
                subject=subject,
                body=body,
                hash_norm=h,
            )
        )

    # Dedup per hash_norm (per file)
    seen = set()
    deduped = []
    for m in out:
        if m.hash_norm in seen:
            continue
        seen.add(m.hash_norm)
        deduped.append(m)
    return deduped


# -------------------------
# Selezione + Output
# -------------------------
def ask_int(prompt: str, default: Optional[int] = None) -> int:
    while True:
        s = input(f"{prompt}" + (f" [{default}]" if default is not None else "") + ": ").strip()
        if not s and default is not None:
            return default
        try:
            v = int(s)
            if v < 0:
                raise ValueError()
            return v
        except Exception:
            print("Valore non valido. Inserisci un intero >= 0.")


def sample_exact(pool: List[MailRow], n: int, rng: random.Random, what: str) -> List[MailRow]:
    if n <= 0:
        return []
    if len(pool) < n:
        raise RuntimeError(f"Campioni insufficienti per {what}: disponibili {len(pool)} < richiesti {n}")
    return rng.sample(pool, n)


def write_outputs(selected: List[MailRow], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    emails_dir = out_dir / "emails"
    emails_dir.mkdir(parents=True, exist_ok=True)

    report_path = out_dir / "report.csv"
    # CSV SENZA body/text (solo metadati)
    with report_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["numero", "filename", "class", "origin", "source_file", "row_idx"],
            quoting=csv.QUOTE_MINIMAL,
        )
        w.writeheader()

        for i, m in enumerate(selected, start=1):
            filename = f"{i:04d}.txt"
            content = build_body(m.subject, m.body)
            (emails_dir / filename).write_text(content + "\n", encoding="utf-8")

            w.writerow(
                {
                    "numero": f"{i:04d}",
                    "filename": f"{i:04d}.txt",
                    "class": m.cls,        # phishing / non-phishing / unknown
                    "origin": m.origin,    # ai / manuale
                    "source_file": m.source_file,
                    "row_idx": m.row_idx,
                }
            )

    print(f"\nOK: creati {len(selected)} file in {emails_dir}")
    print(f"OK: report CSV creato in {report_path}")


def main():
    print("=== CSV -> MAIL (.txt) + report.csv (senza body; con sanitizzazione) ===")

    in_dir_str = input("Inserisci la cartella dove si trovano i CSV: ").strip()
    in_dir = Path(in_dir_str).expanduser().resolve()
    if not in_dir.exists() or not in_dir.is_dir():
        raise SystemExit(f"Cartella input non valida: {in_dir}")

    csv_files = sorted([p for p in in_dir.glob("*.csv")])
    if not csv_files:
        raise SystemExit("Nessun file .csv trovato nella cartella indicata.")

    recognized_prefixes = (PREFIX_AI_PHISH, PREFIX_AI_LEGIT, PREFIX_MAN_PHISH, PREFIX_MAN_LEGIT, PREFIX_MAN_MIX)

    # Carica tutti i record dai CSV riconosciuti
    all_records: List[MailRow] = []
    used_files = []
    ignored_files = []

    for p in csv_files:
        if p.name.startswith(recognized_prefixes):
            recs = load_csv_records(p)
            all_records.extend(recs)
            used_files.append(p.name)
        else:
            ignored_files.append(p.name)

    if not all_records:
        raise SystemExit(
            "Nessun CSV con prefisso riconosciuto trovato o nessun record valido.\n"
            "Prefissi accettati: A_P_, A_L_, M_P_, M_L_, M_P_L_"
        )

    # Dedup globale
    global_seen = set()
    global_dedup: List[MailRow] = []
    for m in all_records:
        if m.hash_norm in global_seen:
            continue
        global_seen.add(m.hash_norm)
        global_dedup.append(m)
    all_records = global_dedup

    # Pool
    ai_phish = [m for m in all_records if m.origin == "ai" and m.cls == "phishing"]
    ai_legit = [m for m in all_records if m.origin == "ai" and m.cls == "non-phishing"]
    man_phish = [m for m in all_records if m.origin == "manuale" and m.cls == "phishing"]
    man_legit = [m for m in all_records if m.origin == "manuale" and m.cls == "non-phishing"]
    unknown = [m for m in all_records if m.cls == "unknown"]

    print("\n--- File usati ---")
    for f in used_files:
        print("  -", f)
    if ignored_files:
        print("\n--- File ignorati (prefisso non riconosciuto) ---")
        for f in ignored_files:
            print("  -", f)

    print("\n--- Disponibilità dopo lettura + sanitizzazione + dedup ---")
    print(f"AI phishing:          {len(ai_phish)}")
    print(f"AI legit (ham):       {len(ai_legit)}")
    print(f"Manuale phishing:     {len(man_phish)}")
    print(f"Manuale legit (ham):  {len(man_legit)}")
    if unknown:
        print(f"Unknown (non usati):  {len(unknown)}")

    # Quantità richieste (come da specifica)
    total_phish = ask_int("\nQuante mail di PHISHING vuoi generare (totale)", default=50)
    total_legit = ask_int("Quante mail LEGIT (ham) vuoi generare (totale)", default=50)

    ai_phish_n = ask_int("Quante mail AI-GENERATED di PHISHING", default=0)
    ai_legit_n = ask_int("Quante mail AI-GENERATED LEGIT (ham)", default=0)
    man_phish_n = ask_int("Quante mail MANUALI di PHISHING", default=total_phish)
    man_legit_n = ask_int("Quante mail MANUALI LEGIT (ham)", default=total_legit)

    # Coerenza: split deve combaciare coi totali
    if ai_phish_n + man_phish_n != total_phish:
        raise SystemExit(
            f"Errore: totale phishing={total_phish} ma AI({ai_phish_n}) + manual({man_phish_n}) = {ai_phish_n + man_phish_n}."
        )
    if ai_legit_n + man_legit_n != total_legit:
        raise SystemExit(
            f"Errore: totale legit={total_legit} ma AI({ai_legit_n}) + manual({man_legit_n}) = {ai_legit_n + man_legit_n}."
        )

    seed = ask_int("Seed (per estrazione riproducibile)", default=42)

    out_dir_str = input("\nInserisci la cartella di output: ").strip()
    out_dir = Path(out_dir_str).expanduser().resolve()

    rng = random.Random(seed)

    # Selezione
    selected: List[MailRow] = []
    selected.extend(sample_exact(ai_phish, ai_phish_n, rng, "AI phishing"))
    selected.extend(sample_exact(ai_legit, ai_legit_n, rng, "AI legit"))
    selected.extend(sample_exact(man_phish, man_phish_n, rng, "Manuale phishing"))
    selected.extend(sample_exact(man_legit, man_legit_n, rng, "Manuale legit"))

    # Shuffle finale (non lasciare blocchi separati)
    rng.shuffle(selected)

    # Output
    write_outputs(selected, out_dir)

    # Info riepilogo
    print("\n--- Riepilogo output ---")
    print(f"Totale file: {len(selected)}")
    print(f"Phishing: {sum(1 for m in selected if m.cls=='phishing')}")
    print(f"Legit:    {sum(1 for m in selected if m.cls=='non-phishing')}")
    print(f"AI phishing:     {sum(1 for m in selected if m.origin=='ai' and m.cls=='phishing')}")
    print(f"AI legit:        {sum(1 for m in selected if m.origin=='ai' and m.cls=='non-phishing')}")
    print(f"Manuale phishing:{sum(1 for m in selected if m.origin=='manuale' and m.cls=='phishing')}")
    print(f"Manuale legit:   {sum(1 for m in selected if m.origin=='manuale' and m.cls=='non-phishing')}")


if __name__ == "__main__":
    main()
