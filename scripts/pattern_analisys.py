#!/usr/bin/env python3
import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import yaml

WS_RE = re.compile(r"\s+")


def sniff_delimiter(path: Path) -> str:
    """Try to detect CSV delimiter from first bytes."""
    raw = path.read_bytes()
    # try decode with utf-8-sig to drop BOM
    text = raw.decode("utf-8-sig", errors="replace")
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        # fallback: heuristic counts
        counts = {d: sample.count(d) for d in [",", ";", "\t", "|"]}
        return max(counts, key=counts.get) if max(counts.values()) > 0 else ","


def normalize_colname(s: str) -> str:
    # remove BOM, quotes, extra spaces, lower
    s = s.replace("\ufeff", "").strip().strip('"').strip("'").strip()
    s = re.sub(r"\s+", " ", s)
    return s.lower()


def preprocess_text(
    text: str,
    lowercase: bool = True,
    ignore_square_brackets: bool = True,
    square_bracket_regex: str = r"\[[^\]]*\]",
) -> str:
    if text is None:
        text = ""
    if ignore_square_brackets:
        text = re.sub(square_bracket_regex, " ", text)
    if lowercase:
        text = text.lower()
    text = WS_RE.sub(" ", text).strip()
    return text


def keyword_to_regex(keyword: str) -> re.Pattern:
    """
    Convert keyword/phrase to a boundary-aware regex.
    Example:
      "login"  -> \\blogin\\b
      "log in" -> \\blog\\s+in\\b
    """
    k = keyword.strip()
    if not k:
        return re.compile(r"(?!x)x")  # never match
    parts = [re.escape(p) for p in k.split()]
    if len(parts) == 1:
        pat = r"\b" + parts[0] + r"\b"
    else:
        pat = r"\b" + r"\s+".join(parts) + r"\b"
    return re.compile(pat, re.IGNORECASE)


@dataclass
class CategoryPatterns:
    cat_id: str
    keyword_res: List[re.Pattern]
    regex_res: List[re.Pattern]


def load_patterns_yaml(patterns_path: Path) -> Tuple[Dict[str, Any], List[CategoryPatterns]]:
    data = yaml.safe_load(patterns_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("patterns.yaml: invalid root structure (expected mapping/dict)")

    preprocessing = data.get("preprocessing", {}) or {}
    categories = data.get("categories", [])
    if not isinstance(categories, list) or not categories:
        raise ValueError("patterns.yaml: missing/empty 'categories' list")

    compiled: List[CategoryPatterns] = []
    for c in categories:
        if not isinstance(c, dict):
            continue
        cat_id = c.get("id")
        if not cat_id:
            raise ValueError("patterns.yaml: every category must have a non-empty 'id'")

        keywords = c.get("keywords", []) or []
        regexes = c.get("regex", []) or []

        kw_res = [keyword_to_regex(k) for k in keywords if isinstance(k, str) and k.strip()]
        rx_res = [re.compile(r, re.IGNORECASE) for r in regexes if isinstance(r, str) and r.strip()]

        compiled.append(CategoryPatterns(cat_id=str(cat_id), keyword_res=kw_res, regex_res=rx_res))

    return preprocessing, compiled


def read_txt_for_row(txt_dir: Path, numero_cell: str, source_file: Optional[str]) -> str:
    """
    If numero is '0010' read 0010.txt.
    If numero is '10' -> zfill to 4 -> 0010.txt
    Fallback: try source_file (if it already contains .txt).
    """
    nraw = str(numero_cell).strip()

    digits = re.sub(r"\D", "", nraw)
    if digits:
        digits = digits.zfill(4)[-4:]
        p = txt_dir / f"{digits}.txt"
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace")

    if source_file:
        sf = str(source_file).strip()
        p2 = txt_dir / sf
        if p2.exists():
            return p2.read_text(encoding="utf-8", errors="replace")
        if not sf.lower().endswith(".txt"):
            p3 = txt_dir / (sf + ".txt")
            if p3.exists():
                return p3.read_text(encoding="utf-8", errors="replace")

    raise FileNotFoundError(f"TXT not found for numero='{numero_cell}' (source_file='{source_file}') in {txt_dir}")


def compute_hits(text: str, cat: CategoryPatterns) -> int:
    hits = 0
    for r in cat.keyword_res:
        hits += len(r.findall(text))
    for r in cat.regex_res:
        hits += len(r.findall(text))
    return hits


def build_groups(df: pd.DataFrame) -> Dict[str, pd.Series]:
    """
    Build boolean masks for statistics.

    Requested groupings:
      - phishing / non-phishing
      - manual / ai   (ai := ai-generated OR llama3 OR mistral)
      - phishing+manual / phishing+ai
    """
    cls = df["class"].astype(str).str.lower().str.strip()
    origin = df["origin"].astype(str).str.lower().str.strip()

    phishing = cls.eq("phishing")
    non_phishing = cls.isin(["non-phishing", "nonphishing", "ham", "legit", "legitimate", "0", "false", "no"])

    manual = (
        origin.str.contains(r"\bmanual\b", regex=True)
        | origin.eq("manuale")
        | origin.eq("m")
    )

    ai_generated = origin.str.contains(r"ai[-_ ]?generated", regex=True) | origin.eq("ai")
    llama3 = origin.str.contains("llama3", regex=False)
    mistral = origin.str.contains("mistral", regex=False)

    ai = ai_generated | llama3 | mistral

    return {
        "phishing": phishing,
        "non-phishing": non_phishing,
        "manual": manual,
        "ai": ai,
        "phishing_manual": phishing & manual,
        "phishing_ai": phishing & ai,
    }


def coerce_required_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Try to map existing columns to required ones:
    numero, class, origin, source_file, row_idx
    """
    # normalize current columns
    col_map = {c: normalize_colname(c) for c in df.columns}
    inv = {}
    for orig, norm in col_map.items():
        inv.setdefault(norm, orig)

    def find_col(candidates: List[str]) -> Optional[str]:
        for cand in candidates:
            cand = normalize_colname(cand)
            if cand in inv:
                return inv[cand]
        return None

    # candidate synonyms
    col_num = find_col(["numero", "number", "id", "file_id", "mail_id", "index"])
    col_class = find_col(["class", "label", "y", "target", "category"])
    col_origin = find_col(["origin", "source", "generator", "engine", "model"])
    col_source_file = find_col(["source_file", "file", "filename", "txt_file", "sourcefile"])
    col_row_idx = find_col(["row_idx", "row", "rowid", "row_index", "csv_row", "idx"])

    missing = []
    if col_num is None: missing.append("numero")
    if col_class is None: missing.append("class")
    if col_origin is None: missing.append("origin")
    if col_source_file is None: missing.append("source_file")
    if col_row_idx is None: missing.append("row_idx")

    if missing:
        raise SystemExit(
            f"report.csv missing columns: {missing}\n"
            f"Columns found: {list(df.columns)}\n"
            f"Tip: check delimiter/headers or rename columns to: numero,class,origin,source_file,row_idx"
        )

    out = df.rename(columns={
        col_num: "numero",
        col_class: "class",
        col_origin: "origin",
        col_source_file: "source_file",
        col_row_idx: "row_idx",
    }).copy()

    # Ensure required columns exist as strings
    for c in ["numero", "class", "origin", "source_file", "row_idx"]:
        out[c] = out[c].astype(str).fillna("")
    return out


def main():
    ap = argparse.ArgumentParser(description="Pattern analysis over report.csv + txt corpus (YAML patterns)")
    ap.add_argument("--report", required=True, help="Input report.csv")
    ap.add_argument("--txt-dir", required=True, help="Directory containing .txt emails (e.g., 0010.txt)")
    ap.add_argument("--patterns", required=True, help="patterns.yaml file")
    ap.add_argument("--out-dir", default=".", help="Output directory")
    args = ap.parse_args()

    report_path = Path(args.report).expanduser().resolve()
    txt_dir = Path(args.txt_dir).expanduser().resolve()
    patterns_path = Path(args.patterns).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not report_path.exists():
        raise SystemExit(f"Missing report file: {report_path}")
    if not txt_dir.exists() or not txt_dir.is_dir():
        raise SystemExit(f"Invalid txt directory: {txt_dir}")
    if not patterns_path.exists():
        raise SystemExit(f"Missing patterns file: {patterns_path}")

    preprocessing, cats = load_patterns_yaml(patterns_path)
    lowercase = bool(preprocessing.get("lowercase", True))
    ignore_sq = bool(preprocessing.get("ignore_square_bracket_placeholders", True))
    square_bracket_regex = preprocessing.get("square_bracket_regex", r"\[[^\]]*\]")

    delim = sniff_delimiter(report_path)
    df_raw = pd.read_csv(
        report_path,
        dtype=str,
        keep_default_na=False,
        sep=delim,
        engine="python",
        encoding="utf-8-sig",
    )

    df = coerce_required_columns(df_raw)

    # Create per-category columns
    for cat in cats:
        df[f"presence_{cat.cat_id}"] = 0
        df[f"hit_count_{cat.cat_id}"] = 0

    # Process rows
    for idx, row in df.iterrows():
        raw_txt = read_txt_for_row(txt_dir, row["numero"], row["source_file"])
        pre_txt = preprocess_text(
            raw_txt,
            lowercase=lowercase,
            ignore_square_brackets=ignore_sq,
            square_bracket_regex=square_bracket_regex,
        )
        for cat in cats:
            hits = compute_hits(pre_txt, cat)
            df.at[idx, f"hit_count_{cat.cat_id}"] = hits
            df.at[idx, f"presence_{cat.cat_id}"] = 1 if hits > 0 else 0

    # Save analysis_report.csv
    analysis_report_path = out_dir / "analysis_report.csv"
    df.to_csv(analysis_report_path, index=False, quoting=csv.QUOTE_ALL)

    # Stats per group
    groups = build_groups(df)
    cat_ids = [c.cat_id for c in cats]

    def to_num(s: pd.Series) -> pd.Series:
        return pd.to_numeric(s, errors="coerce").fillna(0.0)

    rows_stats: List[Dict[str, Any]] = []
    for gname, mask in groups.items():
        gdf = df[mask].copy()
        n = len(gdf)

        if n == 0:
            rows_stats.append({
                "group": gname,
                "n_emails": 0,
                "category": "__SUMMARY__",
                "presence_rate_pct": 0.0,
                "mean_hit_count": 0.0,
                "hit_share_pct": 0.0,
                "top_by_presence": "",
                "top_by_mean_hits": "",
            })
            continue

        total_hits_group = 0.0
        for cat_id in cat_ids:
            total_hits_group += float(to_num(gdf[f"hit_count_{cat_id}"]).sum())

        per_cat_tmp = []
        for cat_id in cat_ids:
            pres = to_num(gdf[f"presence_{cat_id}"])
            hits = to_num(gdf[f"hit_count_{cat_id}"])

            presence_rate_pct = float(pres.mean() * 100.0)
            mean_hit_count = float(hits.mean())
            cat_total_hits = float(hits.sum())
            hit_share_pct = float((cat_total_hits / total_hits_group) * 100.0) if total_hits_group > 0 else 0.0

            per_cat_tmp.append((cat_id, presence_rate_pct, mean_hit_count))

            rows_stats.append({
                "group": gname,
                "n_emails": n,
                "category": cat_id,
                "presence_rate_pct": f"{presence_rate_pct:.2f}".replace(".", ","),
                "mean_hit_count": f"{mean_hit_count:.2f}".replace(".", ","),
                "hit_share_pct": f"{hit_share_pct:.2f}".replace(".", ","),
                "top_by_presence": "",
                "top_by_mean_hits": "",
            })

        top_by_presence = max(per_cat_tmp, key=lambda x: x[1])[0]
        top_by_mean_hits = max(per_cat_tmp, key=lambda x: x[2])[0]

        rows_stats.append({
            "group": gname,
            "n_emails": n,
            "category": "__SUMMARY__",
            "presence_rate_pct": "",
            "mean_hit_count": "",
            "hit_share_pct": "",
            "top_by_presence": top_by_presence,
            "top_by_mean_hits": top_by_mean_hits,
        })

    stats_df = pd.DataFrame(rows_stats)
    analysis_stats_path = out_dir / "analysis_stats.csv"
    stats_df.to_csv(analysis_stats_path, index=False, quoting=csv.QUOTE_ALL)

    print("OK:")
    print(" -", analysis_report_path)
    print(" -", analysis_stats_path)
    print(f"\nCSV delimiter detected: '{delim}'")
    print("Placeholders [ ... ] are removed before matching.")


if __name__ == "__main__":
    main()
