#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ollama_as_a_judge.py

- Reads a CSV report with fields:
  numero, filename, class, origin, source_file, row_idx
- For each row, reads the corresponding .txt file and queries a local/remote LLM (Ollama or OpenAI-compatible)
  with TWO prompts:
    1) phishing vs non-phishing
    2) manual vs ai-generated vs unknown
- Stores predictions + confidence into an extended report CSV
- Computes success rates (accuracy) for groups:
  phishing, non-phishing, ai, manuale, phishing ai, phishing manuale
- Shows a live progress/status line that updates BEFORE each call:
  - file being processed
  - stage (loading / judge: phishing / judge: origin / done)
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List

import requests

# -----------------------------
# Default host requested
# -----------------------------
OLLAMA_HOST_DEFAULT = "http://localhost:11434"

# -----------------------------
# Prompt templates
# NOTE: we avoid str.format() to prevent JSON braces issues.
# We use token {{EMAIL_TEXT}} and replace.
# IMPORTANT: do NOT put "phishing|non-phishing" as the label value in the JSON example, or the model may copy it.
# -----------------------------
PHISH_PROMPT_TEMPLATE = """Return ONLY one valid JSON object (no extra text, no markdown).

Task: classify the EMAIL TEXT as either:
- "phishing"  (attempts to deceive the recipient to reveal credentials/money/data or to perform risky actions)
- "non-phishing" (legitimate or benign message)

Output format (exact keys, same order not required):
{"label":"phishing|non-phishing","confidence":0.0,"signals":[],"rationale":""}

Rules:
- "label" MUST be exactly one of: "phishing", "non-phishing" (do NOT use "|" in the value).
- "confidence" MUST be a number in [0,1] reflecting how sure you are (not a calibrated probability).
- "signals" MUST be a short list (max 6) of the strongest textual cues you used (e.g., "urgent action", "credential request", "payment request", "account threat", "spoofed identity", "suspicious link mention").
- "rationale" MUST be <= 2 sentences, descriptive only, and MUST NOT include personal data or real links; use placeholders like [URL], [EMAIL], [NAME].

If evidence is mixed or weak:
- choose the most likely label
- set confidence low (e.g., <= 0.4)

EMAIL TEXT:
{{EMAIL_TEXT}}
"""

ORIGIN_PROMPT_TEMPLATE = """Return ONLY one valid JSON object (no extra text, no markdown).

Task: estimate whether the EMAIL TEXT is more likely:
- "manual" (written by a human)
- "ai-generated" (generated or heavily rewritten by a language model)
- "unknown" (cannot tell reliably)

Output format (exact keys, same order not required):
{"label":"manual|ai-generated|unknown","confidence":0.0,"style_cues":[],"rationale":""}

Rules:
- "label" MUST be exactly one of: "manual", "ai-generated", "unknown" (do NOT use "|" in the value).
- "confidence" MUST be a number in [0,1] reflecting how sure you are (not a calibrated probability).
- "style_cues" MUST be a short list (max 6) of stylistic indicators (e.g., "very polished neutral tone", "template-like phrasing", "high consistency", "low idiosyncrasy", "generic salutations", "unnatural repetitiveness").
- "rationale" MUST be <= 2 sentences, descriptive only, and MUST NOT include personal data or real links; use placeholders like [URL], [NAME].

Guidance:
- Prefer "unknown" with low confidence if the text is too short, too generic, or mixed.
- Do NOT use dataset provenance; judge only from the text.

EMAIL TEXT:
{{EMAIL_TEXT}}
"""



REPAIR_PROMPT_TEMPLATE = """You must output ONLY valid JSON that matches exactly this schema:

{schema}

Here is the previous invalid output:
{bad_output}

Now output ONLY the corrected JSON, nothing else.
"""

# -----------------------------
# Label normalization
# -----------------------------
def normalize_class_label(x: str) -> Optional[str]:
    if x is None:
        return None
    s = x.strip().lower()
    s = s.replace("_", "-").replace(" ", "")
    if s in ("phishing", "phish"):
        return "phishing"
    if s in ("non-phishing", "nonphishing", "legit", "legitimate", "ham", "nonphish"):
        return "non-phishing"
    return None


def normalize_origin_label(x: str) -> Optional[str]:
    if x is None:
        return None
    s = x.strip().lower()
    s = s.replace("_", "-").replace(" ", "")
    if s in ("manual", "human", "man"):
        return "manual"
    if s in ("ai", "aigenerated", "ai-generated", "llm", "ollama"):
        return "ai-generated"
    if s in ("unknown", "unk", "na", "n/d", "nd"):
        return "unknown"
    return None


def clamp01(v: Any) -> float:
    try:
        f = float(v)
    except Exception:
        return 0.0
    return 0.0 if f < 0.0 else (1.0 if f > 1.0 else f)


# -----------------------------
# Robust JSON extraction
# -----------------------------
def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Robust JSON extraction:
    1) try direct json.loads on stripped text
    2) scan for any substring that parses as a JSON object
    """
    if not text:
        return None

    t = text.strip()
    try:
        return json.loads(t)
    except Exception:
        pass

    starts = [m.start() for m in re.finditer(r"\{", text)]
    for s in starts:
        for e in range(len(text) - 1, s, -1):
            if text[e] != "}":
                continue
            candidate = text[s:e + 1].strip()
            try:
                return json.loads(candidate)
            except Exception:
                continue
    return None


# -----------------------------
# Output validation (prevents copied templates like "manual|ai-generated|unknown")
# -----------------------------
def is_valid_phish(obj: Dict[str, Any]) -> bool:
    if not isinstance(obj, dict):
        return False
    label_raw = str(obj.get("label", "")).strip()
    if "|" in label_raw:
        return False
    label = normalize_class_label(label_raw)
    if label not in ("phishing", "non-phishing"):
        return False
    try:
        c = float(obj.get("confidence", 0.0))
        if c < 0.0 or c > 1.0:
            return False
        # If the model keeps copying default 0.0, treat it as invalid (unless email empty handled elsewhere)
        if c == 0.0:
            return False
    except Exception:
        return False
    return True


def is_valid_origin(obj: Dict[str, Any]) -> bool:
    if not isinstance(obj, dict):
        return False
    label_raw = str(obj.get("label", "")).strip()
    if "|" in label_raw:
        return False
    label = normalize_origin_label(label_raw)
    if label not in ("manual", "ai-generated", "unknown"):
        return False
    try:
        c = float(obj.get("confidence", 0.0))
        if c < 0.0 or c > 1.0:
            return False
        if c == 0.0:
            return False
    except Exception:
        return False
    return True


# -----------------------------
# Ollama/OpenAI-compatible client with fallback endpoints
# -----------------------------
@dataclass
class LLMConfig:
    base_url: str
    model: str
    temperature: float
    timeout: int
    retries: int
    sleep_s: float
    use_format_json: bool = True
    api_key: Optional[str] = None  # used only for /v1/* if needed


def _headers(cfg: LLMConfig) -> Dict[str, str]:
    h = {"Content-Type": "application/json"}
    if cfg.api_key:
        h["Authorization"] = f"Bearer {cfg.api_key}"
    return h


def llm_generate_api_generate(cfg: LLMConfig, prompt: str) -> str:
    url = cfg.base_url.rstrip("/") + "/api/generate"
    payload: Dict[str, Any] = {
        "model": cfg.model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": cfg.temperature},
    }
    if cfg.use_format_json:
        payload["format"] = "json"

    r = requests.post(url, json=payload, headers=_headers(cfg), timeout=cfg.timeout)
    r.raise_for_status()
    return r.json().get("response", "")


def llm_generate_api_chat(cfg: LLMConfig, prompt: str) -> str:
    url = cfg.base_url.rstrip("/") + "/api/chat"
    payload: Dict[str, Any] = {
        "model": cfg.model,
        "stream": False,
        "messages": [{"role": "user", "content": prompt}],
        "options": {"temperature": cfg.temperature},
    }
    if cfg.use_format_json:
        payload["format"] = "json"

    r = requests.post(url, json=payload, headers=_headers(cfg), timeout=cfg.timeout)
    r.raise_for_status()
    data = r.json()
    msg = data.get("message") or {}
    return msg.get("content", "")


def llm_generate_openai_compat(cfg: LLMConfig, prompt: str) -> str:
    url = cfg.base_url.rstrip("/") + "/v1/chat/completions"
    payload: Dict[str, Any] = {
        "model": cfg.model,
        "temperature": cfg.temperature,
        "stream": False,
        "messages": [{"role": "user", "content": prompt}],
    }

    r = requests.post(url, json=payload, headers=_headers(cfg), timeout=cfg.timeout)
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"]["content"]


def llm_generate(cfg: LLMConfig, prompt: str) -> str:
    """
    Auto-fallback:
      1) /api/generate
      2) /api/chat
      3) /v1/chat/completions
    """
    # 1) /api/generate
    try:
        return llm_generate_api_generate(cfg, prompt)
    except requests.HTTPError as e:
        if getattr(e.response, "status_code", None) not in (404,):
            raise
    except Exception:
        pass

    # 2) /api/chat
    try:
        return llm_generate_api_chat(cfg, prompt)
    except requests.HTTPError as e:
        if getattr(e.response, "status_code", None) not in (404,):
            raise
    except Exception:
        pass

    # 3) OpenAI-compatible
    return llm_generate_openai_compat(cfg, prompt)


def ask_llm_json(
    cfg: LLMConfig,
    prompt: str,
    expected_schema: Dict[str, Any],
    validator
) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Ask LLM to return JSON. If parsing fails or validator fails, do a limited repair retry.
    Returns (json_obj_or_none, raw_text).
    """
    raw = ""
    current_prompt = prompt

    for attempt in range(cfg.retries + 1):
        try:
            raw = llm_generate(cfg, current_prompt)
        except Exception as e:
            raw = f"__ERROR__: {e}"
            if attempt < cfg.retries:
                time.sleep(cfg.sleep_s)
                continue
            return None, raw

        obj = extract_json(raw)
        if obj is not None and validator(obj):
            return obj, raw

        # Repair attempt
        if attempt < cfg.retries:
            current_prompt = REPAIR_PROMPT_TEMPLATE.format(
                schema=json.dumps(expected_schema, indent=2),
                bad_output=raw
            )
            time.sleep(cfg.sleep_s)

    return None, raw


# -----------------------------
# IO helpers
# -----------------------------
def read_text_file(path: str, max_chars: Optional[int] = None) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        txt = f.read()
    txt = txt.strip()
    if max_chars and len(txt) > max_chars:
        txt = txt[:max_chars]
    return txt


def detect_csv_dialect(path: str) -> csv.Dialect:
    """
    Detect delimiter (comma vs tab, etc.) using csv.Sniffer.
    Fallback to excel dialect if detection fails.
    """
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        sample = f.read(4096)
    try:
        return csv.Sniffer().sniff(sample)
    except Exception:
        return csv.excel


def count_csv_rows(path: str, dialect: csv.Dialect) -> int:
    """
    Count data rows (excluding header).
    """
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, dialect)
        n = 0
        header_seen = False
        for _ in reader:
            if not header_seen:
                header_seen = True
                continue
            n += 1
        return n


# -----------------------------
# Progress bar / live status
# -----------------------------
def _short(s: str, max_len: int = 60) -> str:
    s = (s or "").replace("\n", " ")
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def format_status(done: int, total: int, start_time: float, filename: str, step: str) -> str:
    elapsed = max(0.001, time.time() - start_time)
    pct = (done / total) * 100.0 if total else 0.0
    rate = done / elapsed if done else 0.0

    bar_len = 20
    filled = int((done / total) * bar_len) if total else 0
    bar = "[" + "#" * filled + "-" * (bar_len - filled) + "]"

    fn = _short(filename, 55) if filename else "-"
    st = _short(step, 22) if step else "-"

    return f"{bar} {done}/{total} ({pct:5.1f}%) | {rate:5.2f} it/s | {elapsed:6.1f}s | {st:22s} | {fn}"


def print_status(done: int, total: int, start_time: float, filename: str, step: str, force_newline: bool = False) -> None:
    msg = format_status(done, total, start_time, filename, step)

    is_tty = sys.stderr.isatty()
    if is_tty and not force_newline:
        pad = " " * 10
        print("\r" + msg + pad, end="", file=sys.stderr, flush=True)
    else:
        print(msg, file=sys.stderr, flush=True)


# -----------------------------
# Metrics
# -----------------------------
@dataclass
class GroupStat:
    name: str
    total: int = 0
    correct: int = 0

    @property
    def accuracy_pct(self) -> float:
        return (self.correct / self.total) * 100.0 if self.total else 0.0


def prompt_for_host(default_host: str) -> str:
    try:
        if not sys.stdin.isatty():
            return default_host
        val = input(f"Ollama host [{default_host}]: ").strip()
        return val if val else default_host
    except EOFError:
        return default_host


def main():
    ap = argparse.ArgumentParser(
        description="Use Ollama as a judge (phishing + origin), extend report, compute success rates by group."
    )
    ap.add_argument("--input-csv", default="general_repos.csv",
                    help="Input CSV with fields: numero,filename,class,origin,source_file,row_idx")
    ap.add_argument("--txt-dir", default=".",
                    help="Directory containing .txt files (joined with filename if filename is relative)")
    ap.add_argument("--out-report", default="general_repos_with_ollama.csv",
                    help="Output extended CSV report with predictions")
    ap.add_argument("--out-metrics", default="ollama_success_rates.csv",
                    help="Output CSV with success percentages by group")
    ap.add_argument("--ollama-url", default=None,
                    help=f"Base URL. If omitted, script will ask (default: {OLLAMA_HOST_DEFAULT}).")
    ap.add_argument("--model", required=True,
                    help="Model name (e.g., qwen2.5, llama3, mistral)")
    ap.add_argument("--temperature", type=float, default=0.0,
                    help="Temperature (suggested 0.0 for stable JSON)")
    ap.add_argument("--timeout", type=int, default=120,
                    help="HTTP timeout seconds")
    ap.add_argument("--retries", type=int, default=1,
                    help="Retries for failed/invalid JSON responses (including invalid labels/confidence)")
    ap.add_argument("--sleep", type=float, default=0.2,
                    help="Sleep seconds between retries")
    ap.add_argument("--max-chars", type=int, default=12000,
                    help="Max chars from email text to send to the model (truncate huge emails)")
    ap.add_argument("--no-format-json", action="store_true",
                    help="Disable sending format='json' (use if your endpoint doesn't support it)")
    ap.add_argument("--api-key", default=None,
                    help="Optional API key (used for /v1/* endpoints). Can also set OPENAI_API_KEY env var.")
    ap.add_argument("--status-newline", action="store_true",
                    help="Print status on new lines instead of updating one line (useful in logs/CI).")
    args = ap.parse_args()

    host = args.ollama_url.strip() if args.ollama_url else prompt_for_host(OLLAMA_HOST_DEFAULT)
    api_key = args.api_key or os.getenv("OPENAI_API_KEY") or os.getenv("OLLAMA_API_KEY")

    cfg = LLMConfig(
        base_url=host,
        model=args.model,
        temperature=args.temperature,
        timeout=args.timeout,
        retries=args.retries,
        sleep_s=args.sleep,
        use_format_json=not args.no_format_json,
        api_key=api_key
    )

    # Expected schemas (used for repair prompt)
    phish_schema = {"label": "non-phishing", "confidence": 0.5, "signals": [], "rationale": ""}
    origin_schema = {"label": "unknown", "confidence": 0.5, "style_cues": [], "rationale": ""}

    # Group stats required
    g_phish = GroupStat("phishing")
    g_nonphish = GroupStat("non-phishing")
    g_ai = GroupStat("ai")
    g_manual = GroupStat("manuale")
    g_phish_ai = GroupStat("phishing ai")
    g_phish_manual = GroupStat("phishing manuale")

    if not os.path.exists(args.input_csv):
        print(f"ERROR: input CSV not found: {args.input_csv}", file=sys.stderr)
        sys.exit(1)

    dialect = detect_csv_dialect(args.input_csv)
    total_rows = count_csv_rows(args.input_csv, dialect)

    start = time.time()
    processed = 0

    rows_out: List[Dict[str, Any]] = []

    with open(args.input_csv, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f, dialect=dialect)
        required = ["numero", "filename", "class", "origin", "source_file", "row_idx"]
        missing = [c for c in required if c not in (reader.fieldnames or [])]
        if missing:
            print(f"ERROR: missing columns in input CSV: {missing}", file=sys.stderr)
            sys.exit(1)

        # initial status
        print_status(0, total_rows, start, "", "starting", force_newline=True)

        for row in reader:
            processed += 1

            filename = (row.get("filename") or "").strip()
            true_class_raw = row.get("class", "")
            true_origin_raw = row.get("origin", "")

            true_class = normalize_class_label(true_class_raw) or (true_class_raw.strip().lower())
            true_origin = normalize_origin_label(true_origin_raw) or (true_origin_raw.strip().lower())

            # Resolve file path
            path = filename
            if not os.path.isabs(path):
                path = os.path.join(args.txt_dir, filename)

            # Live status: loading
            print_status(
                processed, total_rows, start, filename,
                "loading file",
                force_newline=args.status_newline
            )

            if not os.path.exists(path):
                row["pred_class_label"] = ""
                row["pred_class_confidence"] = ""
                row["pred_origin_label"] = ""
                row["pred_origin_confidence"] = ""
                row["judge_model"] = args.model
                row["judge_host"] = host
                row["judge_error"] = f"missing_file:{path}"
                row["phish_raw"] = ""
                row["origin_raw"] = ""
                rows_out.append(row)

                print_status(
                    processed, total_rows, start, filename,
                    "missing file",
                    force_newline=True
                )
                continue

            email_text = read_text_file(path, max_chars=args.max_chars)

            # 1) phishing vs non-phishing
            print_status(
                processed, total_rows, start, filename,
                "judge: phishing",
                force_newline=args.status_newline
            )
            ph_prompt = PHISH_PROMPT_TEMPLATE.replace("{{EMAIL_TEXT}}", email_text)
            ph_obj, ph_raw = ask_llm_json(cfg, ph_prompt, phish_schema, is_valid_phish)

            pred_class_label = ""
            pred_class_conf = 0.0
            if ph_obj:
                pred_class_label = normalize_class_label(str(ph_obj.get("label", ""))) or str(ph_obj.get("label", "")).strip().lower()
                pred_class_conf = clamp01(ph_obj.get("confidence", 0.0))

            # 2) manual vs ai-generated
            print_status(
                processed, total_rows, start, filename,
                "judge: origin",
                force_newline=args.status_newline
            )
            or_prompt = ORIGIN_PROMPT_TEMPLATE.replace("{{EMAIL_TEXT}}", email_text)
            or_obj, or_raw = ask_llm_json(cfg, or_prompt, origin_schema, is_valid_origin)

            pred_origin_label = ""
            pred_origin_conf = 0.0
            if or_obj:
                pred_origin_label = normalize_origin_label(str(or_obj.get("label", ""))) or str(or_obj.get("label", "")).strip().lower()
                pred_origin_conf = clamp01(or_obj.get("confidence", 0.0))

            row["pred_class_label"] = pred_class_label
            row["pred_class_confidence"] = f"{pred_class_conf:.4f}"
            row["pred_origin_label"] = pred_origin_label
            row["pred_origin_confidence"] = f"{pred_origin_conf:.4f}"
            row["judge_model"] = args.model
            row["judge_host"] = host

            # Save short raw outputs for debugging
            row["phish_raw"] = (ph_raw or "")[:400].replace("\n", "\\n")
            row["origin_raw"] = (or_raw or "")[:400].replace("\n", "\\n")

            # Errors
            err_parts = []
            if ph_obj is None:
                err_parts.append("phish_invalid_or_parse_failed")
            if or_obj is None:
                err_parts.append("origin_invalid_or_parse_failed")
            row["judge_error"] = ";".join(err_parts)

            rows_out.append(row)

            # --- Update group stats (accuracy by subset) ---
            # Class subsets
            if true_class == "phishing":
                g_phish.total += 1
                if pred_class_label == "phishing":
                    g_phish.correct += 1

                # Combined groups: require BOTH predictions correct
                if true_origin in ("ai-generated", "ai"):
                    g_phish_ai.total += 1
                    if (pred_class_label == "phishing") and (pred_origin_label == "ai-generated"):
                        g_phish_ai.correct += 1
                if true_origin == "manual":
                    g_phish_manual.total += 1
                    if (pred_class_label == "phishing") and (pred_origin_label == "manual"):
                        g_phish_manual.correct += 1

            elif true_class == "non-phishing":
                g_nonphish.total += 1
                if pred_class_label == "non-phishing":
                    g_nonphish.correct += 1

            # Origin subsets
            if true_origin in ("ai-generated", "ai"):
                g_ai.total += 1
                if pred_origin_label == "ai-generated":
                    g_ai.correct += 1
            elif true_origin == "manual":
                g_manual.total += 1
                if pred_origin_label == "manual":
                    g_manual.correct += 1

            # done status
            print_status(
                processed, total_rows, start, filename,
                "done",
                force_newline=args.status_newline
            )

        # final line
        print_status(processed, total_rows, start, "", "completed", force_newline=True)

    # Write extended report
    base_cols = ["numero", "filename", "class", "origin", "source_file", "row_idx"]
    new_cols = [
        "pred_class_label", "pred_class_confidence",
        "pred_origin_label", "pred_origin_confidence",
        "judge_model", "judge_host", "judge_error",
        "phish_raw", "origin_raw"
    ]

    all_cols: List[str] = []
    seen = set()
    for c in base_cols + new_cols:
        if c not in seen:
            all_cols.append(c)
            seen.add(c)
    # Append any other columns present
    for r in rows_out:
        for k in r.keys():
            if k not in seen:
                all_cols.append(k)
                seen.add(k)

    with open(args.out_report, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=all_cols)
        w.writeheader()
        for r in rows_out:
            w.writerow(r)

    # Write metrics
    metrics = [g_phish, g_nonphish, g_ai, g_manual, g_phish_ai, g_phish_manual]
    with open(args.out_metrics, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["group", "total", "correct", "accuracy_pct"])
        w.writeheader()
        for g in metrics:
            w.writerow({
                "group": g.name,
                "total": g.total,
                "correct": g.correct,
                "accuracy_pct": f"{g.accuracy_pct:.2f}"
            })

    elapsed = time.time() - start
    print(f"\nOK: report saved to {args.out_report}")
    print(f"OK: metrics saved to {args.out_metrics}")
    print(f"Using host: {host}")
    print(f"Model: {args.model}")
    print(f"Processed: {processed} emails in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
