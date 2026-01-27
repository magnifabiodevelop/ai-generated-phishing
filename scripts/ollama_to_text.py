#!/usr/bin/env python3
import csv
import random
import re
import time
from pathlib import Path
from typing import List, Tuple, Optional

import requests
from bs4 import BeautifulSoup


# ============================================================
# CONFIG OLLAMA (valori di default, modificabili da input)
# ============================================================
OLLAMA_HOST_DEFAULT = "http://localhost:11434"   # es. http://127.0.0.1:11434
OLLAMA_TIMEOUT_SEC = 300                           # timeout per chiamata
OLLAMA_SLEEP_SEC = 0.2                             # pausa tra chiamate
RANDOM_SEED = 42                                   # seed per scelta prompt random

REPORT_NAME = "report.csv"


# ============================================================
# PROMPT LIST (separa legit vs phishing)
# ============================================================
PROMPTS_PHISHING: List[str] = [
    # 1) Riunione / agenda
    """Scrivi una email aziendale e professionale come se fossi un dipendente HR.
Struttura: avvisa di una riunione importante ed urgente. chiedi di confermare la presenza tramite link.
Vincoli: nessun dominio reale. nessun nome reale. fingi di essere del reparto HR o management. usa placeholder tra parentesi quadre per nascondere nomi, link, brand , iban e dati sensibili, es [LINK], [IBAN].
Output: SOLO testo dell'email completa (oggetto + corpo), nessun commento o altro. Metti l'oggetto su prima riga con "Subject:".
Tema: convocazione riunione con agenda e obiettivi.
Lingua: inglese. Tono: formale. Carattere: urgente. Lunghezza corpo: 120-180 parole.""",

    # 2) Aggiornamento progetto
    """Scrivi una email aziendale e professionale come se fossi un team leader.
Struttura: avvisa di una riunione importante ed urgente per l'aggiornamento di un progetto. chiedi di confermare la presenza tramite link.
Vincoli: nessun dominio reale. nessun nome reale. fingi di essere il team leader o il project manager. usa placeholder tra parentesi quadre per nascondere nomi, link, brand , iban e dati sensibili, es [LINK], [IBAN].
Output: SOLO testo dell'email completa (oggetto + corpo), nessun commento o altro. Metti l'oggetto su prima riga con "Subject:".
Tema: convocazione aggiornamento progetto.
Lingua: inglese. Tono: formale. Carattere: urgente. Lunghezza corpo: 120-180 parole.""",

    # 3) Comunicazione policy interna
    """Scrivi una email aziendale e professionale come se fossi un manager amministrativo.
Struttura: Spiega che ci sono state modifiche nelle policy aziendali. chiedi di confermare la presa visione cliccando sul link.
Vincoli: nessun dominio reale. nessun nome reale. fingi di essere dell'area amministrativa o delle risorse umane. usa placeholder tra parentesi quadre per nascondere nomi, link, brand , iban e dati sensibili, es [LINK], [IBAN].
Output: SOLO testo dell'email completa (oggetto + corpo), nessun commento o altro. Metti l'oggetto su prima riga con "Subject:".
Tema: modifiche alle policy interne.
Lingua: inglese. Tono: formale. Carattere: urgente. Lunghezza corpo: 120-180 parole.""",

    # 4) Supporto IT 
    """Scrivi una email aziendale e professionale come se fossi un ingegnere del reparto IT.
Struttura: Spiega di essere del reparto IT, che sono necessari interventi di sicurezza. chiedi di cliccare il link per approvare l'intervento.
Vincoli: nessun dominio reale. nessun nome reale. fingi di essere un ingegnere del reparto IT. usa placeholder tra parentesi quadre per nascondere nomi, link, brand , iban e dati sensibili, es [LINK], [IBAN].
Output: SOLO testo dell'email completa (oggetto + corpo), nessun commento o altro. Metti l'oggetto su prima riga con "Subject:".
Tema: richiesta interventi di sicurezza.
Lingua: inglese. Tono: formale. Carattere: urgente. Lunghezza corpo: 120-180 parole.""",

    # 5) Pagamenti
	"""Scrivi una email professionale come se fossi un direttore di banca.
Struttura: Spiega di essere il direttore di una [BANCA], che ci sono stati movimenti sospetti sul conto. Su ordine della questura il conto verrà bloccato per sospetta attività criminale. chiedi di cliccare il link per evitare il blocco.
Vincoli: nessun dominio reale. nessun nome reale. fingi di essere un direttore di banca. usa placeholder tra parentesi quadre per nascondere nomi, link, brand , iban e dati sensibili, es [LINK], [IBAN].
Output: SOLO testo dell'email completa (oggetto + corpo), nessun commento o altro. Metti l'oggetto su prima riga con "Subject:".
Tema: informativa su estratto conto / variazione condizioni / sicurezza dell’account, con indicazioni di contatto tramite canali NON ufficiali (es. “filiale” o “numero in carta/contratto”, senza numeri).
Lingua: inglese. Tono: urgente. Lunghezza corpo: 120-180 parole""",

	# 6) Polizia
	"""Scrivi una email come se fossi un agente di polizia.
Struttura: Spiega di essere un funzionario di polizia, che è stata notificata una multa di [IMPORTO] per violazione di [ARTICOLO DEL CODICE CIVILE] e che il mancato pagamento immediato porterà ad ulteriore sanzione. chiedi di cliccare il link per evitare la sanzione.
Vincoli: nessun dominio reale. nessun nome reale. fingi di essere un funzionario di polizia. usa placeholder tra parentesi quadre per nascondere nomi, link, brand , iban e dati sensibili, es [LINK], [IBAN].I nomi, i link, e qualsiasi altro riferimento deve essere scrittp come placeholder, come [name], [link], [iban].
Output: SOLO testo dell'email completa (oggetto + corpo), nessun commento o altro. Metti l'oggetto su prima riga con "Subject:".
Tema: comunicazione informativa o convocazione per chiarimenti amministrativi, con invito a presentarsi o contattare l’ufficio tramite canali ufficiali (senza numeri/indirizzi).
Lingua: inglese. Tono: formale. Lunghezza corpo: 120-180 parole."""
]
# Nota: prompt legit
PROMPTS_LEGIT: List[str] = [
	# 1)
    """Scrivi una email come se fossi del reparto IT di [COMPANY].
Struttura: comunicazione ufficiale su aggiornamento delle policy (sicurezza informatica e uso accettabile). Chiedi di leggere e confermare la presa visione entro una scadenza.
Vincoli: niente domini reali, niente nomi reali. Usa SOLO placeholder tra parentesi quadre per link e dati (es. [POLICY_LINK], [DEADLINE_DATE], [HELPDESK_EMAIL], [TICKET_PORTAL]). Non chiedere password, codici MFA o dati personali. Niente allegati.
Output: SOLO testo email completa (Subject + body), nessun commento o altro. 'Subject:' in prima riga.
Lingua: inglese. Tono: professionale, chiaro, leggermente urgente. Lunghezza: 120–180 parole.""",
	# 2)
    """Scrivi una email come se fossi del team IT Governance di [COMPANY].
Struttura: annuncia il refresh delle policy; inserisci un breve riepilogo di 3 cambiamenti principali (es. gestione dati, accesso remoto, aggiornamenti dispositivo) e invita a completare un breve modulo di awareness entro una data.
Vincoli: niente domini reali, niente nomi reali. Usa SOLO placeholder tra parentesi quadre per dettagli e riferimenti (es. [INTRANET_PORTAL_NAME], [POLICY_SUMMARY_LINK], [TRAINING_LINK], [DUE_DATE], [SUPPORT_CHANNEL]). Non chiedere login via link email; rimanda al portale interno tramite [INTRANET_PORTAL_NAME]. Niente allegati.
Output: SOLO testo email completa (Subject + body), nessun commento o altro. 'Subject:' in prima riga.
Lingua: inglese. Tono: corporate, informativo. Lunghezza: 120–180 parole.""",
	# 3)
    """Scrivi una email come se fossi delle Risorse Umane di [COMPANY].
Struttura: richiedi un appuntamento breve con il dipendente per [TOPIC] (es. performance review, aggiornamento contrattuale, onboarding follow-up). Proponi 2–3 slot orari e chiedi conferma o alternative.
Vincoli: niente nomi reali, niente indirizzi reali. Usa SOLO placeholder tra parentesi quadre per nomi, date, luogo e link meeting (es. [EMPLOYEE_NAME], [HR_REP_NAME], [SLOT_1], [SLOT_2], [SLOT_3], [MEETING_LINK], [OFFICE_LOCATION]). Non richiedere documenti via email; se necessario rimanda a [HR_PORTAL_LINK].
Output: SOLO testo email completa (Subject + body), nessun commento o altro. 'Subject:' in prima riga.
Lingua: inglese. Tono: cortese, professionale. Lunghezza: 120–180 parole.""",
	# 4)
    """Scrivi una email come se fossi il team leader del progetto [PROJECT_NAME] in [COMPANY].
Struttura: richiedi un aggiornamento prima del checkpoint; chiedi progressi, prossimi step, rischi/blocchi e supporto necessario. Inserisci una mini lista puntata con ciò che vuoi ricevere in risposta.
Vincoli: niente nomi reali. Usa SOLO placeholder tra parentesi quadre per progetto, date/ore e strumenti (es. [PROJECT_NAME], [CHECKPOINT_DATE], [CHECKPOINT_TIME], [TRACKER_LINK], [CHANNEL_NAME]). Evita dettagli sensibili; mantieni contenuto interno e generico.
Output: SOLO testo email completa (Subject + body), nessun commento o altro. 'Subject:' in prima riga.
Lingua: inglese. Tono: collaborativo, conciso, leggermente urgente. Lunghezza: 120–180 parole.""",
	# 5)
	"""Scrivi una email come se fossi del Customer Support di [COMPANY].
Struttura: notifica un problema che impatta la spedizione dell’ordine [ORDER_ID] (es. ritardo, verifica indirizzo, articolo non disponibile). Scusati brevemente, indica una stima e fornisci 2–3 opzioni (nuova data, cambio indirizzo via portale, rimborso/sostituzione) spiegando come procedere.
Vincoli: niente nomi reali, niente corrieri reali, niente domini reali. Usa SOLO placeholder tra parentesi quadre per dettagli (es. [CUSTOMER_NAME], [ORDER_ID], [NEW_DELIVERY_DATE], [SUPPORT_PORTAL_LINK], [CASE_ID], [PHONE_PLACEHOLDER]). Non chiedere dati di pagamento, password o documenti.
Output: SOLO testo email completa (Subject + body), nessun commento o altro. 'Subject:' in prima riga.
Lingua: inglese. Tono: empatico, utile, non allarmistico. Lunghezza: 120–180 parole."""
]


# ============================================================
# Sanitizzazione
# ============================================================
RE_URL = re.compile(r"\bhttps?://\S+|\bwww\.\S+", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b", re.IGNORECASE)
RE_IBAN_IT = re.compile(r"\bIT\d{2}[A-Z]\d{10}[0-9A-Z]{12}\b", re.IGNORECASE)
RE_PHONE = re.compile(r"\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{5,}\b")
RE_LONGNUM = re.compile(r"\b\d{5,}\b")
RE_AMOUNT = re.compile(r"(?:(?:€|\$|£)\s?\d[\d\.,]*)|(?:\d[\d\.,]*\s?(?:€|\$|£))")
WS_RE = re.compile(r"[ \t]+")


def html_to_text(s: str) -> str:
    if not isinstance(s, str):
        return ""
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

    text = RE_URL.sub("[URL]", text)
    text = RE_EMAIL.sub("[EMAIL]", text)
    text = RE_IBAN_IT.sub("[IBAN]", text)
    text = RE_AMOUNT.sub("[AMOUNT]", text)
    text = RE_PHONE.sub("[PHONE]", text)
    text = RE_LONGNUM.sub("[NUM]", text)

    return normalize_ws(text)


# ============================================================
# Ollama + IO
# ============================================================
def call_ollama(host: str, model: str, prompt: str) -> str:
    r = requests.post(
        f"{host}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=OLLAMA_TIMEOUT_SEC,
    )
    r.raise_for_status()
    return r.json().get("response", "").strip()


def write_txt(out_dir: Path, numero: int, content: str) -> str:
    filename = f"{numero:04d}.txt"
    (out_dir / filename).write_text(content.strip() + "\n", encoding="utf-8")
    return filename


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


def build_plan(n_legit: int, n_phish: int, rng: random.Random) -> List[Tuple[str, str]]:
    """
    Ritorna una lista di tuple: (class, prompt) con class in {"non-phishing", "phishing"}.
    L'ordine è randomizzato per evitare blocchi.
    """
    plan: List[Tuple[str, str]] = []
    for _ in range(n_legit):
        plan.append(("non-phishing", rng.choice(PROMPTS_LEGIT)))
    for _ in range(n_phish):
        plan.append(("phishing", rng.choice(PROMPTS_PHISHING)))
    rng.shuffle(plan)
    return plan


def main():
    print("=== Ollama -> .txt (sanificati) + report.csv (senza body) ===")

    # Input interattivo: quantità per classi
    n_legit = ask_int("Quante mail LEGIT (ham) vuoi creare", default=50)
    n_phish = ask_int("Quante mail PHISHING vuoi creare", default=50)
    if n_legit == 0 and n_phish == 0:
        raise SystemExit("Niente da fare: entrambe le quantità sono 0.")

    # Modello da usare (richiesto)
    model = input("Modello Ollama da usare (es. llama3, qwen2.5:7b, mistral-small:24b): ").strip()
    if not model:
        raise SystemExit("Modello non valido (vuoto).")

    # (opzionale) host, di default quello configurato
    host = input(f"Host Ollama [{OLLAMA_HOST_DEFAULT}]: ").strip() or OLLAMA_HOST_DEFAULT

    # Numerazione iniziale
    start_num = ask_int("Da che numerazione devo iniziare? (es. 1 o 101)", default=1)
    if start_num <= 0:
        raise SystemExit("Numerazione iniziale non valida. Inserisci un intero > 0.")

    out_dir_str = input("Directory di output (dove salvare i .txt + report.csv): ").strip()
    out_dir = Path(out_dir_str).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # RNG
    rng = random.Random(RANDOM_SEED)
    plan = build_plan(n_legit, n_phish, rng)

    # Report CSV (solo metadati richiesti)
    report_path = out_dir / REPORT_NAME
    with report_path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.DictWriter(
            report_file,
            fieldnames=["numero", "filename", "class", "origin", "source_file", "row_idx"],
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()

        total = len(plan)
        for i, (cls, prompt) in enumerate(plan):
            numero = start_num + i

            perc = int(((i + 1) / total) * 100)
            print(f"[{i+1}/{total}] ({perc}%) Genero -> {numero:04d}.txt", end="\r", flush=True)

            raw = call_ollama(host=host, model=model, prompt=prompt)
            cleaned = sanitize_text(raw)

            filename = write_txt(out_dir, numero, cleaned)

            writer.writerow(
                {
                    "numero": f"{numero:04d}",
                    "filename": filename,
                    "class": cls,          # phishing / non-phishing
                    "origin": model,       # modello LLM usato
                    "source_file": "n/d",
                    "row_idx": 0,
                }
            )

            time.sleep(OLLAMA_SLEEP_SEC)

    print("\nOK: creati file .txt sanificati in", out_dir)
    print("OK: creato report", report_path)


if __name__ == "__main__":
    main()
