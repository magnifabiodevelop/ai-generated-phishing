# AI-Generated Phishing: an empirical comparison between traditional attacks and generative AI

This repository supports the L-8 (BSc) thesis **"AI-Generated Phishing: an empirical comparison between traditional attacks and generative AI"**.  
The project investigates—through a reproducible experimental pipeline—the differences between phishing emails **collected from public sources** (“manual” dataset) and phishing emails **generated with Large Language Models (LLMs)** (“AI-generated” dataset), focusing on linguistic patterns, recurring signals, and classification performance.

> **Important note (educational purpose):** all content in this repository is provided **exclusively for educational and research purposes**. It is not intended for offensive, unlawful, or harmful use.

---

## Goals

- Build two comparable datasets:
  - **Dataset A (manual):** emails from public repositories and open datasets (often CSV format).
  - **Dataset B (AI-generated):** emails generated with LLMs in an **ethical and controlled** way.
- Analyze differences between A and B using linguistic/statistical features (e.g., TF-IDF, length, punctuation, readability, lexical similarity).
- Train and evaluate classification models (e.g., Logistic Regression, Random Forest, Transformers such as DistilBERT/BERT).
- Apply interpretability techniques (e.g., SHAP/LIME) to highlight factors driving model decisions.
- Produce reproducible outputs (scripts, reports, charts, notebooks) and discuss limitations/validity.

---

## Repository contents

Typical structure (may vary across revisions):

- `docs/`  
  Supporting material (notes, references, non-sensitive excerpts).
- `scripts/`  
  Scripts for:
  - extracting and normalizing public datasets (CSV → individual emails / unified format),
  - controlled AI email generation (ethical prompts, sanitization),
  - preprocessing and feature engineering,
  - training and model evaluation,
  - final report generation (CSV/JSON).
- `notebooks/`  
  Exploratory analysis, charts, statistical comparisons, experiments.
- `data/` *(optional and subject to restrictions)*  
  Sanitized examples or placeholders; full datasets may be excluded for ethical/licensing reasons.
- `results/`  
  Experiment outputs (metrics, confusion matrices, charts, final reports).

---

## Safety, ethics, and responsible use

This repository is **not meant** to facilitate real-world phishing. In particular:

- AI-generated content is produced using **ethical, controlled prompts**, avoiding:
  - clickable or real links/URLs,
  - real brands or identities,
  - personal data (PII), credentials, bank details, unique identifiers,
  - operational instructions for attacks or bypassing defenses.
- Any examples included are **sanitized** and limited to what is strictly necessary for educational analysis.
- If the repository contains emails from public sources, they are handled with care to reduce the risk of sharing sensitive information and to respect licensing constraints.

**Allowed use:** study, research, education, controlled experimentation.  
**Prohibited use:** offensive activity, fraud, impersonation, real phishing, bypassing security controls.

---

## Datasets

- **Dataset A (manual):** sourced from public repositories/open datasets (often CSV format).
  - Sources are cited in the thesis and/or repository documentation.
- **Dataset B (AI-generated):** produced via LLMs (e.g., Ollama or other models), following ethical prompts and automated sanitization.

> Note: for ethical/licensing reasons, full datasets may not be included in this repository.  
> If so, the “Reproducibility” section explains how to reconstruct them from the original sources.

---

## Reproducibility (high level)

1. **Environment setup**  
   - Python 3.x  
   - Dependencies in `requirements.txt` (or `pyproject.toml` if present)
2. **Dataset A extraction/normalization**  
   - CSV parsing scripts and conversion into a unified format
3. **Controlled generation of Dataset B**  
   - Ethical prompts + automatic sanitization
4. **Preprocessing and feature engineering**
5. **Training & evaluation**
6. **Final reports and charts**

Exact commands are documented within `scripts/` and/or the notebooks.

---

## License

Unless otherwise stated:
- Code: **MIT License** (see `LICENSE`).
- Original documentation/text: **CC BY-NC 4.0** (attribution required, non-commercial use).

If any files are derived from third parties (public datasets, excerpts), their respective licenses apply as documented in the sources.

---

## Disclaimer

This project is provided “as is” for educational and research purposes only.  
The author(s) assume no responsibility for misuse or unlawful use of the material contained herein.

---

## Contact

For questions, issues, or suggestions, please use the repository **Issues** section.

