# Project requirements (reviewed 2026-10-15)

Sources read in full, in the repository's parent folder (course materials, not committed):

| File | Role |
| --- | --- |
| `ai_subject_course_handout.pdf` (5 pages) | Authority for academic deliverables |
| `AI-Based Website Risk Analyzer — Implementation Manual.md` (2,865 lines) | Technical roadmap |
| `Website_Risk_Analyzer_PEAS_Literature_Review.docx` | Original PEAS + 5-paper review (superseded by manual Ch. 5–6) |

No existing code, notebooks, Git repository, README or project instructions were found.

## Course requirements (handout p. 2–4)

- Project component: **40%**, mapped to **CO2** (heuristics, logic, logical inference) and **CO3** (analyse data, deal with
  uncertainty by approximate reasoning, build simple intelligent agents).
- Rubric: "end-to-end AI project development: problem definition, literature review, data preparation, implementation,
  and reporting". Includes a **10% weightage pre-submission**. Assignments are given one month before the course ends;
  evaluation happens in the last two weeks.
- **Mandatory public GitHub repository.**
- Evaluation is "based on the work presented by the students as well as the questions asked".
- "Cases of AI-generated code or plagiarism will be taken seriously" (Unfair Means policy).
- Not in the handout: dates, pre-submission format, report template → ask faculty.

## Technical requirements (manual; this phase)

- Primary data: UCI PhiUSIIL, URL column only; precomputed columns excluded (shortcut audit) — manual Ch. 8–9.
- Hostname-only features computed by one shared extractor for training and inference — Ch. 11.
- Domain-grouped 70/15/15 split, seed 42, no domain overlap — Ch. 9.
- Candidates: Logistic Regression, Random Forest, LightGBM, XGBoost; XGBoost primary — Ch. 12.
- Isotonic calibration and provisional thresholds chosen on validation; test used once — Ch. 12, 14, 19.
- SHAP global and per-URL explanations — Ch. 13.
- Threat intelligence kept separate from training — Ch. 8, 14.
- Next phase: FastAPI backend, rules, TI, fusion, explanation agent, Chrome extension — Ch. 14–18.

## Deliverables

Working pipeline and artifacts (this phase) → backend + extension → report covering the rubric items → demo →
public GitHub repo.

## Status

See `docs/IMPLEMENTATION_STATUS.md` and `docs/PROGRESS.md`.

## Conflicts and unresolved questions

| # | Issue | Resolution |
| --- | --- | --- |
| 1 | The manual's file layout (`backend/app/features.py`, `ml/prepare_data.py`, `ml/explain_global.py`) differs from this phase's requested layout (`ml/feature_extraction.py`, `preprocessing.py`, `split_dataset.py`, `calibrate.py`, `explain.py`) | Followed the phase request; the backend will import `ml.feature_extraction` (DECISIONS D2) |
| 2 | The manual feeds `is_ip` and `is_shared_hosting` to the model | Excluded after measuring zero legitimate prevalence (D5) |
| 3 | The manual calibrates and picks thresholds on the same validation data | Validation split by domain into val_cal / val_thr (D7) |
| 4 | Threshold names: manual "low/high", this phase "alert/high" | Same rules; "alert" = the manual's "low" |
| 5 | Project name "WebGuard AI" is not used in the manual | Used as a subtitle only |
| 6 | Faculty position on AI-assisted code | **Open** — student must ask in writing |
| 7 | Pre-submission format and dates | **Open** — not in the handout |
| 8 | `notebooks/eda.ipynb` requested "if useful" | Not created; `ml/data_audit.py` and its figures cover EDA reproducibly |
