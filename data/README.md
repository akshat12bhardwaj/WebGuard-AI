# data/

Nothing in this folder is committed (see `.gitignore`).

| Folder | Content | Created by |
| --- | --- | --- |
| `raw/phiusiil.zip`, `raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv` | Original UCI archive and CSV (never modified) | `python -m ml.data_download` |
| `processed/dataset.csv` | One row per hostname with 21 computed features | `python -m ml.preprocessing` |
| `processed/{train,val,test}.csv` | Domain-grouped split, seed 42 | `python -m ml.split_dataset` |
| `external/`, `feeds/` | Reserved for the next phase (fresh test set, OpenPhish feed) | — |

Provenance and checksums: `docs/DATA_SOURCES.md` and `reports/metrics/download_provenance.json`.
