# Original production URL model

`model_bundle.joblib` is the unchanged locally trained XGBoost hostname model (`host-v1`), including calibration, thresholds, feature names and training feature bounds. Size: 730,772 bytes.

SHA-256: `dd5c76779d4598e369784d9e5bb5e8963fd7322cb0f6c017395bf608af479bff`.

Training source: Arvind Prasad and Shalini Chandra (2024), *PhiUSIIL Phishing URL (Website)*, [UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/967/phiusiil%2Bphishing%2Burl%2Bdataset), [paper](https://doi.org/10.1016/j.cose.2023.103545). The source dataset is [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). This derived model uses extracted hostname features, domain-grouped splits with seed 42, XGBoost training and validation calibration; it is not the original dataset. No raw rows or reputation feeds are distributed. This attribution does not imply endorsement by the dataset authors.

The recorded training provenance and source license support redistribution of this project-trained artifact with attribution. No separate project-wide software license has been established. Other candidate models and research outputs remain local.

The published bundle enables inference on a fresh checkout. Dependencies must match `requirements.txt`. Only load the trusted repository artifact: joblib deserialization can execute code. Missing weights produce explicit unavailable-model evidence.

Known limitations include substantial legitimate-subdomain false positives and limited real-world calibration. Scores are risk indicators, not guarantees. The original weights and thresholds have not been retrained or modified for publication.
