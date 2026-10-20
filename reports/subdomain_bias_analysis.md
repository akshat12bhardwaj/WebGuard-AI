# Subdomain bias analysis (baseline xgb-host-v1, 2026-10-16)

Script: `python -m ml.subdomain_bias` → `reports/subdomain_bias/` (analysis.json, shap_fp_vs_apex.csv,
false_positive_examples.csv, subdomain_bias_overview.png). The baseline bundle is only read.

## Conclusion

The baseline learned "has a subdomain → phishing" because PhiUSIIL almost never shows a legitimate host with a subdomain.
This is a training-data artifact, not a property of legitimate websites. Evidence below is consistent with this
hypothesis; SHAP rankings alone are not treated as proof.

## Evidence

| Observation | Value | Source |
| --- | --- | --- |
| Legitimate training hosts with a subdomain | 2.86% (phishing: 59.06%) | train split |
| Phishing share in training by subdomain count 0 / 1 / 2 / 3+ | 22.4% / 92.0% / 98.2% / 99.9% | train split |
| Baseline FPR at alert on legitimate subdomain hosts | Tranco top-100k 93.5% (3,000 hosts); new Tranco 100k–1M test 90.3% (8,127); **PhiUSIIL's own test 51.1% (695)** | analysis.json, exp03/comparison.json |
| FPR by subdomain count in Tranco set: 1 / 2 / 3+ | 91.4% / 97.4% / 99.7% (0 subdomains: apex set 18.2%) | analysis.json |
| **Counterfactual:** same 3,000 sites scored with the subdomain removed (registered domain only) | FPR 93.5% → 15.2%; 83.8% of false positives clear; median P(phishing) 0.917 → 0.186 | analysis.json |
| Features changed by removing the subdomain | always: host_length, num_labels, num_dots, host_entropy, subdomain_count/length; often: avg_label_length 96%, vowel_ratio 92%; sometimes: longest_label 38%, digits 32–37%, hyphens 28%, consonant run 30%; never/rarely: registered_domain_length, tld_length, suspicious_word_count 2% | analysis.json |
| Mean SHAP, legitimate subdomain false positives minus correctly-scored apex domains (log-odds) | subdomain_count +2.53, subdomain_length +1.50, num_digits +0.44, num_hyphens +0.21, host_length +0.19, digit_ratio +0.10 | shap_fp_vs_apex.csv |

The counterfactual is the strongest evidence: changing only the subdomain part flips most decisions. It shows what the
model depends on, not why the world works that way.

## Where the errors concentrate

- Common first labels all have FPR ≥ 78%: `cdn` 92%, `api` 80%, `m` 93%, `sync` 96%, `app` 78%, `web` 82%, `s` 94%.
- Top registered domains among false positives are infrastructure: office.net 46, akamai.net 44, trafficmanager.net 42,
  aws.dev 33, aaplimg.com 33, akamaiedge.net 31, playstation.net 29, cloud.microsoft 29.
- Representative false positives (all P = 1.00): `kv801.prod.do.dsp.mp.microsoft.com.edgekey.net`,
  `cdp1.digicert.com.akamaized.net`, `edge.skype.com.trafficmanager.net`, `region-eng-spotifycdn.cdn-gslb.spotify.com`.

## Evaluation-set artifacts

- Tranco's subdomain list (Q2Y54) mixes user-visited sites with DNS-observed infrastructure hostnames (CDNs, telemetry).
  Users rarely visit these in a browser tab, so the 93% figure overstates the user-facing problem. However, the bias is
  also present on PhiUSIIL's own test split (51%) and on ranks 100k–1M (90%).
- Repeated domains: 3,000 hosts come from 1,537 registered domains (median 1, max 46 per domain). The domain-weighted FPR
  (each domain counted once) is 90.7% at alert, so repetition does not explain the bias.
- Label noise: popularity is used as a proxy for legitimacy; some popular hosts can be abused. Not verified site by site.

## Limitations

SHAP explains the raw XGBoost margin; correlated features share credit. The counterfactual changes several features at
once. The external sets are single snapshots from 2026-10-14/15.
