# Detection evaluation (generated 2026-10-31 by evaluation/run_eval.py, EmailShield 2.3.0)

## Dataset
56 synthetic emails: 29 malicious-delivery, 27 legitimate. Harmless by construction: fictional domains, inert marker bytes, no real malware or personal data. Generated deterministically by `evaluation/build_dataset.py` (fixed seed).

## Method
Each file is parsed and scored by the same engine the application uses (no database, no threat-intel). A message counts as *flagged* when its score meets the threshold. Positive class = malicious. Thresholds are the defaults in `config.py`; they were **not tuned** to this dataset.

## Results

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|---|---|---|
| Suspicious or higher (score >= 30) | 23 | 6 | 21 | 6 | 79.3% | 79.3% | 79.3% | 22.2% |
| High risk only (score >= 70) | 9 | 0 | 27 | 20 | 100.0% | 31.0% | 47.4% | 0.0% |

## Processing latency (parse + score, one message at a time, no network)

n=56  median 2.21 ms  p95 3.71 ms  max 3.85 ms  (measured on Linux x86_64, Python 3.12.3; NOT your laptop)

## Misclassified at the 'Suspicious or higher' threshold

| File | Truth | Score | Category | Why (rules that fired) | Group |
|---|---|---|---|---|---|
| ben_hard_esp_0.eml | legitimate | 35 | Suspicious | reply_to_mismatch, kw_payment, return_path_mismatch | hard-negative: billing via mail platform |
| ben_hard_esp_1.eml | legitimate | 35 | Suspicious | reply_to_mismatch, kw_payment, return_path_mismatch | hard-negative: billing via mail platform |
| ben_hard_esp_2.eml | legitimate | 35 | Suspicious | reply_to_mismatch, kw_payment, return_path_mismatch | hard-negative: billing via mail platform |
| ben_hard_esp_3.eml | legitimate | 35 | Suspicious | reply_to_mismatch, kw_payment, return_path_mismatch | hard-negative: billing via mail platform |
| ben_hard_att_0.eml | legitimate | 35 | Suspicious | att_macro, kw_payment, kw_urgency | hard-negative: macro/zip attachments from colleague |
| ben_hard_att_1.eml | legitimate | 35 | Suspicious | att_macro, kw_payment, kw_urgency | hard-negative: macro/zip attachments from colleague |
| mal_hard_giftcard.eml | malicious | 12 | Low risk | kw_payment | hard-positive: BEC gift card, no links |
| mal_hard_cleanlink.eml | malicious | 0 | Low risk | nothing fired | hard-positive: compromised account, clean link |
| mal_hard_https_verify.eml | malicious | 15 | Low risk | kw_credentials | hard-positive: new domain, HTTPS, calm wording |
| mal_hard_callback.eml | malicious | 12 | Low risk | kw_payment | hard-positive: callback phishing, no link |
| mal_hard_qr.eml | malicious | 0 | Low risk | nothing fired | hard-positive: QR-code image only |
| mal_hard_zip_pw.eml | malicious | 23 | Low risk | kw_credentials, att_archive | hard-positive: password-protected archive |

## By scenario

| Scenario | n | Flagged |
|---|---|---|
| easy: IP-address link | 3 | 3 |
| easy: double-extension executable | 3 | 3 |
| easy: lookalike domain phish | 6 | 6 |
| hard-negative: billing via mail platform | 4 | 4 |
| hard-negative: exported without auth headers | 1 | 0 |
| hard-negative: forwarded mail failing SPF/DKIM | 3 | 0 |
| hard-negative: legit password reset | 3 | 0 |
| hard-negative: macro/zip attachments from colleague | 3 | 2 |
| hard-negative: shortener link | 1 | 0 |
| hard-positive: BEC gift card, no links | 1 | 0 |
| hard-positive: QR-code image only | 1 | 0 |
| hard-positive: callback phishing, no link | 1 | 0 |
| hard-positive: compromised account, clean link | 1 | 0 |
| hard-positive: new domain, HTTPS, calm wording | 1 | 0 |
| hard-positive: password-protected archive | 1 | 0 |
| medium: executable disguised as PDF | 2 | 2 |
| medium: macro document with pressure | 2 | 2 |
| medium: mismatched link text, clean auth | 4 | 4 |
| medium: reply-to hijack with urgency | 3 | 3 |
| ordinary | 12 | 0 |

## Limitations (read before quoting any number)
- Small dataset: each percentage moves several points per single email; no confidence intervals are given.
- **Author bias**: the samples were written by the same developer who wrote the rules, so results are optimistic and say nothing about real-world traffic.
- Synthetic emails lack the noise, languages, formatting and volume of real mail; the legitimate class is probably easier than reality.
- Hard-positive samples (no links, clean authentication, text-only lures, QR codes) are included on purpose; misses there are expected for a rule-based engine and show what it cannot see.
- Threat intelligence, attachment sandboxing and content analysis are not part of this measurement.
- This is **not** a production accuracy claim.
