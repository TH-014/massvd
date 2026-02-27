# Vulnerability Analysis — Performance Metrics Report

**Total Files Processed:** 50  
**Correct Predictions (Final Judge):** 22 / 50  
**False Positives:** 17 | **False Negatives:** 11 | **Undecided / Unknown:** 0

---

## Agent Performance Summary

### Synthesizer (Agent 5)

| Metric    | Value  |
|-----------|--------|
| N         | 34 |
| TP        | 1 |
| TN        | 12 |
| FP        | 1 |
| FN        | 20 |
| Accuracy  | 0.3824 |
| Precision | 0.5000 |
| Recall    | 0.0476 |
| F1        | 0.0870 |

---

### Validator (Agent 6)

| Metric    | Value  |
|-----------|--------|
| N         | 48 |
| TP        | 17 |
| TN        | 3 |
| FP        | 17 |
| FN        | 11 |
| Accuracy  | 0.4167 |
| Precision | 0.5000 |
| Recall    | 0.6071 |
| F1        | 0.5484 |

---

### Final Judge

| Metric    | Value  |
|-----------|--------|
| N         | 50 |
| TP        | 19 |
| TN        | 3 |
| FP        | 17 |
| FN        | 11 |
| Accuracy  | 0.4400 |
| Precision | 0.5278 |
| Recall    | 0.6333 |
| F1        | 0.5758 |

---

## Synthesizer vs Validator Disagreement Analysis

| Scenario | Count |
|----------|-------|
| Disagreed — **Synthesizer was correct** | 9 |
| Disagreed — **Validator was correct**   | 9   |

---

## Per-Case Error Summary

| Case No | Ground Truth | Final Verdict | Match | Error Type |
|---------|--------------|---------------|-------|------------|
| 0000 | SAFE | VULNERABLE | NO | FP |
| 0001 | VULNERABLE | VULNERABLE | YES | None |
| 0002 | VULNERABLE | VULNERABLE | YES | None |
| 0003 | SAFE | VULNERABLE | NO | FP |
| 0004 | SAFE | VULNERABLE | NO | FP |
| 0005 | SAFE | SAFE | YES | None |
| 0006 | VULNERABLE | VULNERABLE | YES | None |
| 0007 | VULNERABLE | VULNERABLE | YES | None |
| 0008 | SAFE | VULNERABLE | NO | FP |
| 0009 | VULNERABLE | VULNERABLE | YES | None |
| 0010 | VULNERABLE | VULNERABLE | YES | None |
| 0011 | VULNERABLE | SAFE | NO | FN |
| 0012 | VULNERABLE | VULNERABLE | YES | None |
| 0013 | SAFE | VULNERABLE | NO | FP |
| 0014 | SAFE | VULNERABLE | NO | FP |
| 0015 | SAFE | VULNERABLE | NO | FP |
| 0016 | SAFE | SAFE | YES | None |
| 0017 | VULNERABLE | SAFE | NO | FN |
| 0018 | SAFE | VULNERABLE | NO | FP |
| 0019 | VULNERABLE | VULNERABLE | YES | None |
| 0020 | VULNERABLE | VULNERABLE | YES | None |
| 0021 | VULNERABLE | SAFE | NO | FN |
| 0022 | VULNERABLE | VULNERABLE | YES | None |
| 0023 | VULNERABLE | SAFE | NO | FN |
| 0024 | VULNERABLE | VULNERABLE | YES | None |
| 0025 | VULNERABLE | VULNERABLE | YES | None |
| 0026 | VULNERABLE | SAFE | NO | FN |
| 0027 | SAFE | VULNERABLE | NO | FP |
| 0028 | VULNERABLE | VULNERABLE | YES | None |
| 0029 | VULNERABLE | SAFE | NO | FN |
| 0030 | SAFE | VULNERABLE | NO | FP |
| 0031 | SAFE | VULNERABLE | NO | FP |
| 0032 | VULNERABLE | VULNERABLE | YES | None |
| 0033 | VULNERABLE | VULNERABLE | YES | None |
| 0034 | VULNERABLE | SAFE | NO | FN |
| 0035 | VULNERABLE | VULNERABLE | YES | None |
| 0036 | VULNERABLE | VULNERABLE | YES | None |
| 0037 | SAFE | VULNERABLE | NO | FP |
| 0038 | SAFE | VULNERABLE | NO | FP |
| 0039 | SAFE | VULNERABLE | NO | FP |
| 0040 | VULNERABLE | SAFE | NO | FN |
| 0041 | VULNERABLE | VULNERABLE | YES | None |
| 0042 | VULNERABLE | SAFE | NO | FN |
| 0043 | SAFE | VULNERABLE | NO | FP |
| 0044 | SAFE | VULNERABLE | NO | FP |
| 0045 | VULNERABLE | SAFE | NO | FN |
| 0046 | VULNERABLE | VULNERABLE | YES | None |
| 0047 | SAFE | VULNERABLE | NO | FP |
| 0048 | SAFE | SAFE | YES | None |
| 0049 | VULNERABLE | SAFE | NO | FN |
