# Vulnerability Analysis — Performance Metrics Report

**Total Files Processed:** 50  
**Correct Predictions (Final Judge):** 28 / 50  
**False Positives:** 11 | **False Negatives:** 9 | **Undecided / Unknown:** 2

---

## Agent Performance Summary

### Synthesizer (Agent 5)

| Metric    | Value  |
|-----------|--------|
| N         | 44 |
| TP        | 0 |
| TN        | 27 |
| FP        | 0 |
| FN        | 17 |
| Accuracy  | 0.6136 |
| Precision | 0.0000 |
| Recall    | 0.0000 |
| F1        | 0.0000 |

---

### Validator (Agent 6)

| Metric    | Value  |
|-----------|--------|
| N         | 48 |
| TP        | 10 |
| TN        | 18 |
| FP        | 11 |
| FN        | 9 |
| Accuracy  | 0.5833 |
| Precision | 0.4762 |
| Recall    | 0.5263 |
| F1        | 0.5000 |

---

### Final Judge

| Metric    | Value  |
|-----------|--------|
| N         | 48 |
| TP        | 10 |
| TN        | 18 |
| FP        | 11 |
| FN        | 9 |
| Accuracy  | 0.5833 |
| Precision | 0.4762 |
| Recall    | 0.5263 |
| F1        | 0.5000 |

---

## Synthesizer vs Validator Disagreement Analysis

| Scenario | Count |
|----------|-------|
| Disagreed — **Synthesizer was correct** | 10 |
| Disagreed — **Validator was correct**   | 8   |

---

## Per-Case Error Summary

| Case No | Ground Truth | Final Verdict | Match | Error Type |
|---------|--------------|---------------|-------|------------|
| 0000 | SAFE | SAFE | YES | None |
| 0001 | SAFE | VULNERABLE | NO | FP |
| 0002 | SAFE | VULNERABLE | NO | FP |
| 0003 | SAFE | VULNERABLE | NO | FP |
| 0004 | SAFE | VULNERABLE | NO | FP |
| 0005 | SAFE | UNKNOWN | N/A | UNDECIDED |
| 0006 | SAFE | VULNERABLE | NO | FP |
| 0007 | SAFE | VULNERABLE | NO | FP |
| 0008 | SAFE | VULNERABLE | NO | FP |
| 0009 | SAFE | SAFE | YES | None |
| 0010 | SAFE | SAFE | YES | None |
| 0011 | SAFE | VULNERABLE | NO | FP |
| 0012 | SAFE | SAFE | YES | None |
| 0013 | SAFE | SAFE | YES | None |
| 0014 | SAFE | VULNERABLE | NO | FP |
| 0015 | SAFE | SAFE | YES | None |
| 0016 | SAFE | SAFE | YES | None |
| 0017 | SAFE | SAFE | YES | None |
| 0018 | SAFE | VULNERABLE | NO | FP |
| 0019 | SAFE | VULNERABLE | NO | FP |
| 0020 | SAFE | SAFE | YES | None |
| 0021 | SAFE | SAFE | YES | None |
| 0022 | SAFE | SAFE | YES | None |
| 0023 | SAFE | SAFE | YES | None |
| 0024 | SAFE | SAFE | YES | None |
| 0025 | SAFE | SAFE | YES | None |
| 0026 | SAFE | SAFE | YES | None |
| 0027 | SAFE | SAFE | YES | None |
| 0028 | SAFE | SAFE | YES | None |
| 0029 | SAFE | SAFE | YES | None |
| 0030 | VULNERABLE | SAFE | NO | FN |
| 0031 | VULNERABLE | VULNERABLE | YES | None |
| 0032 | VULNERABLE | VULNERABLE | YES | None |
| 0033 | VULNERABLE | UNKNOWN | N/A | UNDECIDED |
| 0034 | VULNERABLE | VULNERABLE | YES | None |
| 0035 | VULNERABLE | SAFE | NO | FN |
| 0036 | VULNERABLE | VULNERABLE | YES | None |
| 0037 | VULNERABLE | VULNERABLE | YES | None |
| 0038 | VULNERABLE | SAFE | NO | FN |
| 0039 | VULNERABLE | VULNERABLE | YES | None |
| 0040 | VULNERABLE | VULNERABLE | YES | None |
| 0041 | VULNERABLE | SAFE | NO | FN |
| 0042 | VULNERABLE | VULNERABLE | YES | None |
| 0043 | VULNERABLE | SAFE | NO | FN |
| 0044 | VULNERABLE | SAFE | NO | FN |
| 0045 | VULNERABLE | VULNERABLE | YES | None |
| 0046 | VULNERABLE | VULNERABLE | YES | None |
| 0047 | VULNERABLE | SAFE | NO | FN |
| 0048 | VULNERABLE | SAFE | NO | FN |
| 0049 | VULNERABLE | SAFE | NO | FN |
