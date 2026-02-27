# Vulnerability Analysis — Performance Metrics Report

**Total Files Processed:** 100  
**Correct Predictions (Final Judge):** 53 / 100  
**False Positives:** 38 | **False Negatives:** 6 | **Undecided / Unknown:** 3

---

## Agent Performance Summary

### Synthesizer (Agent 5)

| Metric    | Value  |
|-----------|--------|
| N         | 63 |
| TP        | 22 |
| TN        | 20 |
| FP        | 8 |
| FN        | 13 |
| Accuracy  | 0.6667 |
| Precision | 0.7333 |
| Recall    | 0.6286 |
| F1        | 0.6769 |

---

### Validator (Agent 6)

| Metric    | Value  |
|-----------|--------|
| N         | 94 |
| TP        | 44 |
| TN        | 8 |
| FP        | 36 |
| FN        | 6 |
| Accuracy  | 0.5532 |
| Precision | 0.5500 |
| Recall    | 0.8800 |
| F1        | 0.6769 |

---

### Final Judge

| Metric    | Value  |
|-----------|--------|
| N         | 97 |
| TP        | 45 |
| TN        | 8 |
| FP        | 38 |
| FN        | 6 |
| Accuracy  | 0.5464 |
| Precision | 0.5422 |
| Recall    | 0.8824 |
| F1        | 0.6716 |

---

## Synthesizer vs Validator Disagreement Analysis

| Scenario | Count |
|----------|-------|
| Disagreed — **Synthesizer was correct** | 12 |
| Disagreed — **Validator was correct**   | 7   |

---

## Per-Case Error Summary

| Case No | Ground Truth | Final Verdict | Match | Error Type |
|---------|--------------|---------------|-------|------------|
| 0000 | VULNERABLE | VULNERABLE | YES | None |
| 0001 | SAFE | VULNERABLE | NO | FP |
| 0002 | VULNERABLE | VULNERABLE | YES | None |
| 0003 | SAFE | VULNERABLE | NO | FP |
| 0004 | VULNERABLE | VULNERABLE | YES | None |
| 0005 | VULNERABLE | VULNERABLE | YES | None |
| 0006 | SAFE | VULNERABLE | NO | FP |
| 0007 | VULNERABLE | VULNERABLE | YES | None |
| 0008 | VULNERABLE | VULNERABLE | YES | None |
| 0009 | SAFE | VULNERABLE | NO | FP |
| 0010 | SAFE | VULNERABLE | NO | FP |
| 0011 | VULNERABLE | VULNERABLE | YES | None |
| 0012 | SAFE | VULNERABLE | NO | FP |
| 0013 | SAFE | VULNERABLE | NO | FP |
| 0014 | SAFE | SAFE | YES | None |
| 0015 | VULNERABLE | VULNERABLE | YES | None |
| 0016 | VULNERABLE | VULNERABLE | YES | None |
| 0017 | SAFE | VULNERABLE | NO | FP |
| 0018 | VULNERABLE | VULNERABLE | YES | None |
| 0019 | SAFE | VULNERABLE | NO | FP |
| 0020 | SAFE | SAFE | YES | None |
| 0021 | VULNERABLE | VULNERABLE | YES | None |
| 0022 | SAFE | VULNERABLE | NO | FP |
| 0023 | VULNERABLE | UNKNOWN | N/A | UNDECIDED |
| 0024 | SAFE | VULNERABLE | NO | FP |
| 0025 | VULNERABLE | VULNERABLE | YES | None |
| 0026 | VULNERABLE | SAFE | NO | FN |
| 0027 | SAFE | VULNERABLE | NO | FP |
| 0028 | SAFE | VULNERABLE | NO | FP |
| 0029 | VULNERABLE | VULNERABLE | YES | None |
| 0030 | VULNERABLE | VULNERABLE | YES | None |
| 0031 | SAFE | SAFE | YES | None |
| 0032 | VULNERABLE | VULNERABLE | YES | None |
| 0033 | VULNERABLE | VULNERABLE | YES | None |
| 0034 | VULNERABLE | UNKNOWN | N/A | UNDECIDED |
| 0035 | VULNERABLE | VULNERABLE | YES | None |
| 0036 | SAFE | VULNERABLE | NO | FP |
| 0037 | VULNERABLE | VULNERABLE | YES | None |
| 0038 | VULNERABLE | UNKNOWN | N/A | UNDECIDED |
| 0039 | SAFE | VULNERABLE | NO | FP |
| 0040 | SAFE | VULNERABLE | NO | FP |
| 0041 | VULNERABLE | VULNERABLE | YES | None |
| 0042 | SAFE | VULNERABLE | NO | FP |
| 0043 | SAFE | VULNERABLE | NO | FP |
| 0044 | VULNERABLE | VULNERABLE | YES | None |
| 0045 | VULNERABLE | VULNERABLE | YES | None |
| 0046 | SAFE | VULNERABLE | NO | FP |
| 0047 | SAFE | VULNERABLE | NO | FP |
| 0048 | SAFE | VULNERABLE | NO | FP |
| 0049 | VULNERABLE | VULNERABLE | YES | None |
| 0050 | VULNERABLE | VULNERABLE | YES | None |
| 0051 | SAFE | VULNERABLE | NO | FP |
| 0052 | VULNERABLE | VULNERABLE | YES | None |
| 0053 | SAFE | SAFE | YES | None |
| 0054 | SAFE | VULNERABLE | NO | FP |
| 0055 | VULNERABLE | VULNERABLE | YES | None |
| 0056 | VULNERABLE | VULNERABLE | YES | None |
| 0057 | SAFE | VULNERABLE | NO | FP |
| 0058 | SAFE | VULNERABLE | NO | FP |
| 0059 | SAFE | VULNERABLE | NO | FP |
| 0060 | SAFE | VULNERABLE | NO | FP |
| 0061 | VULNERABLE | VULNERABLE | YES | None |
| 0062 | VULNERABLE | SAFE | NO | FN |
| 0063 | VULNERABLE | SAFE | NO | FN |
| 0064 | VULNERABLE | VULNERABLE | YES | None |
| 0065 | SAFE | SAFE | YES | None |
| 0066 | VULNERABLE | VULNERABLE | YES | None |
| 0067 | VULNERABLE | VULNERABLE | YES | None |
| 0068 | SAFE | VULNERABLE | NO | FP |
| 0069 | VULNERABLE | VULNERABLE | YES | None |
| 0070 | VULNERABLE | VULNERABLE | YES | None |
| 0071 | SAFE | VULNERABLE | NO | FP |
| 0072 | VULNERABLE | VULNERABLE | YES | None |
| 0073 | VULNERABLE | SAFE | NO | FN |
| 0074 | VULNERABLE | SAFE | NO | FN |
| 0075 | SAFE | VULNERABLE | NO | FP |
| 0076 | VULNERABLE | VULNERABLE | YES | None |
| 0077 | SAFE | SAFE | YES | None |
| 0078 | VULNERABLE | SAFE | NO | FN |
| 0079 | VULNERABLE | VULNERABLE | YES | None |
| 0080 | SAFE | SAFE | YES | None |
| 0081 | VULNERABLE | VULNERABLE | YES | None |
| 0082 | VULNERABLE | VULNERABLE | YES | None |
| 0083 | SAFE | VULNERABLE | NO | FP |
| 0084 | VULNERABLE | VULNERABLE | YES | None |
| 0085 | VULNERABLE | VULNERABLE | YES | None |
| 0086 | SAFE | VULNERABLE | NO | FP |
| 0087 | VULNERABLE | VULNERABLE | YES | None |
| 0088 | SAFE | VULNERABLE | NO | FP |
| 0089 | VULNERABLE | VULNERABLE | YES | None |
| 0090 | SAFE | VULNERABLE | NO | FP |
| 0091 | VULNERABLE | VULNERABLE | YES | None |
| 0092 | SAFE | VULNERABLE | NO | FP |
| 0093 | SAFE | SAFE | YES | None |
| 0094 | VULNERABLE | VULNERABLE | YES | None |
| 0095 | SAFE | VULNERABLE | NO | FP |
| 0096 | SAFE | VULNERABLE | NO | FP |
| 0097 | VULNERABLE | VULNERABLE | YES | None |
| 0098 | SAFE | VULNERABLE | NO | FP |
| 0099 | VULNERABLE | VULNERABLE | YES | None |
