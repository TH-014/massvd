# Multi-Agent Vulnerability Detection - Summary Report

**Date:** 2026-02-17 02:19:18
**Model:** gpt-4o-mini
**Total Samples:** 100

## Overall Metrics

- **Accuracy:** 56/100 (56.00%)
- **Precision:** 0.5581 (55.81%)
- **Recall:** 0.8889 (88.89%)
- **F1 Score:** 0.6857 (68.57%)

## Error Analysis

- **True Positives:** 48
- **True Negatives:** 8
- **False Positives:** 38 (38.00%)
- **False Negatives:** 6 (6.00%)
- **Manual Review Needed:** 0 (0.00%)

## Iteration Statistics

- **Total Iterations:** 100
- **Average Iterations per Sample:** 1.00
- **Samples Requiring Refinement:** 0 (0.00%)

## Detailed Results

| Index | Ground Truth | Prediction | Confidence | Iterations | Correct | Error Type |
|-------|--------------|------------|------------|------------|---------|------------|
| 0000 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0001 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0002 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0003 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0004 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0005 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0006 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0007 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0008 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0009 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0010 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0011 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0012 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0013 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0014 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0015 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0016 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0017 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0018 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0019 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0020 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0021 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0022 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0023 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0024 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0025 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0026 | VUL | SAFE | MEDIUM | 1 | ❌ | FN |
| 0027 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0028 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0029 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0030 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0031 | SAFE | SAFE | MEDIUM | 1 | ✅ | - |
| 0032 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0033 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0034 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0035 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0036 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0037 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0038 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0039 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0040 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0041 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0042 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0043 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0044 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0045 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0046 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0047 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0048 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0049 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0050 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0051 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0052 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0053 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0054 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0055 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0056 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0057 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0058 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0059 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0060 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0061 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0062 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0063 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0064 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0065 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0066 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0067 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0068 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0069 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0070 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0071 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0072 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0073 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0074 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0075 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0076 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0077 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0078 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0079 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0080 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0081 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0082 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0083 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0084 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0085 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0086 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0087 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0088 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0089 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0090 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0091 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0092 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0093 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0094 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0095 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0096 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0097 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0098 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0099 | VUL | VUL | HIGH | 1 | ✅ | - |
