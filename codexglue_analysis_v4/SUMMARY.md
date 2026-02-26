# Multi-Agent Vulnerability Detection - Summary Report

**Date:** 2026-02-26 18:19:08
**Model:** gpt-4o-mini
**Total Samples:** 35
**Maximum Context Limit:** 3

## Overall Metrics

- **Accuracy:** 12/35 (34.29%)
- **Precision:** 0.4375 (43.75%)
- **Recall:** 0.3889 (38.89%)
- **F1 Score:** 0.4118 (41.18%)

## Error Analysis

- **True Positives:** 7
- **True Negatives:** 5
- **False Positives:** 9 (25.71%)
- **False Negatives:** 11 (31.43%)
- **Manual Review Needed:** 3 (8.57%)

## Iteration & Context Statistics

- **Total Iterations:** 55
- **Average Iterations per Sample:** 1.57
- **Total Context Requests:** 7
- **Average Context Requests per Sample:** 0.20
- **Samples Requiring Refinement:** 0 (0.00%)

## Detailed Results

| Index | Ground Truth | Prediction | Confidence | Iterations | Ctx Reqs | Correct | Error |
|-------|--------------|------------|------------|------------|----------|---------|-------|
| 0000 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0001 | SAFE | VUL | HIGH | 2 | 0 | ❌ | FP |
| 0002 | SAFE | MR | LOW | 2 | 0 | ❌ | - |
| 0003 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0004 | VUL | VUL | HIGH | 2 | 0 | ✅ | - |
| 0005 | SAFE | VUL | HIGH | 2 | 0 | ❌ | FP |
| 0006 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0007 | VUL | VUL | HIGH | 2 | 0 | ✅ | - |
| 0008 | SAFE | SAFE | HIGH | 2 | 1 | ✅ | - |
| 0009 | SAFE | SAFE | HIGH | 1 | 0 | ✅ | - |
| 0010 | SAFE | VUL | HIGH | 2 | 0 | ❌ | FP |
| 0011 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0012 | SAFE | MR | LOW | 2 | 1 | ❌ | - |
| 0013 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0014 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0015 | VUL | VUL | HIGH | 2 | 1 | ✅ | - |
| 0016 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0017 | SAFE | VUL | HIGH | 2 | 0 | ❌ | FP |
| 0018 | VUL | VUL | HIGH | 2 | 0 | ✅ | - |
| 0019 | SAFE | SAFE | HIGH | 1 | 0 | ✅ | - |
| 0020 | SAFE | VUL | HIGH | 2 | 0 | ❌ | FP |
| 0021 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0022 | VUL | SAFE | MEDIUM | 1 | 0 | ❌ | FN |
| 0023 | VUL | VUL | HIGH | 2 | 0 | ✅ | - |
| 0024 | VUL | VUL | HIGH | 2 | 1 | ✅ | - |
| 0025 | SAFE | SAFE | HIGH | 1 | 0 | ✅ | - |
| 0026 | SAFE | VUL | HIGH | 2 | 1 | ❌ | FP |
| 0027 | SAFE | VUL | HIGH | 2 | 0 | ❌ | FP |
| 0028 | VUL | SAFE | HIGH | 1 | 0 | ❌ | FN |
| 0029 | SAFE | VUL | HIGH | 2 | 0 | ❌ | FP |
| 0030 | SAFE | SAFE | MEDIUM | 1 | 0 | ✅ | - |
| 0031 | VUL | VUL | HIGH | 2 | 0 | ✅ | - |
| 0032 | SAFE | VUL | HIGH | 2 | 1 | ❌ | FP |
| 0033 | SAFE | MR | LOW | 2 | 1 | ❌ | - |
| 0034 | VUL | SAFE | MEDIUM | 1 | 0 | ❌ | FN |
