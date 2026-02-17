# Multi-Agent Vulnerability Detection - Summary Report

**Date:** 2026-02-17 00:03:51
**Model:** gpt-4o-mini
**Total Samples:** 50

## Overall Metrics

- **Accuracy:** 22/50 (44.00%)
- **Precision:** 0.5278 (52.78%)
- **Recall:** 0.6333 (63.33%)
- **F1 Score:** 0.5758 (57.58%)

## Error Analysis

- **True Positives:** 19
- **True Negatives:** 3
- **False Positives:** 17 (34.00%)
- **False Negatives:** 11 (22.00%)
- **Manual Review Needed:** 0 (0.00%)

## Iteration Statistics

- **Total Iterations:** 50
- **Average Iterations per Sample:** 1.00
- **Samples Requiring Refinement:** 0 (0.00%)

## Detailed Results

| Index | Ground Truth | Prediction | Confidence | Iterations | Correct | Error Type |
|-------|--------------|------------|------------|------------|---------|------------|
| 0000 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0001 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0002 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0003 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0004 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0005 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0006 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0007 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0008 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0009 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0010 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0011 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0012 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0013 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0014 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0015 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0016 | SAFE | SAFE | HIGH | 1 | ✅ | - |
| 0017 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0018 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0019 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0020 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0021 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0022 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0023 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0024 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0025 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0026 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0027 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0028 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0029 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0030 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0031 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0032 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0033 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0034 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0035 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0036 | VUL | VUL | HIGH | 1 | ✅ | - |
| 0037 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0038 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0039 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0040 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0041 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0042 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0043 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0044 | SAFE | VUL | MEDIUM | 1 | ❌ | FP |
| 0045 | VUL | SAFE | HIGH | 1 | ❌ | FN |
| 0046 | VUL | VUL | MEDIUM | 1 | ✅ | - |
| 0047 | SAFE | VUL | HIGH | 1 | ❌ | FP |
| 0048 | SAFE | SAFE | MEDIUM | 1 | ✅ | - |
| 0049 | VUL | SAFE | HIGH | 1 | ❌ | FN |
