#!/usr/bin/env python3
"""
analyze_reports.py
------------------
Reads all vulnerability analysis markdown files from an input directory,
generates:
  1. analysis_results.csv   — one row per file with verdicts and match info
  2. performance_metrics.md — accuracy, precision, recall, F1 for each agent

Usage:
    python analyze_reports.py --input /path/to/md/files --output /path/to/output
    python analyze_reports.py --input ./reports                         # output defaults to ./output
    python analyze_reports.py                                           # input=./input, output=./output
"""

import os
import re
import json
import csv
import argparse
from pathlib import Path


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Parse vulnerability analysis MD files and generate CSV + metrics report."
    )
    parser.add_argument(
        "--input", "-i",
        default="./input",
        help="Directory containing .md analysis files (default: ./input)"
    )
    parser.add_argument(
        "--output", "-o",
        default="./",
        help="Directory to write output files (default: ./output)"
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def extract_json_block(text: str, start_marker: str) -> dict | None:
    """Find the first complete JSON object after start_marker in text."""
    idx = text.find(start_marker)
    if idx == -1:
        return None
    j_start = text.find('{', idx)
    if j_start == -1:
        return None
    depth = 0
    for i, c in enumerate(text[j_start:]):
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[j_start: j_start + i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def verdict_to_label(verdict: str) -> int | None:
    """Convert a verdict string to 0/1, or None if undecided."""
    v = verdict.upper()
    if v == "VULNERABLE":
        return 1
    if v == "SAFE":
        return 0
    return None  # ITERATE, MANUAL_REVIEW, UNKNOWN, etc.


def extract_case_number(filename: str) -> str:
    """
    Extract a meaningful case number from the filename.
    Examples:
        analysis_0042.md          -> 0042
        1772182652473_analysis_0000.md -> 0000
        report_123.md             -> 123
    Falls back to the full stem if no number is found.
    """
    stem = Path(filename).stem
    # Remove common prefixes like timestamps (long digit sequences at start)
    stem_clean = re.sub(r'^\d{10,}_', '', stem)          # strip leading timestamp_
    stem_clean = re.sub(r'analysis_?', '', stem_clean, flags=re.IGNORECASE)
    numbers = re.findall(r'\d+', stem_clean)
    return numbers[-1] if numbers else stem


# ---------------------------------------------------------------------------
# Per-file parsing
# ---------------------------------------------------------------------------

def parse_file(filepath: str) -> dict:
    """Parse a single analysis MD file and return a structured result dict."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    fname = os.path.basename(filepath)
    case_no = extract_case_number(fname)

    # ---- Ground truth ----
    gt_match = re.search(
        r'\*\*Label:\*\*\s*\d+\s*\((VULNERABLE|SAFE)\)',
        content, re.IGNORECASE
    )
    ground_truth = gt_match.group(1).upper() if gt_match else "UNKNOWN"

    # ---- Synthesizer (Agent 5) ----
    synth_json = extract_json_block(content, "Synthesizer's Verdict (Agent 5)")
    if synth_json is None:
        # Fallback: find the JSON block that contains preliminary_verdict
        synth_json = extract_json_block(content, '"preliminary_verdict"')
    if synth_json is None:
        # Last resort: search anywhere in the text
        for match in re.finditer(r'\{', content):
            candidate = _try_parse_json_at(content, match.start())
            if candidate and 'preliminary_verdict' in candidate:
                synth_json = candidate
                break

    synth_verdict = synth_json.get('preliminary_verdict', 'UNKNOWN').upper() if synth_json else 'UNKNOWN'
    synth_conf    = synth_json.get('confidence', 'UNKNOWN').upper()           if synth_json else 'UNKNOWN'

    # ---- Validator (Agent 6) ----
    val_json = extract_json_block(content, "Validator's Verdict (Agent 6)")
    if val_json is None:
        for match in re.finditer(r'\{', content):
            candidate = _try_parse_json_at(content, match.start())
            if candidate and 'validator_verdict' in candidate:
                val_json = candidate
                break

    val_verdict = val_json.get('validator_verdict', 'UNKNOWN').upper() if val_json else 'UNKNOWN'
    val_conf    = val_json.get('confidence', 'UNKNOWN').upper()         if val_json else 'UNKNOWN'

    # ---- Final Judge ----
    # Prefer the structured "## Final Verdict" section at the bottom of the file
    final_section = re.search(
        r'## Final Verdict\s+(.*?)(?=##|\Z)', content, re.DOTALL
    )
    if final_section:
        section_text = final_section.group(1)
        fv_match   = re.search(r'\*\*Verdict:\*\*\s*(VULNERABLE|SAFE|MANUAL_REVIEW|ITERATE)', section_text, re.IGNORECASE)
        fc_match   = re.search(r'\*\*Confidence:\*\*\s*(\w+)', section_text)
        final_verdict = fv_match.group(1).upper() if fv_match else 'UNKNOWN'
        final_conf    = fc_match.group(1).upper() if fc_match else 'UNKNOWN'
    else:
        # Fallback: look for Final Judge JSON block
        judge_json = extract_json_block(content, '"final_verdict"')
        final_verdict = judge_json.get('final_verdict', 'UNKNOWN').upper() if judge_json else 'UNKNOWN'
        final_conf    = judge_json.get('confidence', 'UNKNOWN').upper()     if judge_json else 'UNKNOWN'

    # ---- Match & error type ----
    gt_label    = verdict_to_label(ground_truth)
    final_label = verdict_to_label(final_verdict)

    if gt_label is None:
        match      = 'N/A'
        error_type = 'UNKNOWN_GT'
    elif final_label is None:
        match      = 'N/A'
        error_type = 'UNDECIDED'
    elif gt_label == final_label:
        match      = 'YES'
        error_type = 'None'
    else:
        match = 'NO'
        error_type = 'FN' if (gt_label == 1 and final_label == 0) else 'FP'

    return {
        'case_no':                case_no,
        'ground_truth':           ground_truth,
        'synthesizer_verdict':    synth_verdict,
        'synthesizer_confidence': synth_conf,
        'validator_verdict':      val_verdict,
        'validator_confidence':   val_conf,
        'final_verdict':          final_verdict,
        'final_confidence':       final_conf,
        'match':                  match,
        'error_type':             error_type,
        # internal labels for metrics
        '_gt_label':              gt_label,
        '_final_label':           final_label,
        '_synth_label':           verdict_to_label(synth_verdict),
        '_val_label':             verdict_to_label(val_verdict),
    }


def _try_parse_json_at(text: str, start: int) -> dict | None:
    """Try to parse a JSON object starting at position start."""
    depth = 0
    for i, c in enumerate(text[start:]):
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start: start + i + 1])
                except json.JSONDecodeError:
                    return None
    return None


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(preds: list, labels: list) -> dict:
    """
    Compute binary classification metrics.
    Skips pairs where either pred or label is None.
    """
    pairs = [(p, l) for p, l in zip(preds, labels) if p is not None and l is not None]
    n = len(pairs)
    if n == 0:
        return {'N': 0, 'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0,
                'Accuracy': 0.0, 'Precision': 0.0, 'Recall': 0.0, 'F1': 0.0}

    tp = sum(1 for p, l in pairs if p == 1 and l == 1)
    tn = sum(1 for p, l in pairs if p == 0 and l == 0)
    fp = sum(1 for p, l in pairs if p == 1 and l == 0)
    fn = sum(1 for p, l in pairs if p == 0 and l == 1)

    accuracy  = (tp + tn) / n
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    return {
        'N': n, 'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
        'Accuracy': accuracy, 'Precision': precision, 'Recall': recall, 'F1': f1
    }


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

CSV_FIELDS = [
    'case no', 'ground truth',
    'synthesizer verdict', 'synthesizer confidence',
    'validator verdict',   'validator confidence',
    'final verdict',       'final confidence',
    'match', 'error type'
]


def write_csv(rows: list[dict], output_path: str):
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in rows:
            writer.writerow({
                'case no':                  r['case_no'],
                'ground truth':             r['ground_truth'],
                'synthesizer verdict':      r['synthesizer_verdict'],
                'synthesizer confidence':   r['synthesizer_confidence'],
                'validator verdict':        r['validator_verdict'],
                'validator confidence':     r['validator_confidence'],
                'final verdict':            r['final_verdict'],
                'final confidence':         r['final_confidence'],
                'match':                    r['match'],
                'error type':               r['error_type'],
            })


def _metrics_table(m: dict) -> str:
    lines = [
        "| Metric    | Value  |",
        "|-----------|--------|",
    ]
    for key in ['N', 'TP', 'TN', 'FP', 'FN']:
        lines.append(f"| {key:<9} | {m.get(key, 0)} |")
    for key in ['Accuracy', 'Precision', 'Recall', 'F1']:
        lines.append(f"| {key:<9} | {m.get(key, 0.0):.4f} |")
    return '\n'.join(lines)


def write_metrics_md(rows: list[dict], output_path: str):
    gt_labels    = [r['_gt_label']    for r in rows]
    synth_labels = [r['_synth_label'] for r in rows]
    val_labels   = [r['_val_label']   for r in rows]
    final_labels = [r['_final_label'] for r in rows]

    synth_m = compute_metrics(synth_labels, gt_labels)
    val_m   = compute_metrics(val_labels,   gt_labels)
    final_m = compute_metrics(final_labels, gt_labels)

    # Disagreement counts
    synth_right = 0
    val_right   = 0
    for r in rows:
        sp, vp, gl = r['_synth_label'], r['_val_label'], r['_gt_label']
        if sp is not None and vp is not None and gl is not None and sp != vp:
            if sp == gl:
                synth_right += 1
            elif vp == gl:
                val_right += 1

    # Error breakdown
    total     = len(rows)
    correct   = sum(1 for r in rows if r['match'] == 'YES')
    fp_count  = sum(1 for r in rows if r['error_type'] == 'FP')
    fn_count  = sum(1 for r in rows if r['error_type'] == 'FN')
    undecided = sum(1 for r in rows if r['error_type'] in ('UNDECIDED', 'UNKNOWN_GT'))

    md = f"""# Vulnerability Analysis — Performance Metrics Report

**Total Files Processed:** {total}  
**Correct Predictions (Final Judge):** {correct} / {total}  
**False Positives:** {fp_count} | **False Negatives:** {fn_count} | **Undecided / Unknown:** {undecided}

---

## Agent Performance Summary

### Synthesizer (Agent 5)

{_metrics_table(synth_m)}

---

### Validator (Agent 6)

{_metrics_table(val_m)}

---

### Final Judge

{_metrics_table(final_m)}

---

## Synthesizer vs Validator Disagreement Analysis

| Scenario | Count |
|----------|-------|
| Disagreed — **Synthesizer was correct** | {synth_right} |
| Disagreed — **Validator was correct**   | {val_right}   |

---

## Per-Case Error Summary

| Case No | Ground Truth | Final Verdict | Match | Error Type |
|---------|--------------|---------------|-------|------------|
"""
    for r in rows:
        md += (f"| {r['case_no']} | {r['ground_truth']} "
               f"| {r['final_verdict']} | {r['match']} | {r['error_type']} |\n")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(md)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    input_dir  = Path(args.input)
    output_dir = Path(args.output)

    if not input_dir.exists():
        print(f"[ERROR] Input directory not found: {input_dir}")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    md_files = sorted(input_dir.glob("*.md"))
    if not md_files:
        print(f"[WARNING] No .md files found in: {input_dir}")
        return

    print(f"Found {len(md_files)} markdown file(s) in '{input_dir}'. Parsing...\n")

    rows = []
    failed = []
    for filepath in md_files:
        try:
            row = parse_file(str(filepath))
            rows.append(row)
            status = "✓" if row['match'] == 'YES' else ("✗" if row['match'] == 'NO' else "?")
            print(f"  [{status}] {filepath.name:<50}  GT={row['ground_truth']:<10}  "
                  f"Final={row['final_verdict']:<10}  Match={row['match']}")
        except Exception as e:
            failed.append(filepath.name)
            print(f"  [!] {filepath.name} — FAILED: {e}")

    print(f"\n{'─'*60}")
    print(f"  Parsed:  {len(rows)} files")
    if failed:
        print(f"  Failed:  {len(failed)} files → {', '.join(failed)}")

    # Write outputs
    csv_path = output_dir / "analysis_results.csv"
    md_path  = output_dir / "performance_metrics.md"

    write_csv(rows, str(csv_path))
    write_metrics_md(rows, str(md_path))

    print(f"\n  Output CSV     → {csv_path}")
    print(f"  Output Metrics → {md_path}")
    print(f"{'─'*60}\nDone.\n")


if __name__ == "__main__":
    main()
