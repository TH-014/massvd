#!/usr/bin/env python3
"""
Multi-Agent System for Security Vulnerability Detection - v2
Changes:
- Synthesizer can request function definitions from QEMU repo via ctags + git grep
- Parallel analysis is run on fetched function definitions too
- Synthesizer has a maximum_context_limit for how many times it can request more context
- If synthesizer says SAFE → final verdict is SAFE (no validator needed)
- If synthesizer says VULNERABLE → validator validates, then both go to final judge
"""

import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
import openai
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# QEMU Repo helpers
# ─────────────────────────────────────────────────────────────────────────────

QEMU_REPO = os.path.expanduser("~/Class_Mat/Thesis/Qemu/qemu")


def lookup_function_in_ctags(function_name: str) -> List[Tuple[str, str]]:
    """
    Use ctags to find which files contain the given function name.
    Returns a list of (function_name, relative_file_path) tuples.
    """
    tags_file = os.path.join(QEMU_REPO, "tags")
    results = []
    try:
        output = subprocess.check_output(
            ["grep", f"^{function_name}\t", tags_file],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in output.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                fname = parts[0]
                fpath = parts[1]
                results.append((fname, fpath))
    except subprocess.CalledProcessError:
        pass  # function not found
    except FileNotFoundError:
        print(f"Warning: ctags file not found at {tags_file}")
    return results


def fetch_function_definition(function_name: str, relative_path: str) -> Optional[str]:
    """
    Use git grep -Ww to fetch the full function definition from the QEMU repo.
    Returns the function source code as a string, or None if not found.
    """
    try:
        output = subprocess.check_output(
            ["git", "grep", "-Ww", function_name, relative_path],
            cwd=QEMU_REPO,
            text=True,
            stderr=subprocess.DEVNULL
        )
        return output.strip() if output.strip() else None
    except subprocess.CalledProcessError:
        return None
    except FileNotFoundError:
        print(f"Warning: git not found or QEMU repo not accessible at {QEMU_REPO}")
        return None


def get_function_source(function_name: str) -> Optional[Tuple[str, str, str]]:
    """
    Look up a function name via ctags and return its source.
    Returns (function_name, file_path, source_code) or None.
    Picks the first match that returns actual source.
    """
    matches = lookup_function_in_ctags(function_name)
    if not matches:
        return None
    for fname, fpath in matches:
        source = fetch_function_definition(function_name, fpath)
        if source:
            return (fname, fpath, source)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentResponse:
    agent_name: str
    system_prompt: str
    user_prompt: str
    response: str
    timestamp: str
    iteration: int = 0


@dataclass
class FunctionContext:
    """Holds fetched function definition and its parallel analysis results"""
    function_name: str
    file_path: str
    source_code: str
    context_analysis: Optional[AgentResponse] = None
    memory_analysis: Optional[AgentResponse] = None
    validation_analysis: Optional[AgentResponse] = None
    pattern_analysis: Optional[AgentResponse] = None


@dataclass
class AnalysisResult:
    index: int
    programming_language: str
    code_snippet: str
    ground_truth_label: int
    ground_truth_cwe: str

    context_analyzer: Optional[AgentResponse] = None
    memory_safety: Optional[AgentResponse] = None
    input_validation: Optional[AgentResponse] = None
    pattern_expert: Optional[AgentResponse] = None

    synthesizer: List[AgentResponse] = field(default_factory=list)
    validator: List[AgentResponse] = field(default_factory=list)
    final_judge: Optional[AgentResponse] = None

    # Extra function contexts fetched by synthesizer
    fetched_function_contexts: List[FunctionContext] = field(default_factory=list)
    context_requests: int = 0  # how many times synthesizer requested more context

    total_iterations: int = 0
    refinement_occurred: bool = False

    final_verdict: Optional[str] = None
    final_label: Optional[int] = None
    confidence: Optional[str] = None

    is_correct: Optional[bool] = None
    error_type: Optional[str] = None  # 'FP', 'FN', or None


# ─────────────────────────────────────────────────────────────────────────────
# Prompt Templates
# ─────────────────────────────────────────────────────────────────────────────

class PromptTemplates:

    @staticmethod
    def get_context_analyzer_prompts(code: str, language: str,
                                     func_name: str = "target function") -> Tuple[str, str]:
        system_prompt = """You are Agent 1: Context Analyzer in a multi-agent security vulnerability detection system.

Your SOLE purpose is to build context BEFORE security analysis begins. You do NOT flag vulnerabilities.

Your responsibilities:
1. Identify the framework/library being used (e.g., QEMU, Linux Kernel, glibc, custom)
2. Detect architectural patterns (ownership transfer, bounded buffers, guard clauses)
3. Find validation macros (e.g., TF_LITE_ENSURE, CHECK, ASSERT, bounds checks, g_assert)
4. Document safety contracts (pre-validated inputs, caller responsibilities)
5. Identify guard clauses and defensive programming patterns
6. Note all external function calls — these may be analyzed separately

CRITICAL: You must NOT make vulnerability judgments. Your job is only to provide context.

Output format (JSON):
{
    "framework": "name of framework or 'custom'",
    "patterns_detected": ["list of patterns found"],
    "validation_macros": ["list of macros/guards found"],
    "safety_contracts": ["documented safety assumptions"],
    "guard_clauses": ["identified guard conditions"],
    "external_calls": ["function names called but not defined here"],
    "context_summary": "brief summary of the code's context"
}"""

        user_prompt = f"""Analyze the following {language} function `{func_name}` and provide context:

```{language}
{code}
```

Remember: Only provide context. Do NOT flag vulnerabilities.
Make sure to list all external function calls in "external_calls"."""

        return system_prompt, user_prompt

    @staticmethod
    def get_memory_safety_prompts(code: str, language: str, context: str,
                                  func_name: str = "target function") -> Tuple[str, str]:
        system_prompt = """You are Agent 2: Memory Safety Analyst in a multi-agent security vulnerability detection system.

Your purpose is to analyze memory operations with CONTEXT AWARENESS.

ANTI-PATTERNS TO AVOID:
❌ DO NOT flag malloc/calloc/new by default
❌ DO NOT assume all pointers are unsafe
❌ DO NOT ignore ownership patterns
❌ DO NOT ignore wrapper functions that handle safety

What to check:
1. Buffer operations — are sizes validated?
2. Pointer arithmetic — are bounds checked?
3. Memory allocation — is NULL checked? Is size controlled?
4. Deallocation — any double-free or use-after-free?
5. Are there wrapper functions that handle safety?
6. Integer overflow in size computations

Consider the context provided by Agent 1. If validation macros or guard clauses exist, account for them.

Output format (JSON):
{
    "memory_issues_found": ["list of potential issues with line references"],
    "safe_patterns_found": ["list of safe patterns detected"],
    "requires_validation": ["operations that need validation checks"],
    "context_considerations": "how context affects analysis",
    "preliminary_verdict": "SAFE/SUSPICIOUS/VULNERABLE",
    "confidence": "HIGH/MEDIUM/LOW"
}"""

        user_prompt = f"""Analyze memory safety for function `{func_name}` ({language}):

```{language}
{code}
```

Context from Agent 1:
{context}

Analyze memory operations considering the provided context."""

        return system_prompt, user_prompt

    @staticmethod
    def get_input_validation_prompts(code: str, language: str, context: str,
                                     func_name: str = "target function") -> Tuple[str, str]:
        system_prompt = """You are Agent 3: Input Validation Specialist in a multi-agent security vulnerability detection system.

Your purpose is to detect missing validation while considering framework mechanisms.

What to check:
1. Are user inputs validated before use?
2. Are array indices bounds-checked?
3. Are string lengths verified?
4. Do framework macros provide validation (e.g., TF_LITE_ENSURE, g_return_if_fail)?
5. Are there implicit validations (fixed-size arrays, constants)?

IMPORTANT:
- Fixed-width types with constant sizes are safe
- Validation macros from frameworks COUNT as validation
- Guard clauses COUNT as validation

Output format (JSON):
{
    "inputs_identified": ["list of inputs found"],
    "validation_status": {"input_name": "VALIDATED/MISSING/IMPLICIT"},
    "framework_validations": ["macros or functions providing validation"],
    "missing_validations": ["inputs lacking validation"],
    "preliminary_verdict": "SAFE/SUSPICIOUS/VULNERABLE",
    "confidence": "HIGH/MEDIUM/LOW"
}"""

        user_prompt = f"""Analyze input validation for function `{func_name}` ({language}):

```{language}
{code}
```

Context from Agent 1:
{context}

Check for input validation considering framework mechanisms."""

        return system_prompt, user_prompt

    @staticmethod
    def get_pattern_expert_prompts(code: str, language: str, context: str,
                                   memory_analysis: str, validation_analysis: str,
                                   func_name: str = "target function") -> Tuple[str, str]:
        system_prompt = """You are Agent 4: Pattern Recognition Expert in a multi-agent security vulnerability detection system.

Your purpose is to identify safe and unsafe patterns, and you have OVERRIDE AUTHORITY over previous agents.

SAFE PATTERNS (Don't flag):
✅ Transfer of ownership (malloc then return, caller frees)
✅ Bounded ring buffers (wraparound with modulo)
✅ Guard-then-operate (check before use)
✅ RAII/Smart pointers (automatic cleanup)
✅ Const correctness (read-only access)
✅ Checked arithmetic wrappers

UNSAFE PATTERNS (Flag):
❌ Unbounded copy (strcpy, sprintf without bounds)
❌ TOCTOU races (time-of-check to time-of-use)
❌ Use-after-free
❌ Integer overflow in size calculations
❌ Format string vulnerabilities
❌ Off-by-one errors in bounds checks

KEY FEATURE: You can override false positives from Agents 2 and 3 if you detect safe patterns.

Output format (JSON):
{
    "safe_patterns": ["patterns that indicate safety"],
    "unsafe_patterns": ["patterns that indicate vulnerability"],
    "overrides": ["any false positives you're overriding from Agents 2/3"],
    "additional_concerns": ["new issues not caught by previous agents"],
    "preliminary_verdict": "SAFE/SUSPICIOUS/VULNERABLE",
    "confidence": "HIGH/MEDIUM/LOW"
}"""

        user_prompt = f"""Analyze patterns in function `{func_name}` ({language}):

```{language}
{code}
```

Context from Agent 1:
{context}

Memory Safety Analysis (Agent 2):
{memory_analysis}

Input Validation Analysis (Agent 3):
{validation_analysis}

Identify safe/unsafe patterns and override any false positives."""

        return system_prompt, user_prompt

    @staticmethod
    def get_synthesizer_prompts(
        code: str, language: str,
        all_analyses: Dict[str, str],
        extra_function_contexts: List[Dict],
        maximum_context_limit: int,
        contexts_used: int,
        iteration: int = 0,
        previous_feedback: str = None # type: ignore
    ) -> Tuple[str, str]:

        system_prompt = f"""You are Agent 5: Vulnerability Synthesizer in a multi-agent security vulnerability detection system.

Your purpose is to aggregate findings from all previous agents and make a FINAL decision.

=== CONTEXT FETCH CAPABILITY ===
You may request the definition of any external function called by the target function if you believe
it is critical to determining whether a vulnerability exists.

To request a function definition, include this in your JSON output:
  "request_function": "exact_function_name"

You have used {{contexts_used}} context requests so far. You may request at most {maximum_context_limit} total.
If you have reached the limit or do not need more context, set "request_function": null.

IMPORTANT: Only request a function if it is DIRECTLY relevant to a potential vulnerability path.
Do NOT request functions that are clearly utility wrappers or well-known safe functions (e.g., g_malloc0, strlen).

=== DECISION CRITERIA ===
- HIGH confidence: All agents agree + no conflicting safe patterns + clear evidence
- MEDIUM confidence: Some disagreement between agents OR mixed signals
- LOW confidence: Contradictions + safe patterns present OR unclear evidence

IMPORTANT PRINCIPLES:
- Be CONSERVATIVE: When in doubt, lean SAFE if there are defensive patterns
- TRUST validation macros and framework-specific safety mechanisms
- REQUIRE concrete evidence of exploitable vulnerability before flagging VULNERABLE

=== VERDICT FLOW ===
- If you verdict SAFE → your verdict is FINAL. No further agents will run.
- If you verdict VULNERABLE → a Validator agent will review your finding.

Output format (JSON):
{{
    "synthesis": "summary of all findings",
    "agreements": ["points where agents agree"],
    "conflicts": ["points where agents disagree"],
    "preliminary_verdict": "SAFE/VULNERABLE",
    "preliminary_label": 0,  // CRITICAL: 0 = SAFE, 1 = VULNERABLE
    "confidence": "HIGH/MEDIUM/LOW",
    "reasoning": "detailed explanation with specific code references",
    "key_evidence": ["most important evidence points"],
    "uncertainty_areas": ["areas where you're uncertain"],
    "request_function": null   // or "function_name" to fetch its definition
}}

LABEL MAPPING (CRITICAL):
- SAFE  → preliminary_label = 0
- VULNERABLE → preliminary_label = 1"""

        # Build extra context section
        extra_ctx_section = ""
        if extra_function_contexts:
            extra_ctx_section = "\n\n=== ADDITIONAL FUNCTION DEFINITIONS FETCHED ==="
            for fc in extra_function_contexts:
                extra_ctx_section += f"\n\n--- Function: {fc['function_name']} ({fc['file_path']}) ---\n"
                extra_ctx_section += f"Source:\n```c\n{fc['source_code']}\n```\n"
                if fc.get('context_analysis'):
                    extra_ctx_section += f"\nContext Analysis:\n{fc['context_analysis']}\n"
                if fc.get('memory_analysis'):
                    extra_ctx_section += f"\nMemory Analysis:\n{fc['memory_analysis']}\n"
                if fc.get('validation_analysis'):
                    extra_ctx_section += f"\nValidation Analysis:\n{fc['validation_analysis']}\n"
                if fc.get('pattern_analysis'):
                    extra_ctx_section += f"\nPattern Analysis:\n{fc['pattern_analysis']}\n"

        user_prompt = f"""Synthesize findings for this {language} code (Iteration {iteration + 1}):
Context requests used: {contexts_used}/{maximum_context_limit}

=== TARGET FUNCTION ===
```{language}
{code}
```

Agent 1 (Context Analyzer):
{all_analyses['context']}

Agent 2 (Memory Safety):
{all_analyses['memory']}

Agent 3 (Input Validation):
{all_analyses['validation']}

Agent 4 (Pattern Expert):
{all_analyses['patterns']}
{extra_ctx_section}"""

        if previous_feedback:
            user_prompt += f"""

=== VALIDATOR FEEDBACK FROM PREVIOUS ITERATION ===
{previous_feedback}

Please reconsider your analysis in light of the validator's specific concerns."""

        user_prompt += "\n\nProvide your verdict. If you need more function context and have not reached the limit, set request_function."

        # Inject actual contexts_used count
        system_prompt = system_prompt.replace("{contexts_used}", str(contexts_used))

        return system_prompt, user_prompt

    @staticmethod
    def get_validator_prompts(
        code: str, language: str,
        synthesizer_verdict: str,
        all_analyses: Dict[str, str],
        extra_function_contexts: List[Dict],
        iteration: int = 0
    ) -> Tuple[str, str]:
        system_prompt = """You are Agent 6: Validator in a multi-agent security vulnerability detection system.

The Synthesizer has flagged this code as VULNERABLE. Your job is to INDEPENDENTLY validate this claim.

Your responsibilities:
1. Re-analyze the evidence from Agents 1-4 independently
2. Check if the Synthesizer's vulnerability claim is well-supported by evidence
3. Verify that safe patterns were not overlooked or misinterpreted
4. Examine any additional fetched function contexts for relevant safety guarantees
5. Provide your own independent verdict

VALIDATION CHECKLIST:
✓ Is the vulnerability path actually exploitable?
✓ Are safe patterns (guard clauses, macros, ownership transfer) properly recognized?
✓ Are there any logical gaps or inconsistencies in the Synthesizer's reasoning?
✓ Is the confidence level appropriate for the certainty of evidence?

CRITICAL PRINCIPLES:
- You are NOT adversarial — you seek TRUTH
- AGREE with the Synthesizer when their analysis is correct
- DISAGREE only when you find genuine errors or missed mitigations
- Be SPECIFIC about what you agree/disagree with
- Provide CONCRETE evidence for any disagreements

Output format (JSON):
{
    "independent_analysis": "your own analysis of the evidence",
    "agreement_status": "AGREE/DISAGREE",
    "validator_verdict": "SAFE/VULNERABLE",
    "validator_label": 0,  // CRITICAL: 0 = SAFE, 1 = VULNERABLE
    "confidence": "HIGH/MEDIUM/LOW",
    "reasoning": "detailed explanation",
    "points_of_agreement": ["specific points of agreement with Synthesizer"],
    "points_of_disagreement": ["specific points of disagreement, if any"],
    "critical_evidence": ["key evidence that supports your verdict"],
    "feedback_for_refinement": "specific concerns if disagreement requires further iteration"
}

LABEL MAPPING (CRITICAL):
- SAFE  → validator_label = 0
- VULNERABLE → validator_label = 1"""

        extra_ctx_section = ""
        if extra_function_contexts:
            extra_ctx_section = "\n\n=== ADDITIONAL FUNCTION DEFINITIONS ==="
            for fc in extra_function_contexts:
                extra_ctx_section += f"\n\n--- Function: {fc['function_name']} ({fc['file_path']}) ---\n"
                extra_ctx_section += f"Source:\n```c\n{fc['source_code']}\n```\n"
                if fc.get('pattern_analysis'):
                    extra_ctx_section += f"\nPattern Analysis:\n{fc['pattern_analysis']}\n"

        user_prompt = f"""Validate the Synthesizer's VULNERABLE claim for this {language} code (Iteration {iteration + 1}):

=== TARGET FUNCTION ===
```{language}
{code}
```

Evidence from Specialist Agents:

Agent 1 (Context):
{all_analyses['context']}

Agent 2 (Memory Safety):
{all_analyses['memory']}

Agent 3 (Input Validation):
{all_analyses['validation']}

Agent 4 (Pattern Expert):
{all_analyses['patterns']}
{extra_ctx_section}

=== SYNTHESIZER'S VULNERABILITY CLAIM ===
{synthesizer_verdict}

Independently validate this claim. Do you AGREE (truly VULNERABLE) or DISAGREE (actually SAFE)?"""

        return system_prompt, user_prompt

    @staticmethod
    def get_final_judge_prompts(
        code: str, language: str,
        synthesizer_verdict: str,
        validator_verdict: str,
        iteration_count: int
    ) -> Tuple[str, str]:
        system_prompt = """You are Agent 7: Final Judge in a multi-agent security vulnerability detection system.

You are the ULTIMATE decision maker. Your verdict is FINAL and BINDING.

Context: The Synthesizer flagged this code as VULNERABLE. The Validator has independently reviewed this claim.

Your decision process:

CASE 1: SYNTHESIZER and VALIDATOR BOTH say VULNERABLE
→ High confidence. Issue VULNERABLE verdict.

CASE 2: SYNTHESIZER says VULNERABLE, VALIDATOR says SAFE
→ Carefully review BOTH analyses.
→ Determine which analysis is better supported by evidence.
→ If you can make a HIGH or MEDIUM confidence decision → Issue final verdict.
→ If evidence is genuinely ambiguous and iteration_count < 2 → Request ITERATE.

CASE 3: SYNTHESIZER says VULNERABLE, VALIDATOR AGREES but with caveats
→ Weigh the caveats. Issue the most well-supported verdict.

ITERATION DECISION:
- Request iteration ONLY if evidence is genuinely contradictory AND iteration_count < 2
- Otherwise: Make your best judgment

Output format (JSON):
{
    "decision_type": "CONSENSUS/ADJUDICATION/ITERATION_NEEDED",
    "final_verdict": "SAFE/VULNERABLE/ITERATE",
    "final_label": 0,  // CRITICAL: 0=SAFE, 1=VULNERABLE, null=ITERATE
    "confidence": "HIGH/MEDIUM/LOW",
    "reasoning": "detailed explanation of final decision",
    "key_deciding_factors": ["factors that determined the verdict"],
    "synthesizer_assessment": "evaluation of Agent 5's reasoning",
    "validator_assessment": "evaluation of Agent 6's reasoning",
    "iteration_justification": "why iteration is needed (only if ITERATE)",
    "guidance_for_iteration": "specific points for Synthesizer to reconsider (only if ITERATE)"
}

LABEL MAPPING (CRITICAL):
- SAFE  → final_label = 0
- VULNERABLE → final_label = 1
- ITERATE / MANUAL_REVIEW → final_label = null"""

        user_prompt = f"""Make the final judgment for this {language} code:

```{language}
{code}
```

Current Iteration: {iteration_count + 1} / 3

Synthesizer's Verdict (Agent 5):
{synthesizer_verdict}

Validator's Verdict (Agent 6):
{validator_verdict}

Render your final, binding verdict."""

        return system_prompt, user_prompt


# ─────────────────────────────────────────────────────────────────────────────
# Main Detector
# ─────────────────────────────────────────────────────────────────────────────

class MultiAgentVulnerabilityDetector:

    def __init__(self, api_key: str, model: str = "gpt-4o-mini",
                 max_iterations: int = 3, maximum_context_limit: int = 3):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model
        self.max_iterations = max_iterations
        self.maximum_context_limit = maximum_context_limit
        self.prompts = PromptTemplates()

    # ── LLM call ──────────────────────────────────────────────────────────────

    def call_llm(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 2000) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content  # type: ignore
        except Exception as e:
            return f"Error calling LLM: {str(e)}"

    def create_agent_response(self, agent_name: str, system_prompt: str,
                              user_prompt: str, response: str,
                              iteration: int = 0) -> AgentResponse:
        return AgentResponse(
            agent_name=agent_name,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response=response,
            timestamp=datetime.now().isoformat(),
            iteration=iteration
        )

    def parse_json_response(self, response: str) -> Optional[Dict]:
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            print(f"Warning: Could not parse JSON: {e}")
        return None

    def validate_and_fix_labels(self, data: Dict, agent_name: str) -> Dict:
        if not data:
            return data

        verdict_key = label_key = None
        if 'preliminary_verdict' in data and 'preliminary_label' in data:
            verdict_key, label_key = 'preliminary_verdict', 'preliminary_label'
        elif 'validator_verdict' in data and 'validator_label' in data:
            verdict_key, label_key = 'validator_verdict', 'validator_label'
        elif 'final_verdict' in data and 'final_label' in data:
            verdict_key, label_key = 'final_verdict', 'final_label'

        if verdict_key and label_key:
            verdict = data[verdict_key]
            label = data[label_key]
            if verdict == "SAFE" and label != 0:
                print(f"⚠️  {agent_name}: Mismatch SAFE but label={label}. Correcting to 0.")
                data[label_key] = 0
            elif verdict == "VULNERABLE" and label != 1:
                print(f"⚠️  {agent_name}: Mismatch VULNERABLE but label={label}. Correcting to 1.")
                data[label_key] = 1
            elif verdict in ["ITERATE", "MANUAL_REVIEW"] and label is not None:
                print(f"⚠️  {agent_name}: label should be null for verdict={verdict}. Correcting.")
                data[label_key] = None

        return data

    # ── Parallel specialist analysis for a single code snippet ───────────────

    def run_parallel_specialist_analysis(
        self, code: str, language: str, func_name: str = "function"
    ) -> Dict[str, str]:
        """
        Run Agents 1-4 in parallel (Agent 1 first, then 2/3/4 in parallel).
        Returns dict with keys: context, memory, validation, patterns
        """
        print(f"    Running parallel specialist analysis for `{func_name}`...")

        # Agent 1 must run first (provides context for others)
        sys_p, usr_p = self.prompts.get_context_analyzer_prompts(code, language, func_name)
        context_response = self.call_llm(sys_p, usr_p)

        # Agents 2, 3, 4 run in parallel
        def run_memory():
            sp, up = self.prompts.get_memory_safety_prompts(code, language, context_response, func_name)
            return 'memory', sp, up, self.call_llm(sp, up)

        def run_validation():
            sp, up = self.prompts.get_input_validation_prompts(code, language, context_response, func_name)
            return 'validation', sp, up, self.call_llm(sp, up)

        def run_pattern(mem_r, val_r):
            sp, up = self.prompts.get_pattern_expert_prompts(
                code, language, context_response, mem_r, val_r, func_name)
            return 'patterns', sp, up, self.call_llm(sp, up)

        memory_response = validation_response = None
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(run_memory): 'memory',
                executor.submit(run_validation): 'validation',
            }
            for future in as_completed(futures):
                key, _sp, _up, resp = future.result()
                if key == 'memory':
                    memory_response = resp
                else:
                    validation_response = resp

        _key, _sp, _up, pattern_response = run_pattern(memory_response, validation_response)

        return {
            'context': context_response,
            'memory': memory_response,
            'validation': validation_response,
            'patterns': pattern_response,
        } # type: ignore

    # ── Fetch a called function's definition and run parallel analysis ────────

    def fetch_and_analyze_function(
        self, function_name: str, language: str
    ) -> Optional[FunctionContext]:
        """
        Fetch function definition via ctags + git grep, then run parallel analysis on it.
        Returns a FunctionContext or None if not found.
        """
        print(f"    Fetching definition of `{function_name}` from QEMU repo...")
        result = get_function_source(function_name)
        if not result:
            print(f"    ⚠️  Could not find `{function_name}` in QEMU repo.")
            return None

        fname, fpath, source = result
        print(f"    ✓ Found `{fname}` in {fpath}")

        analyses = self.run_parallel_specialist_analysis(source, language, function_name)

        fc = FunctionContext(
            function_name=fname,
            file_path=fpath,
            source_code=source,
        )
        # Store as AgentResponse objects using dummy prompts for logging
        fc.context_analysis = self.create_agent_response(
            f"Context Analyzer [{fname}]", "", "", analyses['context'])
        fc.memory_analysis = self.create_agent_response(
            f"Memory Safety [{fname}]", "", "", analyses['memory'])
        fc.validation_analysis = self.create_agent_response(
            f"Input Validation [{fname}]", "", "", analyses['validation'])
        fc.pattern_analysis = self.create_agent_response(
            f"Pattern Expert [{fname}]", "", "", analyses['patterns'])

        return fc

    def _fc_to_dict(self, fc: FunctionContext) -> Dict:
        """Convert FunctionContext to dict for prompt injection."""
        return {
            'function_name': fc.function_name,
            'file_path': fc.file_path,
            'source_code': fc.source_code,
            'context_analysis': fc.context_analysis.response if fc.context_analysis else "",
            'memory_analysis': fc.memory_analysis.response if fc.memory_analysis else "",
            'validation_analysis': fc.validation_analysis.response if fc.validation_analysis else "",
            'pattern_analysis': fc.pattern_analysis.response if fc.pattern_analysis else "",
        }

    # ── Main analysis pipeline ────────────────────────────────────────────────

    def analyze_code(self, code: str, language: str, index: int,
                     ground_truth_label: int, ground_truth_cwe: str) -> AnalysisResult:

        result = AnalysisResult(
            index=index,
            programming_language=language,
            code_snippet=code,
            ground_truth_label=ground_truth_label,
            ground_truth_cwe=ground_truth_cwe,
        )

        print(f"\n{'='*80}")
        print(f"Analyzing code snippet {index}")
        print(f"{'='*80}")

        # ── Phase 1 & 2: Parallel Specialist Analysis on target function ──────
        print("Phase 1+2: Parallel Specialist Analysis on target function...")
        target_analyses = self.run_parallel_specialist_analysis(code, language, f"snippet_{index}")

        # Store agent responses in result
        dummy = lambda name, r: self.create_agent_response(name, "", "", r)
        result.context_analyzer = dummy("Context Analyzer", target_analyses['context'])
        result.memory_safety = dummy("Memory Safety Analyst", target_analyses['memory'])
        result.input_validation = dummy("Input Validation Specialist", target_analyses['validation'])
        result.pattern_expert = dummy("Pattern Recognition Expert", target_analyses['patterns'])

        # ── Phase 3: Iterative Synthesis with optional context fetching ───────
        print("\nPhase 3+: Synthesis with context-fetch loop...")

        all_analyses = target_analyses
        extra_function_contexts: List[FunctionContext] = []
        contexts_used = 0
        already_fetched = set()

        iteration = 0
        previous_feedback = None
        final_decision_reached = False

        while iteration < self.max_iterations and not final_decision_reached:
            print(f"\n  Iteration {iteration + 1}/{self.max_iterations}")

            # Build list of extra context dicts for prompt
            extra_ctx_dicts = [self._fc_to_dict(fc) for fc in extra_function_contexts]

            # ── Synthesizer ──────────────────────────────────────────────────
            print(f"    Synthesizer (iteration {iteration + 1})...")
            sys_p, usr_p = self.prompts.get_synthesizer_prompts(
                code=code,
                language=language,
                all_analyses=all_analyses,
                extra_function_contexts=extra_ctx_dicts,
                maximum_context_limit=self.maximum_context_limit,
                contexts_used=contexts_used,
                iteration=iteration,
                previous_feedback=previous_feedback, # type: ignore
            )
            synth_response = self.call_llm(sys_p, usr_p, max_tokens=2500)
            synth_data = self.parse_json_response(synth_response)
            synth_data = self.validate_and_fix_labels(synth_data, "Synthesizer") # type: ignore

            result.synthesizer.append(
                self.create_agent_response("Vulnerability Synthesizer", sys_p, usr_p,
                                           synth_response, iteration)
            )

            # ── Check if synthesizer requested more context ──────────────────
            requested_func = None
            if synth_data and contexts_used < self.maximum_context_limit:
                requested_func = synth_data.get('request_function')
                if requested_func and isinstance(requested_func, str) \
                        and requested_func.strip() \
                        and requested_func not in already_fetched:
                    requested_func = requested_func.strip()
                    print(f"    Synthesizer requests function context: `{requested_func}`")
                    fc = self.fetch_and_analyze_function(requested_func, language)
                    if fc:
                        extra_function_contexts.append(fc)
                        result.fetched_function_contexts.append(fc)
                        already_fetched.add(requested_func)
                    contexts_used += 1
                    result.context_requests = contexts_used
                    # Re-run synthesizer with the new context (same iteration slot)
                    # (we continue the while loop which will retry at same iteration)
                    # To avoid infinite retry at same iteration, we treat each fetch
                    # as a sub-iteration and just proceed normally.
                else:
                    requested_func = None

            # ── Read synthesizer verdict ─────────────────────────────────────
            synth_verdict = "UNKNOWN"
            if synth_data:
                synth_verdict = synth_data.get('preliminary_verdict', 'UNKNOWN')

            print(f"    Synthesizer verdict: {synth_verdict}")

            # ── If SAFE → final verdict, skip validator ──────────────────────
            if synth_verdict == "SAFE":
                print("    ✓ Synthesizer says SAFE → Final verdict: SAFE (no validator needed)")
                result.final_verdict = "SAFE"
                result.final_label = 0
                result.confidence = synth_data.get('confidence', 'MEDIUM') if synth_data else 'MEDIUM'
                final_decision_reached = True
                result.total_iterations = iteration + 1
                break

            # ── If VULNERABLE → run Validator then Final Judge ───────────────
            if synth_verdict == "VULNERABLE":
                # Validator
                print(f"    Validator (iteration {iteration + 1})...")
                extra_ctx_dicts = [self._fc_to_dict(fc) for fc in extra_function_contexts]
                sys_p, usr_p = self.prompts.get_validator_prompts(
                    code=code,
                    language=language,
                    synthesizer_verdict=synth_response,
                    all_analyses=all_analyses,
                    extra_function_contexts=extra_ctx_dicts,
                    iteration=iteration,
                )
                val_response = self.call_llm(sys_p, usr_p, max_tokens=2000)
                val_data = self.parse_json_response(val_response)
                val_data = self.validate_and_fix_labels(val_data, "Validator")

                result.validator.append(
                    self.create_agent_response("Validator", sys_p, usr_p,
                                               val_response, iteration)
                )

                # Final Judge
                print(f"    Final Judge (iteration {iteration + 1})...")
                sys_p, usr_p = self.prompts.get_final_judge_prompts(
                    code=code,
                    language=language,
                    synthesizer_verdict=synth_response,
                    validator_verdict=val_response,
                    iteration_count=iteration,
                )
                judge_response = self.call_llm(sys_p, usr_p, max_tokens=2000)
                judge_data = self.parse_json_response(judge_response)
                judge_data = self.validate_and_fix_labels(judge_data, "Final Judge") # type: ignore

                if judge_data:
                    final_verdict = judge_data.get('final_verdict', 'UNKNOWN')
                    if final_verdict == 'ITERATE' and iteration < self.max_iterations - 1:
                        print(f"    → Judge requests iteration. Refining...")
                        result.refinement_occurred = True
                        previous_feedback = judge_data.get('guidance_for_iteration', val_response)
                        iteration += 1
                        continue
                    else:
                        final_decision_reached = True
                        result.final_judge = self.create_agent_response(
                            "Final Judge", sys_p, usr_p, judge_response, iteration
                        )
                        result.final_verdict = final_verdict if final_verdict != 'ITERATE' else 'MANUAL_REVIEW'
                        result.final_label = judge_data.get('final_label')
                        result.confidence = judge_data.get('confidence', 'UNKNOWN')
                else:
                    # Fallback
                    final_decision_reached = True
                    result.final_judge = self.create_agent_response(
                        "Final Judge", sys_p, usr_p, judge_response, iteration
                    )
                    if 'VULNERABLE' in judge_response.upper():
                        result.final_verdict = 'VULNERABLE'
                        result.final_label = 1
                    elif 'SAFE' in judge_response.upper():
                        result.final_verdict = 'SAFE'
                        result.final_label = 0
                    else:
                        result.final_verdict = 'MANUAL_REVIEW'
                        result.final_label = None

            else:
                # Unknown verdict — treat as manual review
                print(f"    ⚠️  Unknown synthesizer verdict: {synth_verdict}. Marking MANUAL_REVIEW.")
                result.final_verdict = 'MANUAL_REVIEW'
                result.final_label = None
                result.confidence = 'LOW'
                final_decision_reached = True

            iteration += 1

        result.total_iterations = iteration + 1 if not final_decision_reached else result.total_iterations or (iteration + 1)

        # Accuracy
        if result.final_label is not None:
            result.is_correct = (result.final_label == ground_truth_label)
            if not result.is_correct:
                if result.final_label == 1 and ground_truth_label == 0:
                    result.error_type = 'FP'
                elif result.final_label == 0 and ground_truth_label == 1:
                    result.error_type = 'FN'

        print(f"\n{'='*80}")
        print(f"Final Verdict: {result.final_verdict} (Label: {result.final_label})")
        print(f"Ground Truth: {ground_truth_label}")
        print(f"Correct: {result.is_correct}, Error Type: {result.error_type}")
        print(f"Total Iterations: {result.total_iterations}")
        print(f"Context Requests: {result.context_requests}/{self.maximum_context_limit}")
        print(f"{'='*80}")

        return result

    # ── Report generation ─────────────────────────────────────────────────────

    def generate_markdown_report(self, result: AnalysisResult, output_dir: Path):
        output_file = output_dir / f"analysis_{result.index:04d}.md"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Vulnerability Analysis Report - Sample {result.index}\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Language:** {result.programming_language}\n\n")
            f.write(f"**Total Iterations:** {result.total_iterations}\n\n")
            f.write(f"**Context Requests:** {result.context_requests}\n\n")
            f.write(f"**Refinement Occurred:** {'Yes' if result.refinement_occurred else 'No'}\n\n")

            f.write("## Code Snippet\n\n")
            f.write(f"```{result.programming_language.lower()}\n{result.code_snippet}\n```\n\n")

            f.write("## Ground Truth\n\n")
            f.write(f"- **Label:** {result.ground_truth_label} "
                    f"({'VULNERABLE' if result.ground_truth_label == 1 else 'SAFE'})\n")
            f.write(f"- **CWE ID:** {result.ground_truth_cwe}\n\n")

            f.write("## Multi-Agent Analysis\n\n")

            for agent_name, agent_resp in [
                ("Agent 1: Context Analyzer", result.context_analyzer),
                ("Agent 2: Memory Safety Analyst", result.memory_safety),
                ("Agent 3: Input Validation Specialist", result.input_validation),
                ("Agent 4: Pattern Recognition Expert", result.pattern_expert),
            ]:
                if agent_resp:
                    self._write_agent_section(f, agent_name, agent_resp)

            # Fetched function contexts
            if result.fetched_function_contexts:
                f.write("## Fetched Function Contexts\n\n")
                for fc in result.fetched_function_contexts:
                    f.write(f"### Function: `{fc.function_name}` ({fc.file_path})\n\n")
                    f.write(f"```c\n{fc.source_code}\n```\n\n")
                    for analysis_name, analysis_resp in [
                        ("Context Analysis", fc.context_analysis),
                        ("Memory Safety Analysis", fc.memory_analysis),
                        ("Validation Analysis", fc.validation_analysis),
                        ("Pattern Analysis", fc.pattern_analysis),
                    ]:
                        if analysis_resp:
                            self._write_agent_section(f, analysis_name, analysis_resp)

            for i, sr in enumerate(result.synthesizer):
                self._write_agent_section(f, f"Agent 5: Synthesizer (Iteration {i+1})", sr)
            for i, vr in enumerate(result.validator):
                self._write_agent_section(f, f"Agent 6: Validator (Iteration {i+1})", vr)
            if result.final_judge:
                self._write_agent_section(f, "Agent 7: Final Judge", result.final_judge)

            f.write("## Final Verdict\n\n")
            f.write(f"- **Verdict:** {result.final_verdict}\n")
            f.write(f"- **Label:** {result.final_label} ")
            if result.final_label == 0:
                f.write("(SAFE)\n")
            elif result.final_label == 1:
                f.write("(VULNERABLE)\n")
            else:
                f.write("(MANUAL REVIEW NEEDED)\n")
            f.write(f"- **Confidence:** {result.confidence}\n\n")

            f.write("## Accuracy Assessment\n\n")
            f.write(f"- **Prediction Correct:** {result.is_correct}\n")
            if result.error_type:
                f.write(f"- **Error Type:** {result.error_type}\n")
                if result.error_type == 'FP':
                    f.write("  - False Positive: Flagged as vulnerable but actually safe\n")
                elif result.error_type == 'FN':
                    f.write("  - False Negative: Flagged as safe but actually vulnerable\n")
            f.write("\n")

            f.write("## Summary\n\n")
            f.write("| Metric | Value |\n|--------|-------|\n")
            f.write(f"| Ground Truth | {result.ground_truth_label} "
                    f"({'VULNERABLE' if result.ground_truth_label == 1 else 'SAFE'}) |\n")
            f.write(f"| Prediction | {result.final_label} ({result.final_verdict}) |\n")
            f.write(f"| Confidence | {result.confidence} |\n")
            f.write(f"| Correct | {'✅ Yes' if result.is_correct else '❌ No'} |\n")
            f.write(f"| Error Type | {result.error_type if result.error_type else 'N/A'} |\n")
            f.write(f"| Iterations | {result.total_iterations} |\n")
            f.write(f"| Context Requests | {result.context_requests} |\n")
            f.write(f"| Refinement | {'Yes' if result.refinement_occurred else 'No'} |\n")

        print(f"Report saved to: {output_file}")

    def _write_agent_section(self, f, agent_name: str, agent_response: AgentResponse):
        f.write(f"### {agent_name}\n\n")
        if agent_response.system_prompt:
            f.write("#### System Prompt\n\n```\n")
            f.write(agent_response.system_prompt)
            f.write("\n```\n\n")
        if agent_response.user_prompt:
            f.write("#### User Prompt\n\n```\n")
            f.write(agent_response.user_prompt)
            f.write("\n```\n\n")
        f.write("#### Response\n\n```\n")
        f.write(agent_response.response)
        f.write("\n```\n\n")
        f.write(f"*Timestamp: {agent_response.timestamp}*\n\n---\n\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    api_key = os.getenv('OPENAI_KEY')
    if not api_key:
        print("Error: OPENAI_KEY not found in environment variables")
        print("Please ensure your .bashrc contains: export OPENAI_KEY='your-key-here'")
        return

    detector = MultiAgentVulnerabilityDetector(
        api_key=api_key,
        model="gpt-4o-mini",
        max_iterations=3,
        maximum_context_limit=3,   # synthesizer can ask for at most 3 function definitions
    )

    dataset_path = "./test_1.jsonl"
    print(f"Loading dataset from: {dataset_path}")

    with open(dataset_path, 'r') as f:
        dataset = [json.loads(line) for line in f]

    print(f"Loaded {len(dataset)} samples")

    output_dir = Path("./codexglue_analysis_v4")
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for i, sample in enumerate(dataset):
        code = sample['func']
        language = 'c'
        ground_truth_label = sample['target']
        ground_truth_cwe = 'unknown'

        result = detector.analyze_code(
            code=code, language=language, index=i,
            ground_truth_label=ground_truth_label,
            ground_truth_cwe=ground_truth_cwe
        )
        detector.generate_markdown_report(result, output_dir)
        results.append(result)

    # Summary report
    print("\n" + "="*80)
    print("ANALYSIS COMPLETE - Generating Summary Report")
    print("="*80)

    total = len(results)
    correct = sum(1 for r in results if r.is_correct)
    fp_count = sum(1 for r in results if r.error_type == 'FP')
    fn_count = sum(1 for r in results if r.error_type == 'FN')
    manual_review = sum(1 for r in results if r.final_label is None)
    tp = sum(1 for r in results if r.final_label == 1 and r.ground_truth_label == 1)
    tn = sum(1 for r in results if r.final_label == 0 and r.ground_truth_label == 0)
    precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0
    recall = tp / (tp + fn_count) if (tp + fn_count) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    total_iters = sum(r.total_iterations for r in results)
    avg_iters = total_iters / total if total > 0 else 0
    total_ctx_reqs = sum(r.context_requests for r in results)
    refinement_count = sum(1 for r in results if r.refinement_occurred)

    summary_file = output_dir / "SUMMARY.md"
    with open(summary_file, 'w') as f:
        f.write("# Multi-Agent Vulnerability Detection - Summary Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Model:** gpt-4o-mini\n")
        f.write(f"**Total Samples:** {total}\n")
        f.write(f"**Maximum Context Limit:** {detector.maximum_context_limit}\n\n")

        f.write("## Overall Metrics\n\n")
        f.write(f"- **Accuracy:** {correct}/{total} ({100*correct/total:.2f}%)\n")
        f.write(f"- **Precision:** {precision:.4f} ({100*precision:.2f}%)\n")
        f.write(f"- **Recall:** {recall:.4f} ({100*recall:.2f}%)\n")
        f.write(f"- **F1 Score:** {f1_score:.4f} ({100*f1_score:.2f}%)\n\n")

        f.write("## Error Analysis\n\n")
        f.write(f"- **True Positives:** {tp}\n")
        f.write(f"- **True Negatives:** {tn}\n")
        f.write(f"- **False Positives:** {fp_count} ({100*fp_count/total:.2f}%)\n")
        f.write(f"- **False Negatives:** {fn_count} ({100*fn_count/total:.2f}%)\n")
        f.write(f"- **Manual Review Needed:** {manual_review} ({100*manual_review/total:.2f}%)\n\n")

        f.write("## Iteration & Context Statistics\n\n")
        f.write(f"- **Total Iterations:** {total_iters}\n")
        f.write(f"- **Average Iterations per Sample:** {avg_iters:.2f}\n")
        f.write(f"- **Total Context Requests:** {total_ctx_reqs}\n")
        f.write(f"- **Average Context Requests per Sample:** {total_ctx_reqs/total:.2f}\n")
        f.write(f"- **Samples Requiring Refinement:** {refinement_count} ({100*refinement_count/total:.2f}%)\n\n")

        f.write("## Detailed Results\n\n")
        f.write("| Index | Ground Truth | Prediction | Confidence | Iterations | Ctx Reqs | Correct | Error |\n")
        f.write("|-------|--------------|------------|------------|------------|----------|---------|-------|\n")
        for r in results:
            gt = "VUL" if r.ground_truth_label == 1 else "SAFE"
            pred = "VUL" if r.final_label == 1 else ("SAFE" if r.final_label == 0 else "MR")
            icon = "✅" if r.is_correct else "❌"
            err = r.error_type if r.error_type else "-"
            f.write(f"| {r.index:04d} | {gt} | {pred} | {r.confidence} | "
                    f"{r.total_iterations} | {r.context_requests} | {icon} | {err} |\n")

    print(f"\nSummary report saved to: {summary_file}")
    print(f"Individual reports saved to: {output_dir}")
    print(f"\n{'='*80}\nFINAL STATISTICS\n{'='*80}")
    print(f"Total accuracy: {correct}/{total} ({100*correct/total:.2f}%)")
    print(f"Precision: {precision:.4f}  Recall: {recall:.4f}  F1: {f1_score:.4f}")
    print(f"False Positives: {fp_count}  False Negatives: {fn_count}")
    print(f"Average Iterations: {avg_iters:.2f}")
    print(f"Total Context Requests: {total_ctx_reqs}  Avg per sample: {total_ctx_reqs/total:.2f}")
    print(f"Samples Refined: {refinement_count}/{total}")


if __name__ == "__main__":
    main()