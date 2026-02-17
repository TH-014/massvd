#!/usr/bin/env python3
"""
Multi-Agent System for Security Vulnerability Detection
Updated design: Agent 6 as Validator with iterative refinement capability
"""

import json
import pandas as pd
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import openai
from datetime import datetime


@dataclass
class AgentResponse:
    """Store response from an individual agent"""
    agent_name: str
    system_prompt: str
    user_prompt: str
    response: str
    timestamp: str
    iteration: int = 0  # Track iteration number for iterative refinement


@dataclass
class AnalysisResult:
    """Store complete analysis result for a code snippet"""
    index: int
    programming_language: str
    code_snippet: str
    ground_truth_label: int
    ground_truth_cwe: str
    
    # Agent responses (can have multiple iterations)
    context_analyzer: Optional[AgentResponse] = None
    memory_safety: Optional[AgentResponse] = None
    input_validation: Optional[AgentResponse] = None
    pattern_expert: Optional[AgentResponse] = None
    synthesizer: Optional[List[AgentResponse]] = None  # List for iterations
    validator: Optional[List[AgentResponse]] = None  # List for iterations
    final_judge: Optional[AgentResponse] = None
    
    # Iteration tracking
    total_iterations: int = 0
    refinement_occurred: bool = False
    
    # Final verdict
    final_verdict: Optional[str] = None
    final_label: Optional[int] = None  # 0 = safe, 1 = vulnerable
    confidence: Optional[str] = None
    
    # Accuracy metrics
    is_correct: Optional[bool] = None
    error_type: Optional[str] = None  # None, 'FP', 'FN'


class PromptTemplates:
    """System and user prompts for each agent"""
    
    @staticmethod
    def get_context_analyzer_prompts(code: str, language: str) -> tuple[str, str]:
        system_prompt = """You are Agent 1: Context Analyzer in a multi-agent security vulnerability detection system.

Your SOLE purpose is to build context BEFORE security analysis begins. You do NOT flag vulnerabilities.

Your responsibilities:
1. Identify the framework/library being used (e.g., TensorFlow Lite, Linux Kernel, glibc, custom)
2. Detect architectural patterns (ownership transfer, bounded buffers, guard clauses)
3. Find validation macros (e.g., TF_LITE_ENSURE, CHECK, ASSERT, bounds checks)
4. Document safety contracts (pre-validated inputs, caller responsibilities)
5. Identify guard clauses and defensive programming patterns

CRITICAL: You must NOT make vulnerability judgments. Your job is only to provide context that other agents will use.

Output format (JSON):
{
    "framework": "name of framework or 'custom'",
    "patterns_detected": ["list of patterns found"],
    "validation_macros": ["list of macros/guards found"],
    "safety_contracts": ["documented safety assumptions"],
    "guard_clauses": ["identified guard conditions"],
    "context_summary": "brief summary of the code's context"
}"""

        user_prompt = f"""Analyze the following {language} code snippet and provide context:

```{language}
{code}
```

Remember: Only provide context. Do NOT flag vulnerabilities."""

        return system_prompt, user_prompt

    @staticmethod
    def get_memory_safety_prompts(code: str, language: str, context: str) -> tuple[str, str]:
        system_prompt = """You are Agent 2: Memory Safety Analyst in a multi-agent security vulnerability detection system.

Your purpose is to analyze memory operations with CONTEXT AWARENESS.

ANTI-PATTERNS TO AVOID:
❌ DO NOT flag malloc/calloc/new by default
❌ DO NOT assume all pointers are unsafe
❌ DO NOT ignore ownership patterns
❌ DO NOT ignore wrapper functions that handle safety

What to check:
1. Buffer operations - are sizes validated?
2. Pointer arithmetic - are bounds checked?
3. Memory allocation - is NULL checked? Is size controlled?
4. Deallocation - any double-free or use-after-free?
5. Are there wrapper functions that handle safety?

Consider the context provided by Agent 1. If validation macros or guard clauses exist, account for them.

Output format (JSON):
{
    "memory_issues_found": ["list of potential issues"],
    "safe_patterns_found": ["list of safe patterns detected"],
    "requires_validation": ["operations that need validation checks"],
    "context_considerations": "how context affects analysis",
    "preliminary_verdict": "SAFE/SUSPICIOUS/VULNERABLE",
    "confidence": "HIGH/MEDIUM/LOW"
}"""

        user_prompt = f"""Analyze memory safety for this {language} code:

```{language}
{code}
```

Context from Agent 1:
{context}

Analyze memory operations considering the provided context."""

        return system_prompt, user_prompt

    @staticmethod
    def get_input_validation_prompts(code: str, language: str, context: str) -> tuple[str, str]:
        system_prompt = """You are Agent 3: Input Validation Specialist in a multi-agent security vulnerability detection system.

Your purpose is to detect missing validation while considering framework mechanisms.

What to check:
1. Are user inputs validated before use?
2. Are array indices bounds-checked?
3. Are string lengths verified?
4. Do framework macros provide validation (e.g., TF_LITE_ENSURE)?
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

        user_prompt = f"""Analyze input validation for this {language} code:

```{language}
{code}
```

Context from Agent 1:
{context}

Check for input validation considering framework mechanisms."""

        return system_prompt, user_prompt

    @staticmethod
    def get_pattern_expert_prompts(code: str, language: str, context: str, 
                                   memory_analysis: str, validation_analysis: str) -> tuple[str, str]:
        system_prompt = """You are Agent 4: Pattern Recognition Expert in a multi-agent security vulnerability detection system.

Your purpose is to identify safe and unsafe patterns, and you have OVERRIDE AUTHORITY over previous agents.

SAFE PATTERNS (Don't flag):
✅ Transfer of ownership (malloc then return, caller frees)
✅ Bounded ring buffers (wraparound with modulo)
✅ Guard-then-operate (check before use)
✅ RAII/Smart pointers (automatic cleanup)
✅ Const correctness (read-only access)

UNSAFE PATTERNS (Flag):
❌ Unbounded copy (strcpy, sprintf without bounds)
❌ TOCTOU races (time-of-check to time-of-use)
❌ Use-after-free
❌ Integer overflow in size calculations
❌ Format string vulnerabilities

KEY FEATURE: You can override false positives from Agents 2 and 3 if you detect safe patterns.

Output format (JSON):
{
    "safe_patterns": ["patterns that indicate safety"],
    "unsafe_patterns": ["patterns that indicate vulnerability"],
    "overrides": ["any false positives you're overriding"],
    "additional_concerns": ["new issues not caught by previous agents"],
    "preliminary_verdict": "SAFE/SUSPICIOUS/VULNERABLE",
    "confidence": "HIGH/MEDIUM/LOW"
}"""

        user_prompt = f"""Analyze patterns in this {language} code:

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
    def get_synthesizer_prompts(code: str, language: str, all_analyses: Dict[str, str],
                               iteration: int = 0, previous_feedback: str = None) -> tuple[str, str]: # type: ignore
        system_prompt = """You are Agent 5: Vulnerability Synthesizer in a multi-agent security vulnerability detection system.

Your purpose is to aggregate findings from all previous agents and make a PRELIMINARY decision.

Decision Criteria:
- HIGH confidence: All agents agree + no conflicting safe patterns + clear evidence
- MEDIUM confidence: Some disagreement between agents OR mixed signals
- LOW confidence: Contradictions + safe patterns present OR unclear evidence

Process:
1. Review all agent findings
2. Identify agreements and conflicts
3. Weight evidence (safe patterns vs. concerns)
4. Assign preliminary verdict with confidence
5. Document reasoning clearly with specific evidence

IMPORTANT PRINCIPLES:
- Be CONSERVATIVE: When in doubt, lean towards SAFE if there are defensive patterns
- TRUST validation macros and framework-specific safety mechanisms
- DON'T flag pointer usage as inherently unsafe
- REQUIRE concrete evidence of exploitable vulnerability before flagging VULNERABLE

Your verdict will be validated by Agent 6 (Validator) before reaching the Final Judge.

Output format (JSON):
{
    "synthesis": "summary of all findings",
    "agreements": ["points where agents agree"],
    "conflicts": ["points where agents disagree"],
    "preliminary_verdict": "SAFE/VULNERABLE",
    "preliminary_label": 0 or 1,  // CRITICAL: 0 = SAFE, 1 = VULNERABLE
    "confidence": "HIGH/MEDIUM/LOW",
    "reasoning": "detailed explanation with specific code references",
    "key_evidence": ["most important evidence points with line references"],
    "uncertainty_areas": ["areas where you're uncertain"]
}

LABEL MAPPING (CRITICAL):
- If verdict is SAFE → label MUST be 0
- If verdict is VULNERABLE → label MUST be 1

EXAMPLES:
Example 1: {"preliminary_verdict": "SAFE", "preliminary_label": 0}  ✓ Correct
Example 2: {"preliminary_verdict": "VULNERABLE", "preliminary_label": 1}  ✓ Correct
Example 3: {"preliminary_verdict": "SAFE", "preliminary_label": 1}  ✗ WRONG - Should be 0!"""

        user_prompt = f"""Synthesize findings for this {language} code (Iteration {iteration + 1}):

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
{all_analyses['patterns']}"""

        if previous_feedback:
            user_prompt += f"""

VALIDATOR FEEDBACK FROM PREVIOUS ITERATION:
{previous_feedback}

Please reconsider your analysis in light of the validator's specific concerns and provide an updated verdict."""

        user_prompt += "\n\nProvide your preliminary verdict by synthesizing all findings."

        return system_prompt, user_prompt

    @staticmethod
    def get_validator_prompts(code: str, language: str, 
                             synthesizer_verdict: str, all_analyses: Dict[str, str],
                             iteration: int = 0) -> tuple[str, str]:
        system_prompt = """You are Agent 6: Validator in a multi-agent security vulnerability detection system.

Your purpose is to VALIDATE the Synthesizer's analysis through independent cross-checking.

Your responsibilities:
1. INDEPENDENTLY re-analyze the evidence from Agents 1-4
2. Check if the Synthesizer's reasoning is sound and well-supported
3. Verify that key evidence was not overlooked or misinterpreted
4. Ensure the confidence level matches the strength of evidence
5. Provide your own independent verdict

VALIDATION CHECKLIST:
✓ Does the verdict match the evidence from specialist agents?
✓ Are safe patterns (guard clauses, macros, ownership transfer) properly recognized?
✓ Are genuine vulnerabilities (unbounded operations, missing checks) properly identified?
✓ Is the confidence level appropriate for the certainty of evidence?
✓ Are there any logical gaps or inconsistencies in the reasoning?

CRITICAL PRINCIPLES:
- You are NOT adversarial - you seek TRUTH, not contradiction
- AGREE with the Synthesizer when their analysis is correct
- DISAGREE only when you find genuine errors in reasoning or missed evidence
- Be SPECIFIC about what you agree/disagree with
- Provide CONCRETE evidence for any disagreements

Agreement Outcomes:
- If you AGREE (both SAFE or both VULNERABLE): State agreement and support the verdict
- If you DISAGREE: Provide specific reasons and your alternative verdict with evidence

Output format (JSON):
{
    "independent_analysis": "your own analysis of the evidence",
    "agreement_status": "AGREE/DISAGREE",
    "validator_verdict": "SAFE/VULNERABLE",
    "validator_label": 0 or 1,  // CRITICAL: 0 = SAFE, 1 = VULNERABLE
    "confidence": "HIGH/MEDIUM/LOW",
    "reasoning": "detailed explanation of your assessment",
    "points_of_agreement": ["specific points where you agree with Synthesizer"],
    "points_of_disagreement": ["specific points where you disagree, if any"],
    "critical_evidence": ["key evidence that supports your verdict"],
    "feedback_for_refinement": "specific concerns if disagreement requires iteration"
}

LABEL MAPPING (CRITICAL):
- If validator_verdict is SAFE → validator_label MUST be 0
- If validator_verdict is VULNERABLE → validator_label MUST be 1

EXAMPLES:
Example 1: {"validator_verdict": "SAFE", "validator_label": 0}  ✓ Correct
Example 2: {"validator_verdict": "VULNERABLE", "validator_label": 1}  ✓ Correct
Example 3: {"validator_verdict": "SAFE", "validator_label": 1}  ✗ WRONG - Should be 0!"""

        user_prompt = f"""Validate the Synthesizer's analysis for this {language} code (Iteration {iteration + 1}):

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

Synthesizer's Verdict (Agent 5):
{synthesizer_verdict}

Independently validate this analysis. Do you AGREE or DISAGREE? Provide your own verdict."""

        return system_prompt, user_prompt

    @staticmethod
    def get_final_judge_prompts(code: str, language: str, 
                               synthesizer_verdict: str, 
                               validator_verdict: str,
                               iteration_count: int) -> tuple[str, str]:
        system_prompt = """You are Agent 7: Final Judge in a multi-agent security vulnerability detection system.

You are the ULTIMATE decision maker. Your verdict is FINAL and BINDING.

Your decision process:

CASE 1: SYNTHESIZER and VALIDATOR AGREE
→ Accept their consensus verdict
→ Set confidence based on their agreement strength
→ Provide final verdict immediately

CASE 2: SYNTHESIZER and VALIDATOR DISAGREE
→ Carefully review BOTH analyses
→ Examine the evidence from specialist agents (Agents 1-4)
→ Determine which analysis is better supported by evidence
→ If you can make a HIGH or MEDIUM confidence decision: Issue final verdict
→ If evidence is genuinely ambiguous: Request iteration (max 2 iterations)

ITERATION DECISION:
- Request iteration ONLY if:
  * Evidence is genuinely contradictory
  * Neither agent's reasoning is clearly superior
  * Specific clarification could resolve the disagreement
  * Iteration count < 2
- Otherwise: Make your best judgment and issue final verdict

Output format (JSON):
{
    "decision_type": "CONSENSUS/ADJUDICATION/ITERATION_NEEDED",
    "final_verdict": "SAFE/VULNERABLE/ITERATE",
    "final_label": 0 or 1 or null,  // CRITICAL: 0 = SAFE, 1 = VULNERABLE, null = ITERATE/MANUAL_REVIEW
    "confidence": "HIGH/MEDIUM/LOW",
    "reasoning": "detailed explanation of final decision",
    "key_deciding_factors": ["factors that determined the verdict"],
    "synthesizer_assessment": "evaluation of Agent 5's reasoning",
    "validator_assessment": "evaluation of Agent 6's reasoning",
    "iteration_justification": "why iteration is needed (only if ITERATE)",
    "guidance_for_iteration": "specific points for Synthesizer to reconsider (only if ITERATE)"
}

LABEL MAPPING (CRITICAL):
- If final_verdict is SAFE → final_label MUST be 0
- If final_verdict is VULNERABLE → final_label MUST be 1
- If final_verdict is ITERATE or MANUAL_REVIEW → final_label MUST be null

EXAMPLES:
Example 1: {"final_verdict": "SAFE", "final_label": 0}  ✓ Correct
Example 2: {"final_verdict": "VULNERABLE", "final_label": 1}  ✓ Correct
Example 3: {"final_verdict": "SAFE", "final_label": 1}  ✗ WRONG - Should be 0!
Example 4: {"final_verdict": "ITERATE", "final_label": null}  ✓ Correct"""

        user_prompt = f"""Make the final judgment for this {language} code:

```{language}
{code}
```

Current Iteration: {iteration_count + 1}
Maximum Iterations: 3

Synthesizer's Verdict (Agent 5):
{synthesizer_verdict}

Validator's Verdict (Agent 6):
{validator_verdict}

Render your final, binding verdict. If they agree, affirm it. If they disagree, adjudicate or request iteration if needed."""

        return system_prompt, user_prompt


class MultiAgentVulnerabilityDetector:
    """Main class orchestrating the multi-agent analysis"""
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini", max_iterations: int = 3):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model
        self.max_iterations = max_iterations
        self.prompts = PromptTemplates()
    
    def call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Make a call to the LLM API"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,  # Low temperature for consistency
                max_tokens=2000
            )
            return response.choices[0].message.content # type: ignore
        except Exception as e:
            return f"Error calling LLM: {str(e)}"
    
    def create_agent_response(self, agent_name: str, system_prompt: str, 
                            user_prompt: str, response: str, iteration: int = 0) -> AgentResponse:
        """Create an AgentResponse object"""
        return AgentResponse(
            agent_name=agent_name,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response=response,
            timestamp=datetime.now().isoformat(),
            iteration=iteration
        )
    
    def parse_json_response(self, response: str) -> Optional[Dict]:
        """Try to parse JSON from LLM response"""
        import re
        try:
            # Try to find JSON in the response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            print(f"Warning: Could not parse JSON: {e}")
        return None
    
    def validate_and_fix_labels(self, data: Dict, agent_name: str) -> Dict:
        """Validate that labels match verdicts and fix mismatches"""
        if not data:
            return data
        
        # Check for verdict-label mismatches and fix them
        verdict_key = None
        label_key = None
        
        if 'preliminary_verdict' in data and 'preliminary_label' in data:
            verdict_key = 'preliminary_verdict'
            label_key = 'preliminary_label'
        elif 'validator_verdict' in data and 'validator_label' in data:
            verdict_key = 'validator_verdict'
            label_key = 'validator_label'
        elif 'final_verdict' in data and 'final_label' in data:
            verdict_key = 'final_verdict'
            label_key = 'final_label'
        
        if verdict_key and label_key:
            verdict = data[verdict_key]
            label = data[label_key]
            
            # Correct mapping: SAFE=0, VULNERABLE=1
            if verdict == "SAFE" and label != 0:
                print(f"⚠️  {agent_name}: Label mismatch detected! Verdict=SAFE but label={label}. Correcting to 0.")
                data[label_key] = 0
            elif verdict == "VULNERABLE" and label != 1:
                print(f"⚠️  {agent_name}: Label mismatch detected! Verdict=VULNERABLE but label={label}. Correcting to 1.")
                data[label_key] = 1
            elif verdict in ["ITERATE", "MANUAL_REVIEW"] and label is not None:
                print(f"⚠️  {agent_name}: Label should be null for verdict={verdict}. Correcting.")
                data[label_key] = None
        
        return data
    
    def analyze_code(self, code: str, language: str, index: int, 
                    ground_truth_label: int, ground_truth_cwe: str) -> AnalysisResult:
        """Run complete multi-agent analysis on a code snippet"""
        
        result = AnalysisResult(
            index=index,
            programming_language=language,
            code_snippet=code,
            ground_truth_label=ground_truth_label,
            ground_truth_cwe=ground_truth_cwe,
            synthesizer=[],  # Initialize as list for iterations
            validator=[]     # Initialize as list for iterations
        )
        
        print(f"\n{'='*80}")
        print(f"Analyzing code snippet {index}")
        print(f"{'='*80}")
        
        # Phase 1: Context Analysis (Agent 1)
        print("Phase 1: Context Analysis...")
        sys_prompt, usr_prompt = self.prompts.get_context_analyzer_prompts(code, language)
        context_response = self.call_llm(sys_prompt, usr_prompt)
        result.context_analyzer = self.create_agent_response(
            "Context Analyzer", sys_prompt, usr_prompt, context_response
        )
        
        # Phase 2: Parallel Analysis (Agents 2, 3, 4)
        print("Phase 2: Parallel Specialist Analysis...")
        
        # Agent 2: Memory Safety
        sys_prompt, usr_prompt = self.prompts.get_memory_safety_prompts(
            code, language, context_response
        )
        memory_response = self.call_llm(sys_prompt, usr_prompt)
        result.memory_safety = self.create_agent_response(
            "Memory Safety Analyst", sys_prompt, usr_prompt, memory_response
        )
        
        # Agent 3: Input Validation
        sys_prompt, usr_prompt = self.prompts.get_input_validation_prompts(
            code, language, context_response
        )
        validation_response = self.call_llm(sys_prompt, usr_prompt)
        result.input_validation = self.create_agent_response(
            "Input Validation Specialist", sys_prompt, usr_prompt, validation_response
        )
        
        # Agent 4: Pattern Expert
        sys_prompt, usr_prompt = self.prompts.get_pattern_expert_prompts(
            code, language, context_response, memory_response, validation_response
        )
        pattern_response = self.call_llm(sys_prompt, usr_prompt)
        result.pattern_expert = self.create_agent_response(
            "Pattern Recognition Expert", sys_prompt, usr_prompt, pattern_response
        )
        
        # Prepare analyses for synthesis
        all_analyses = {
            'context': context_response,
            'memory': memory_response,
            'validation': validation_response,
            'patterns': pattern_response
        }
        
        # Phase 3-5: Iterative Synthesis-Validation-Judgment Loop
        iteration = 0
        previous_feedback = None
        final_decision_reached = False
        
        while iteration < self.max_iterations and not final_decision_reached:
            print(f"\nIteration {iteration + 1}/{self.max_iterations}")
            
            # Phase 3: Synthesis (Agent 5)
            print(f"  Phase 3: Vulnerability Synthesis (Iteration {iteration + 1})...")
            sys_prompt, usr_prompt = self.prompts.get_synthesizer_prompts(
                code, language, all_analyses, iteration, previous_feedback # type: ignore
            )
            synthesizer_response = self.call_llm(sys_prompt, usr_prompt)
            
            # Parse and validate synthesizer response
            synth_data = self.parse_json_response(synthesizer_response)
            synth_data = self.validate_and_fix_labels(synth_data, "Synthesizer")
            
            result.synthesizer.append(self.create_agent_response( # type: ignore
                "Vulnerability Synthesizer", sys_prompt, usr_prompt, 
                synthesizer_response, iteration
            ))
            
            # Phase 4: Validation (Agent 6)
            print(f"  Phase 4: Validation (Iteration {iteration + 1})...")
            sys_prompt, usr_prompt = self.prompts.get_validator_prompts(
                code, language, synthesizer_response, all_analyses, iteration
            )
            validator_response = self.call_llm(sys_prompt, usr_prompt)
            
            # Parse and validate validator response
            val_data = self.parse_json_response(validator_response)
            val_data = self.validate_and_fix_labels(val_data, "Validator")
            
            result.validator.append(self.create_agent_response( # type: ignore
                "Validator", sys_prompt, usr_prompt, validator_response, iteration
            ))
            
            # Phase 5: Final Judgment (Agent 7)
            print(f"  Phase 5: Final Adjudication (Iteration {iteration + 1})...")
            sys_prompt, usr_prompt = self.prompts.get_final_judge_prompts(
                code, language, synthesizer_response, validator_response, iteration
            )
            judge_response = self.call_llm(sys_prompt, usr_prompt)
            
            # Parse judge's decision
            judge_data = self.parse_json_response(judge_response)
            
            # Validate and fix label mismatches
            judge_data = self.validate_and_fix_labels(judge_data, "Final Judge") # type: ignore
            
            if judge_data:
                decision_type = judge_data.get('decision_type', 'ADJUDICATION')
                final_verdict = judge_data.get('final_verdict', 'UNKNOWN')
                
                if final_verdict == 'ITERATE' and iteration < self.max_iterations - 1:
                    print(f"    → Judge requests iteration. Refining analysis...")
                    result.refinement_occurred = True
                    previous_feedback = judge_data.get('guidance_for_iteration', 
                                                       validator_response)
                    iteration += 1
                else:
                    # Final decision reached
                    final_decision_reached = True
                    result.final_judge = self.create_agent_response(
                        "Final Judge", sys_prompt, usr_prompt, judge_response, iteration
                    )
                    result.final_verdict = final_verdict if final_verdict != 'ITERATE' else 'MANUAL_REVIEW'
                    result.final_label = judge_data.get('final_label')
                    result.confidence = judge_data.get('confidence', 'UNKNOWN')
                    
                    if final_verdict == 'ITERATE':
                        print(f"    → Maximum iterations reached. Marking for manual review.")
            else:
                # Couldn't parse - treat as final decision
                final_decision_reached = True
                result.final_judge = self.create_agent_response(
                    "Final Judge", sys_prompt, usr_prompt, judge_response, iteration
                )
                # Fallback parsing
                if 'VULNERABLE' in judge_response.upper():
                    result.final_verdict = 'VULNERABLE'
                    result.final_label = 1
                elif 'SAFE' in judge_response.upper():
                    result.final_verdict = 'SAFE'
                    result.final_label = 0
                else:
                    result.final_verdict = 'MANUAL_REVIEW'
                    result.final_label = None
        
        result.total_iterations = iteration + 1
        
        # Calculate accuracy
        if result.final_label is not None:
            result.is_correct = (result.final_label == ground_truth_label)
            if not result.is_correct:
                if result.final_label == 1 and ground_truth_label == 0:
                    result.error_type = 'FP'  # False Positive
                elif result.final_label == 0 and ground_truth_label == 1:
                    result.error_type = 'FN'  # False Negative
        
        print(f"\n{'='*80}")
        print(f"Final Verdict: {result.final_verdict} (Label: {result.final_label})")
        print(f"Ground Truth: {ground_truth_label}")
        print(f"Correct: {result.is_correct}, Error Type: {result.error_type}")
        print(f"Total Iterations: {result.total_iterations}")
        print(f"Refinement Occurred: {result.refinement_occurred}")
        print(f"{'='*80}")
        
        return result
    
    def generate_markdown_report(self, result: AnalysisResult, output_dir: Path):
        """Generate detailed markdown report for a single analysis"""
        
        output_file = output_dir / f"analysis_{result.index:04d}.md"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write(f"# Vulnerability Analysis Report - Sample {result.index}\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Language:** {result.programming_language}\n\n")
            f.write(f"**Total Iterations:** {result.total_iterations}\n\n")
            f.write(f"**Refinement Occurred:** {'Yes' if result.refinement_occurred else 'No'}\n\n")
            
            # Code Snippet
            f.write("## Code Snippet\n\n")
            f.write(f"```{result.programming_language.lower()}\n")
            f.write(result.code_snippet)
            f.write("\n```\n\n")
            
            # Ground Truth
            f.write("## Ground Truth\n\n")
            f.write(f"- **Label:** {result.ground_truth_label} ({'VULNERABLE' if result.ground_truth_label == 1 else 'SAFE'})\n")
            f.write(f"- **CWE ID:** {result.ground_truth_cwe}\n\n")
            
            # Agent Analyses
            f.write("## Multi-Agent Analysis\n\n")
            
            # Phase 1 & 2 agents (single iteration)
            single_agents = [
                ("Agent 1: Context Analyzer", result.context_analyzer),
                ("Agent 2: Memory Safety Analyst", result.memory_safety),
                ("Agent 3: Input Validation Specialist", result.input_validation),
                ("Agent 4: Pattern Recognition Expert", result.pattern_expert)
            ]
            
            for agent_name, agent_response in single_agents:
                if agent_response:
                    self._write_agent_section(f, agent_name, agent_response)
            
            # Iterative agents (can have multiple iterations)
            if result.synthesizer:
                for i, synth_response in enumerate(result.synthesizer):
                    agent_name = f"Agent 5: Vulnerability Synthesizer (Iteration {i + 1})"
                    self._write_agent_section(f, agent_name, synth_response)
            
            if result.validator:
                for i, val_response in enumerate(result.validator):
                    agent_name = f"Agent 6: Validator (Iteration {i + 1})"
                    self._write_agent_section(f, agent_name, val_response)
            
            # Final Judge
            if result.final_judge:
                self._write_agent_section(f, "Agent 7: Final Judge", result.final_judge)
            
            # Final Verdict
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
            
            # Accuracy Assessment
            f.write("## Accuracy Assessment\n\n")
            f.write(f"- **Prediction Correct:** {result.is_correct}\n")
            if result.error_type:
                f.write(f"- **Error Type:** {result.error_type}\n")
                if result.error_type == 'FP':
                    f.write("  - **False Positive:** System flagged as vulnerable but it's actually safe\n")
                elif result.error_type == 'FN':
                    f.write("  - **False Negative:** System flagged as safe but it's actually vulnerable\n")
            f.write("\n")
            
            # Summary Table
            f.write("## Summary\n\n")
            f.write("| Metric | Value |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Ground Truth | {result.ground_truth_label} ({'VULNERABLE' if result.ground_truth_label == 1 else 'SAFE'}) |\n")
            f.write(f"| Prediction | {result.final_label} ({result.final_verdict}) |\n")
            f.write(f"| Confidence | {result.confidence} |\n")
            f.write(f"| Correct | {'✅ Yes' if result.is_correct else '❌ No'} |\n")
            f.write(f"| Error Type | {result.error_type if result.error_type else 'N/A'} |\n")
            f.write(f"| Iterations | {result.total_iterations} |\n")
            f.write(f"| Refinement | {'Yes' if result.refinement_occurred else 'No'} |\n")
        
        print(f"Report saved to: {output_file}")
    
    def _write_agent_section(self, f, agent_name: str, agent_response: AgentResponse):
        """Helper method to write an agent section in markdown"""
        f.write(f"### {agent_name}\n\n")
        
        f.write("#### System Prompt\n\n")
        f.write("```\n")
        f.write(agent_response.system_prompt)
        f.write("\n```\n\n")
        
        f.write("#### User Prompt\n\n")
        f.write("```\n")
        f.write(agent_response.user_prompt)
        f.write("\n```\n\n")
        
        f.write("#### Response\n\n")
        f.write("```\n")
        f.write(agent_response.response)
        f.write("\n```\n\n")
        
        f.write(f"*Timestamp: {agent_response.timestamp}*\n\n")
        f.write("---\n\n")


def main():
    """Main execution function"""
    
    # Get API key from environment
    api_key = os.getenv('OPENAI_KEY')
    if not api_key:
        print("Error: OPENAI_KEY not found in environment variables")
        print("Please ensure your .bashrc contains: export OPENAI_KEY='your-key-here'")
        return
    
    # Initialize detector
    detector = MultiAgentVulnerabilityDetector(api_key, max_iterations=3)
    
# ==============================================================================================
    # Load dataset from CSV
    dataset_path = "test_1.csv"  # Path to your CSV file

    # Base directory where the relative paths in 'file' column start from. 
    # If the script is running in the root folder (where 'C/testcases/...' exists), use "."
    base_code_dir = "." 
    
    print(f"Loading dataset from: {dataset_path}")
    
    # Read the CSV file
    df = pd.read_csv(dataset_path)
    
    dataset = []
    for index, row in df.iterrows():
        # Construct full path to the code file
        relative_path = row['file']
        full_path = os.path.join(base_code_dir, relative_path)
        
        try:
            # Read the content of the code file
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
                
            # Determine programming language based on file extension
            _, ext = os.path.splitext(relative_path)
            if ext.lower() == '.cpp':
                language = 'C++'
            elif ext.lower() == '.c':
                language = 'C'
            else:
                language = 'Unknown'

            # Construct the sample dictionary to match previous structure
            sample = {
                'code_snippet': code_content,
                'programming_language': language,
                'ground_truth': {
                    'label': row['vul'],  # Maps 'vul' column to label
                    'cwe_id': row['cwe']  # Maps 'cwe' column to cwe_id
                },
                'file_path': relative_path # Keeping track of source file
            }
            dataset.append(sample)
            
        except FileNotFoundError:
            print(f"Warning: Could not find file {full_path}. Skipping index {index}.")
            continue

    print(f"Loaded {len(dataset)} samples successfully")
    
    # Create output directory
    output_dir = Path("./juliet_analysis")
    output_dir.mkdir(parents=True, exist_ok=True)
    
# ==============================================================================================

    # Process each sample
    results = []
    for i, sample in enumerate(dataset):
        code = sample['code_snippet']
        language = sample['programming_language']
        ground_truth_label = sample['ground_truth']['label']
        ground_truth_cwe = sample['ground_truth']['cwe_id']
        
        # Run analysis
        result = detector.analyze_code(
            code=code,
            language=language,
            index=i,
            ground_truth_label=ground_truth_label,
            ground_truth_cwe=ground_truth_cwe
        )
        
        # Generate report
        detector.generate_markdown_report(result, output_dir)
        
        results.append(result)
    
    # Generate summary report
    print("\n" + "="*80)
    print("ANALYSIS COMPLETE - Generating Summary Report")
    print("="*80)
    
    summary_file = output_dir / "SUMMARY.md"
    with open(summary_file, 'w') as f:
        f.write("# Multi-Agent Vulnerability Detection - Summary Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Model:** gpt-4o-mini\n")
        f.write(f"**Total Samples:** {len(results)}\n\n")
        
        # Calculate metrics
        total = len(results)
        correct = sum(1 for r in results if r.is_correct)
        fp_count = sum(1 for r in results if r.error_type == 'FP')
        fn_count = sum(1 for r in results if r.error_type == 'FN')
        manual_review = sum(1 for r in results if r.final_label is None)
        
        # Calculate true positives and true negatives
        tp = sum(1 for r in results if r.final_label == 1 and r.ground_truth_label == 1)
        tn = sum(1 for r in results if r.final_label == 0 and r.ground_truth_label == 0)
        
        # Calculate precision, recall, F1
        precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0
        recall = tp / (tp + fn_count) if (tp + fn_count) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Iteration statistics
        total_iterations = sum(r.total_iterations for r in results)
        avg_iterations = total_iterations / total if total > 0 else 0
        refinement_count = sum(1 for r in results if r.refinement_occurred)
        
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
        
        f.write("## Iteration Statistics\n\n")
        f.write(f"- **Total Iterations:** {total_iterations}\n")
        f.write(f"- **Average Iterations per Sample:** {avg_iterations:.2f}\n")
        f.write(f"- **Samples Requiring Refinement:** {refinement_count} ({100*refinement_count/total:.2f}%)\n\n")
        
        # Detailed results table
        f.write("## Detailed Results\n\n")
        f.write("| Index | Ground Truth | Prediction | Confidence | Iterations | Correct | Error Type |\n")
        f.write("|-------|--------------|------------|------------|------------|---------|------------|\n")
        
        for r in results:
            gt_label = "VUL" if r.ground_truth_label == 1 else "SAFE"
            pred_label = "VUL" if r.final_label == 1 else ("SAFE" if r.final_label == 0 else "MR")
            correct_icon = "✅" if r.is_correct else "❌"
            error = r.error_type if r.error_type else "-"
            
            f.write(f"| {r.index:04d} | {gt_label} | {pred_label} | {r.confidence} | {r.total_iterations} | {correct_icon} | {error} |\n")
    
    print(f"\nSummary report saved to: {summary_file}")
    print(f"Individual reports saved to: {output_dir}")
    print(f"\n{'='*80}")
    print("FINAL STATISTICS")
    print(f"{'='*80}")
    print(f"Total accuracy: {correct}/{total} ({100*correct/total:.2f}%)")
    print(f"Precision: {precision:.4f} ({100*precision:.2f}%)")
    print(f"Recall: {recall:.4f} ({100*recall:.2f}%)")
    print(f"F1 Score: {f1_score:.4f} ({100*f1_score:.2f}%)")
    print(f"False Positives: {fp_count}")
    print(f"False Negatives: {fn_count}")
    print(f"Average Iterations: {avg_iterations:.2f}")
    print(f"Samples Refined: {refinement_count}/{total}")


if __name__ == "__main__":
    main()
