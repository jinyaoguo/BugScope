"""
Evaluation script using Claude Code SDK to audit entire projects for potential bugs.

Uses pre-synthesized detection prompts (from OSO_prompt.json, DBZ_prompt.json,
MLK_prompt.json) and lets Claude Code analyze each project as a whole rather than
individual files.

Usage:
    # Run all bug types on all projects
    unset CLAUDECODE && python eval_claude_code_project.py --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Specific bug types only
    unset CLAUDECODE && python eval_claude_code_project.py --bug-types OSO DBZ --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Specific projects only
    unset CLAUDECODE && python eval_claude_code_project.py --projects vim zstd --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Custom prompt directory and output directory
    unset CLAUDECODE && python eval_claude_code_project.py --prompt-dir result/claude_code --output-dir /path/to/results --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

Note:
    - Must `unset CLAUDECODE` if running from within a Claude Code session.
    - Must `conda activate py311` before running.
    - Results (JSON) are saved to --output-dir (default: result/claude_code_project/).
"""

import asyncio
import json
import os
import time
import argparse
from pathlib import Path
from typing import Dict, List
from datetime import datetime

from claude_code_sdk import (
    query, ClaudeCodeOptions, TextBlock, ResultMessage, AssistantMessage,
    ToolUseBlock,
)

BASE_PATH = Path(__file__).resolve().parent.parent

PROJECTS_DIR = Path("/data4/guo846/RepoAudit-BugScope/baseline/projects")

PROJECTS = ["dynamips", "git", "openldap", "systemd", "vim", "zstd"]

BUG_TYPES = ["OSO", "NOF", "ASO", "DBZ", "MLK"]

BUG_TYPE_FULL_NAME: Dict[str, str] = {
    "OSO": "Buffer Overflow (an out-of-bounds read or write beyond the upper bound of a buffer)",
    "NOF": "Buffer Underflow (a buffer access using a negative offset)",
    "ASO": "Allocation Size Overflow (allocation-size arithmetic wraps and produces an undersized buffer)",
    "DBZ": "Divide By Zero (integer division or modulo where the divisor could be zero without a proper guard)",
    "MLK": "Memory Leak (dynamically allocated memory via malloc/calloc/realloc/new not freed on all execution paths)",
}

DEFAULT_PROMPT_DIR = str(BASE_PATH / "result" / "claude_code")


def load_synthesized_prompt(prompt_dir: str, bug_type: str) -> dict:
    """Load a pre-synthesized prompt JSON file."""
    prompt_file = os.path.join(prompt_dir, f"{bug_type}_prompt.json")
    if not os.path.exists(prompt_file):
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
    with open(prompt_file, "r") as f:
        return json.load(f)


def build_detection_system_prompt(synthesized: dict, bug_type: str) -> str:
    """Build a project-level detection system prompt from a synthesized prompt dict."""
    bug_name = synthesized.get("bug_type", bug_type)
    pattern_desc = synthesized.get("pattern_description", "")
    rules = synthesized.get("detection_rules", [])

    rules_str = ""
    if rules:
        rules_str = "\n\nDetection Rules:\n" + "\n".join(
            f"  {i+1}. {r}" for i, r in enumerate(rules)
        )

    pos_examples = synthesized.get("positive_examples", [])
    neg_examples = synthesized.get("negative_examples", [])

    examples_str = ""
    if pos_examples:
        examples_str += "\n\n--- Positive Examples (BUGGY code) ---"
        for i, ex in enumerate(pos_examples):
            examples_str += f"\nExample {i+1}:\n```c\n{ex['code']}\n```\nWhy buggy: {ex['description']}\n"
    if neg_examples:
        examples_str += "\n\n--- Negative Examples (SAFE code) ---"
        for i, ex in enumerate(neg_examples):
            examples_str += f"\nExample {i+1}:\n```c\n{ex['code']}\n```\nWhy safe: {ex['description']}\n"

    return f"""You are a senior C/C++ security auditor specializing in {bug_name} detection.

Your task is to review the given source code project and detect potential {bug_name} bugs.

{pattern_desc}{rules_str}{examples_str}

For each potential bug found, report:
1. Bug Type ({bug_type})
2. File Path (relative to the project root)
3. Location (function name and approximate line number)
4. Root Cause (brief explanation of why this is a bug)

Format your response as:
=== BUG REPORT ===
Bug Type: {bug_type}
File: <relative_file_path>
Location: <function_name>, line <number>
Root Cause: <explanation>
=== END REPORT ===

If no bugs are found, respond with:
=== NO BUGS FOUND ===

Be thorough but precise. Only report genuine bugs with clear evidence.
Do NOT speculate about variable values or relationships beyond what is explicitly present in the code."""


def build_audit_prompt(project_name: str, project_dir: Path, bug_type: str) -> str:
    """Build the prompt for auditing an entire project."""
    bug_desc = BUG_TYPE_FULL_NAME[bug_type]

    return f"""Please audit the C/C++ project "{project_name}" located at: {project_dir}

Your goal is to detect potential {bug_type} ({bug_desc}) bugs across the entire project.

Steps:
1. Use Glob to discover C/C++ source files (*.c, *.h, *.cpp, *.cc, *.hpp) in the project.
2. Read the most relevant source files — focus on files that are likely to contain {bug_type} bugs based on their names and structure (e.g., files dealing with memory management, parsing, I/O, arithmetic).
3. For any unclear definitions (macros, struct fields, helper functions, constants) referenced in suspicious code, use Grep to search for their definitions.
4. After gathering sufficient context, analyze the code and report any {bug_type} bugs you find.

Guidelines:
- You do NOT need to read every file. Prioritize files that are most likely to contain {bug_type} bugs.
- Use your expertise to identify suspicious patterns and focus your analysis there.
- Report each bug with the file path relative to the project root.
- Only report bugs with clear evidence based on the code and context you retrieved. Do not speculate."""


async def review_project(
    project_name: str, project_dir: Path, bug_type: str,
    system_prompt: str, model: str = None, timeout_seconds: int = 600,
) -> dict:
    """Run Claude Code to detect bugs in an entire project."""
    if not project_dir.exists():
        return {
            "project": project_name,
            "bug_type": bug_type,
            "status": "error",
            "error": f"Project directory not found: {project_dir}",
        }

    prompt = build_audit_prompt(project_name, project_dir, bug_type)

    options = ClaudeCodeOptions(
        system_prompt=system_prompt,
        max_turns=30,
        permission_mode="bypassPermissions",
        allowed_tools=["Read", "Grep", "Glob", "Bash"],
        cwd=str(project_dir),
    )
    if model:
        options.model = model

    result_text = ""
    assistant_texts = []
    cost_usd = 0.0
    usage = None
    start_time = time.time()

    try:
        async def _run_query():
            nonlocal result_text, assistant_texts, cost_usd, usage
            turn = 0
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    turn += 1
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            assistant_texts.append(block.text)
                            print(f"    [Turn {turn}] {block.text[:200]}")
                        elif isinstance(block, ToolUseBlock):
                            print(f"    [Turn {turn}] Tool: {block.name}({json.dumps(block.input, ensure_ascii=False)[:150]})")
                elif isinstance(message, ResultMessage):
                    if message.result:
                        result_text = message.result
                    cost_usd = message.total_cost_usd or 0.0
                    usage = message.usage
                    print(f"    [Result] turns={message.num_turns}, cost=${cost_usd:.4f}")

        await asyncio.wait_for(_run_query(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        final_response = result_text if result_text else "\n".join(assistant_texts)
        return {
            "project": project_name,
            "project_dir": str(project_dir),
            "bug_type": bug_type,
            "status": "timeout",
            "response": final_response,
            "elapsed_seconds": round(elapsed, 2),
            "cost_usd": cost_usd,
            "usage": usage,
        }
    except Exception as e:
        return {
            "project": project_name,
            "project_dir": str(project_dir),
            "bug_type": bug_type,
            "status": "error",
            "error": str(e),
        }

    elapsed = time.time() - start_time
    final_response = result_text if result_text else "\n".join(assistant_texts)

    return {
        "project": project_name,
        "project_dir": str(project_dir),
        "bug_type": bug_type,
        "status": "success",
        "response": final_response,
        "elapsed_seconds": round(elapsed, 2),
        "cost_usd": cost_usd,
        "usage": usage,
    }


async def run_evaluation(
    bug_types: List[str] = None,
    projects: List[str] = None,
    output_dir: str = None,
    prompt_dir: str = None,
    model: str = None,
    timeout_seconds: int = 600,
):
    """Evaluate projects using pre-synthesized prompts."""
    if bug_types is None:
        bug_types = BUG_TYPES
    if projects is None:
        projects = PROJECTS
    if output_dir is None:
        output_dir = str(BASE_PATH / "result" / "claude_code_project")
    if prompt_dir is None:
        prompt_dir = DEFAULT_PROMPT_DIR

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

    # Load pre-synthesized detection prompts
    detection_prompts: Dict[str, str] = {}
    for bug_type in bug_types:
        print(f"[{bug_type}] Loading detection prompt from {prompt_dir}...")
        synthesized = load_synthesized_prompt(prompt_dir, bug_type)
        detection_prompts[bug_type] = build_detection_system_prompt(synthesized, bug_type)
        print(f"[{bug_type}] Detection prompt loaded successfully.")

    # Evaluate each bug type across all projects
    all_results: Dict[str, List[dict]] = {bt: [] for bt in bug_types}
    total_tasks = len(projects) * len(bug_types)
    processed = 0

    for bug_type in bug_types:
        system_prompt = detection_prompts[bug_type]
        print(f"\n{'='*60}")
        print(f"Bug type: {bug_type}")
        print(f"{'='*60}")

        for project_name in projects:
            project_dir = PROJECTS_DIR / project_name
            if not project_dir.exists():
                print(f"[WARN] Project directory not found: {project_dir}, skipping.")
                continue

            processed += 1
            print(f"\n[{processed}/{total_tasks}] {project_name} x {bug_type}")

            result = await review_project(
                project_name, project_dir, bug_type, system_prompt,
                model=model, timeout_seconds=timeout_seconds,
            )
            all_results[bug_type].append(result)

            if result["status"] == "success":
                print(f"  Done in {result['elapsed_seconds']}s, cost=${result.get('cost_usd', 0):.4f}")
            elif result["status"] == "timeout":
                print(f"  TIMEOUT after {result['elapsed_seconds']}s (partial response saved)")
            else:
                print(f"  ERROR: {result.get('error', 'unknown')}")

        # Save per-bug-type results
        out_file = os.path.join(output_dir, f"real_world_{bug_type}.json")
        with open(out_file, "w") as f:
            json.dump(all_results[bug_type], f, indent=2, ensure_ascii=False)
        print(f"\nSaved {bug_type} results to {out_file}")

    # Print summary
    print(f"\n{'='*60}")
    print("EVALUATION SUMMARY")
    print(f"{'='*60}")
    total_cost = 0.0
    for bug_type, results in all_results.items():
        success = sum(1 for r in results if r["status"] == "success")
        timeouts = sum(1 for r in results if r["status"] == "timeout")
        errors = sum(1 for r in results if r["status"] == "error")
        bt_cost = sum(r.get("cost_usd", 0) or 0 for r in results)
        total_cost += bt_cost
        print(f"  {bug_type}: {success} success, {timeouts} timeout, {errors} errors (total {len(results)}), cost=${bt_cost:.4f}")
    print(f"  TOTAL COST: ${total_cost:.4f}")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate Claude Code on project-level bug detection using pre-synthesized prompts"
    )
    parser.add_argument(
        "--bug-types",
        nargs="+",
        choices=BUG_TYPES,
        default=None,
        help="Bug types to evaluate (default: all)",
    )
    parser.add_argument(
        "--projects",
        nargs="+",
        choices=PROJECTS,
        default=None,
        help="Projects to audit (default: all 6)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for results (default: result/claude_code_project/)",
    )
    parser.add_argument(
        "--prompt-dir",
        type=str,
        default=None,
        help=f"Directory with pre-synthesized prompt JSON files (default: {DEFAULT_PROMPT_DIR})",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model to use (e.g. claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Per-project-per-bugtype timeout in seconds (default: 600)",
    )
    args = parser.parse_args()

    asyncio.run(run_evaluation(
        bug_types=args.bug_types,
        projects=args.projects,
        output_dir=args.output_dir,
        prompt_dir=args.prompt_dir,
        model=args.model,
        timeout_seconds=args.timeout,
    ))


if __name__ == "__main__":
    main()
