"""
Evaluation script using Claude Code SDK to review C/C++ files for potential bugs.

Phase 1: Synthesize per-bug-type detection prompts from real-world bug report URLs.
Phase 2: Use synthesized prompts to evaluate benchmark files.

Usage:
    # Run full pipeline (synthesize prompts from example URLs, then evaluate all bug types)
    unset CLAUDECODE && python eval_claude_code.py --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Evaluate only specific bug types
    unset CLAUDECODE && python eval_claude_code.py --bug-types BOF DBZ --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Skip synthesis, use built-in fallback prompts directly
    unset CLAUDECODE && python eval_claude_code.py --skip-synthesis --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Reuse previously synthesized prompts (saved as BOF_prompt.json, etc.)
    unset CLAUDECODE && python eval_claude_code.py --prompt-dir result/claude_code --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Custom output directory
    unset CLAUDECODE && python eval_claude_code.py --output-dir /path/to/results --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

Note:
    - Must `unset CLAUDECODE` if running from within a Claude Code session to avoid nested session errors.
    - Must `conda activate py311` before running.
    - Model ID uses Bedrock format (e.g. us.anthropic.claude-3-7-sonnet-20250219-v1:0).
    - Results (JSON) and synthesized prompts are saved to --output-dir (default: result/claude_code/).
"""

import asyncio
import json
import os
import re
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from claude_code_sdk import (
    query, ClaudeCodeOptions, TextBlock, ResultMessage, AssistantMessage,
    ToolUseBlock, ToolResultBlock,
)

BASE_PATH = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Benchmark files to evaluate
# ---------------------------------------------------------------------------
BOF_files = {
    "../benchmark/Reproduce/Cpp/BUF/curl/lib/sendf.c",
    "../benchmark/Reproduce/Cpp/AOF/sapi/cli/php_cli_server.c",
    "../benchmark/Reproduce/Cpp/BUF/opcache/zend_accelerator_blacklist.c",
    "../benchmark/Reproduce/Cpp/AOF/bfdd/control.c",
    "../benchmark/Reproduce/Cpp/BOF/redis/src/t_zset.c",
    "../benchmark/Reproduce/Cpp/AOF/libcpp/files.cc",
    "../benchmark/Reproduce/Cpp/AOF/ld/libdep_plugin.c",
    "../benchmark/Reproduce/Cpp/BUF/openssl/crypto/bf/bf_ofb64.c",
    "../benchmark/Reproduce/Cpp/BOF/qemu/contrib/elf2dmp/qemu_elf.c",
    "../benchmark/Reproduce/Cpp/BOF/systemd/src/basic/time-util.c",
}

DBZ_files = {
    "../benchmark/Reproduce/Cpp/DBZ/libuv/src/unix/linux-core.c",
    "../benchmark/Reproduce/Cpp/DBZ/goaccess/src/gholder.c",
    "../benchmark/Reproduce/Cpp/DBZ/MagickCore/cache.c",
    "../benchmark/Reproduce/Cpp/DBZ/systemd/src/shared/creds-util.c",
    "../benchmark/Reproduce/Cpp/DBZ/vim/src/misc2.c",
    "../benchmark/Reproduce/Cpp/DBZ/openssl/crypto/pkcs12/p12_key.c",
    "../benchmark/Reproduce/Cpp/DBZ/gdb/amd64-tdep.c",
    "../benchmark/Reproduce/Cpp/DBZ/lib/math/rational.c",
    "../benchmark/Reproduce/Cpp/DBZ/agp/isoch.c",
    "../benchmark/Reproduce/Cpp/DBZ/git/builtin/pack-objects.c",
}

MLK_files = {
    "../benchmark/Reproduce/Cpp/MLK/memcached/memcached.c",
    "../benchmark/Reproduce/Cpp/MLK/libsass/src/permutate.hpp",
    "../benchmark/Reproduce/Cpp/MLK/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c",
    "../benchmark/Reproduce/Cpp/MLK/mm/damon/reclaim.c",
    "../benchmark/Reproduce/Cpp/MLK/rtl_433/src/sdr.c",
    "../benchmark/Reproduce/Cpp/MLK/TrinityEmulator-2/hw/express-gpu/egl_display_wgl.c",
    "../benchmark/Reproduce/Cpp/MLK/TrinityEmulator/contrib/elf2dmp/main.c",
    "../benchmark/Reproduce/Cpp/MLK/binutils/bucomm.c",
}

BUG_TYPE_FILES: Dict[str, set] = {
    "BOF": BOF_files,
    "DBZ": DBZ_files,
    "MLK": MLK_files,
}

# ---------------------------------------------------------------------------
# Example bug report URLs for prompt synthesis
# ---------------------------------------------------------------------------
BOF_examples = [
    "https://github.com/FRRouting/frr/issues/11624",
    "https://github.com/facebook/zstd/issues/3200",
    "https://github.com/systemd/systemd/issues/23258",
]

DBZ_examples = [
    "https://lore.kernel.org/linux-block/21cb65d1-b91a-2627-3824-292de3a7553a@suse.de/T/#t",
    "https://lore.kernel.org/linux-parisc/alpine.DEB.2.22.394.2105121353530.1204552@ramsan.of.borg/T/#t",
]

MLK_examples = [
    "https://github.com/memcached/memcached/pull/1216",
    "https://github.com/libuv/libuv/pull/4720",
]

BUG_TYPE_EXAMPLES: Dict[str, List[str]] = {
    "BOF": BOF_examples,
    "DBZ": DBZ_examples,
    "MLK": MLK_examples,
}

BUG_TYPE_FULL_NAME: Dict[str, str] = {
    "BOF": "Buffer Overflow (including out-of-bounds read/write, buffer overrun, allocation size overflow, buffer underflow)",
    "DBZ": "Divide By Zero (integer division or modulo where the divisor could be zero without a proper guard)",
    "MLK": "Memory Leak (dynamically allocated memory via malloc/calloc/realloc/new not freed on all execution paths)",
}

# ---------------------------------------------------------------------------
# Phase 1: Synthesize detection prompts from example URLs
# ---------------------------------------------------------------------------

SYNTHESIZER_SYSTEM_PROMPT = """You are a senior C/C++ static analysis expert and prompt engineer.
Your task is to analyze real-world bug reports and synthesize a precise detection prompt that can guide an LLM to detect similar bugs in source code.
You have access to tools to fetch web content. Use them to read the bug report URLs provided."""


def build_synthesis_prompt(bug_type: str, urls: List[str]) -> str:
    """Build the prompt asking Claude Code to synthesize a detection prompt from example URLs."""
    bug_desc = BUG_TYPE_FULL_NAME[bug_type]
    urls_str = "\n".join(f"  - {url}" for url in urls)

    return f"""I need you to synthesize a bug detection prompt for: {bug_type} — {bug_desc}.

Here are real-world bug report URLs. Please fetch and analyze each one:
{urls_str}

For each URL:
1. Fetch the page content.
2. Identify the root cause, the buggy code pattern, and the fix applied.
3. Extract or reconstruct a minimal code snippet demonstrating the bug.

After analyzing ALL examples, produce the output below.

OUTPUT FORMAT — return a single JSON object wrapped in triple tildes (~~~json ... ~~~) with these fields:

{{
    "bug_type": "<full bug type name, e.g. Buffer Overflow>",
    "detection_rules": [
        "<rule 1: a precise, conservative condition that identifies this bug>",
        "<rule 2: ...>",
        "..."
    ],
    "pattern_description": "<A detailed description combining all rules, explaining when code is buggy vs safe. Be specific and conservative to minimize false positives.>",
    "positive_examples": [
        {{
            "code": "<minimal buggy C/C++ snippet derived from real bugs>",
            "description": "<why this is buggy, referencing specific variables/conditions>"
        }}
    ],
    "negative_examples": [
        {{
            "code": "<similar-looking but safe C/C++ snippet>",
            "description": "<why this is safe despite looking suspicious>"
        }}
    ]
}}

Requirements:
- Base patterns on the ACTUAL bugs from the URLs, not generic textbook examples.
- Include at least 2 positive and 2 negative examples.
- Negative examples should be tricky — code that looks suspicious but is actually safe.
- detection_rules should be numbered, precise, and conservative.
- pattern_description should be a cohesive paragraph that an LLM can use directly as instructions.

Answer: ~~~json
<your JSON>
~~~"""


async def synthesize_detection_prompt(
    bug_type: str, urls: List[str], model: str = None
) -> Optional[dict]:
    """Use Claude Code to fetch example URLs and synthesize a detection prompt."""
    prompt = build_synthesis_prompt(bug_type, urls)

    options = ClaudeCodeOptions(
        system_prompt=SYNTHESIZER_SYSTEM_PROMPT,
        max_turns=20,
        permission_mode="bypassPermissions",
        allowed_tools=["WebFetch", "Bash", "Read"],
    )
    if model:
        options.model = model

    result_text = ""
    assistant_texts = []
    start_time = time.time()

    turn = 0
    try:
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                turn += 1
                for block in message.content:
                    if isinstance(block, TextBlock):
                        assistant_texts.append(block.text)
                        print(f"    [Synthesis Turn {turn}] {block.text[:200]}")
                    elif isinstance(block, ToolUseBlock):
                        print(f"    [Synthesis Turn {turn}] Tool: {block.name}({json.dumps(block.input, ensure_ascii=False)[:150]})")
            elif isinstance(message, ResultMessage):
                if message.result:
                    result_text = message.result
                cost_usd = message.total_cost_usd
                usage = message.usage
                print(f"    [Synthesis Result] turns={message.num_turns}, cost=${cost_usd:.4f}")
    except Exception as e:
        print(f"  [ERROR] Synthesis failed for {bug_type}: {e}")
        return None

    elapsed = time.time() - start_time
    print(f"  Synthesis for {bug_type} completed in {elapsed:.1f}s")

    # Use ResultMessage.result as primary; fall back to concatenated assistant texts
    full_response = result_text if result_text else "\n".join(assistant_texts)

    # Parse JSON from ~~~json ... ~~~
    pattern = re.compile(r"~~~(?:json)?\s*([\s\S]*?)\s*~~~")
    match = pattern.search(full_response)
    if not match:
        print(f"  [WARN] Could not extract JSON from synthesis response for {bug_type}")
        print(f"  Raw response (first 500 chars): {full_response[:500]}")
        return None

    try:
        parsed = json.loads(match.group(1))
        print(f"  Successfully parsed detection prompt for {bug_type}")
        return parsed
    except json.JSONDecodeError as e:
        print(f"  [WARN] Invalid JSON in synthesis response for {bug_type}: {e}")
        return None


def build_detection_system_prompt(synthesized: dict, bug_type: str) -> str:
    """Build a file-level detection system prompt from a synthesized prompt dict."""
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

Your task is to review the given source code file and detect potential {bug_name} bugs.

{pattern_desc}{rules_str}{examples_str}

For each potential bug found, report:
1. Bug Type ({bug_type})
2. Location (function name and approximate line number)
3. Root Cause (brief explanation of why this is a bug)

Format your response as:
=== BUG REPORT ===
Bug Type: {bug_type}
Location: <function_name>, line <number>
Root Cause: <explanation>
=== END REPORT ===

If no bugs are found, respond with:
=== NO BUGS FOUND ===

Be thorough but precise. Only report genuine bugs with clear evidence.
Do NOT speculate about variable values or relationships beyond what is explicitly present in the code."""


# Fallback generic prompts if synthesis fails
FALLBACK_SYSTEM_PROMPTS: Dict[str, str] = {
    "BOF": """You are a senior C/C++ security auditor specializing in Buffer Overflow detection.

Your task is to review the given source code file and detect potential buffer overflow bugs, including:
- Out-of-bounds read/write
- Buffer overrun (writing past allocated buffer)
- Allocation size overflow (integer overflow in size computation)
- Buffer underflow (accessing before buffer start)

Detection Rules:
1. If the code explicitly defines both an index and a buffer size, and index >= buffer_size, it is a bug.
2. If a bounds check exists but still allows index >= buffer_size, it is a bug.
3. If integer arithmetic computing an allocation size can overflow/wrap, it is a bug.
4. If neither index nor buffer size can be determined from the code, classify as safe (do not speculate).

For each potential bug found, report:
1. Bug Type (BOF)
2. Location (function name and approximate line number)
3. Root Cause (brief explanation)

Format your response as:
=== BUG REPORT ===
Bug Type: BOF
Location: <function_name>, line <number>
Root Cause: <explanation>
=== END REPORT ===

If no bugs are found, respond with:
=== NO BUGS FOUND ===

Be thorough but precise. Only report genuine bugs with clear evidence.""",

    "DBZ": """You are a senior C/C++ security auditor specializing in Divide By Zero detection.

Your task is to review the given source code file and detect potential divide-by-zero bugs where:
- An integer division or modulo operation uses a divisor that could be zero
- The divisor is not properly guarded by a zero-check before use

Detection Rules:
1. If a variable is used as a divisor (/ or %) and there is no prior check ensuring it is non-zero on that path, it is a bug.
2. If a zero-check exists but does not cover all paths to the division, it is a bug.
3. If the divisor is a constant expression that is provably non-zero, it is safe.
4. If the divisor comes from an external source (function parameter, user input) with no validation, it is a bug.

For each potential bug found, report:
1. Bug Type (DBZ)
2. Location (function name and approximate line number)
3. Root Cause (brief explanation)

Format your response as:
=== BUG REPORT ===
Bug Type: DBZ
Location: <function_name>, line <number>
Root Cause: <explanation>
=== END REPORT ===

If no bugs are found, respond with:
=== NO BUGS FOUND ===

Be thorough but precise. Only report genuine bugs with clear evidence.""",

    "MLK": """You are a senior C/C++ security auditor specializing in Memory Leak detection.

Your task is to review the given source code file and detect potential memory leak bugs where:
- Memory is dynamically allocated (malloc/calloc/realloc/new) but not freed on all execution paths
- Early returns, error paths, or goto-cleanup patterns miss a free()

Detection Rules:
1. If a function allocates memory and has an early-return path that does not free it, it is a leak.
2. If memory is allocated in a loop and a continue/break skips the free, it is a leak.
3. If a pointer to allocated memory is overwritten before being freed, it is a leak.
4. If the function documents that the caller is responsible for freeing (returns the pointer), it is NOT a leak.

For each potential bug found, report:
1. Bug Type (MLK)
2. Location (function name and approximate line number)
3. Root Cause (brief explanation)

Format your response as:
=== BUG REPORT ===
Bug Type: MLK
Location: <function_name>, line <number>
Root Cause: <explanation>
=== END REPORT ===

If no bugs are found, respond with:
=== NO BUGS FOUND ===

Be thorough but precise. Only report genuine bugs with clear evidence.""",
}


# ---------------------------------------------------------------------------
# Phase 2: Evaluate benchmark files
# ---------------------------------------------------------------------------

def resolve_file_path(relative_path: str) -> Path:
    """Resolve a relative benchmark file path to absolute."""
    return (BASE_PATH / "src" / relative_path).resolve()


async def review_file(
    file_path: Path, bug_type: str, system_prompt: str, model: str = None,
    timeout_seconds: int = 300,
) -> dict:
    """Run Claude Code to detect bugs with multi-turn context retrieval.

    Args:
        timeout_seconds: Per-file timeout in seconds (default 300 = 5 min).
    """
    if not file_path.exists():
        return {
            "file": str(file_path),
            "bug_type": bug_type,
            "status": "error",
            "error": f"File not found: {file_path}",
        }

    # Use the project root (two levels up from e.g. agp/isoch.c) as cwd so that
    # Grep/Glob can find headers and definitions across the whole project tree.
    # Heuristic: walk up until we hit a directory containing common root markers,
    # otherwise fall back to file's grandparent.
    project_dir = str(file_path.parent)
    candidate = file_path.parent
    for _ in range(10):
        if any((candidate / marker).exists() for marker in
               ["Makefile", "CMakeLists.txt", "configure", ".git", "README.md", "meson.build"]):
            project_dir = str(candidate)
            break
        if candidate.parent == candidate:
            break
        candidate = candidate.parent

    prompt = f"""Please review the C/C++ source code file at: {file_path}

Your goal is to detect potential {bug_type} bugs in this file.

Steps:
1. Read the target file using the Read tool.
2. Identify functions, macros, types, and external calls that are relevant to potential {bug_type} bugs.
3. For any unclear definitions (macros, struct fields, helper functions, constants) referenced in the code, use Grep or Glob to search the surrounding project directory for their definitions so you can reason precisely. Limit your search to at most 3 lookups to stay focused.
4. After gathering sufficient context, analyze the code and report any {bug_type} bugs you find.

Only report bugs with clear evidence based on the code and context you retrieved. Do not speculate."""

    options = ClaudeCodeOptions(
        system_prompt=system_prompt,
        max_turns=10,
        permission_mode="bypassPermissions",
        allowed_tools=["Read", "Grep", "Glob"],
        cwd=project_dir,
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
            "file": str(file_path),
            "file_name": file_path.name,
            "bug_type": bug_type,
            "status": "timeout",
            "response": final_response,
            "elapsed_seconds": round(elapsed, 2),
            "cost_usd": cost_usd,
            "usage": usage,
        }
    except Exception as e:
        return {
            "file": str(file_path),
            "bug_type": bug_type,
            "status": "error",
            "error": str(e),
        }

    elapsed = time.time() - start_time

    # Use ResultMessage.result as primary; fall back to concatenated assistant texts
    final_response = result_text if result_text else "\n".join(assistant_texts)

    return {
        "file": str(file_path),
        "file_name": file_path.name,
        "bug_type": bug_type,
        "status": "success",
        "response": final_response,
        "elapsed_seconds": round(elapsed, 2),
        "cost_usd": cost_usd,
        "usage": usage,
    }


async def run_evaluation(
    bug_types: List[str] = None,
    output_dir: str = None,
    model: str = None,
    skip_synthesis: bool = False,
    prompt_dir: str = None,
    timeout_seconds: int = 300,
):
    """Run full pipeline: synthesize prompts then evaluate benchmark files."""
    if bug_types is None:
        bug_types = list(BUG_TYPE_FILES.keys())
    if output_dir is None:
        output_dir = str(BASE_PATH / "result" / "claude_code")

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

    # --- Phase 1: Synthesize or load detection prompts ---
    detection_prompts: Dict[str, str] = {}

    for bug_type in bug_types:
        if bug_type not in BUG_TYPE_FILES:
            continue

        loaded = False

        # Try loading from prompt_dir if specified
        if prompt_dir:
            prompt_file = os.path.join(prompt_dir, f"{bug_type}_prompt.json")
            if os.path.exists(prompt_file):
                with open(prompt_file, "r") as f:
                    synthesized = json.load(f)
                detection_prompts[bug_type] = build_detection_system_prompt(synthesized, bug_type)
                print(f"[{bug_type}] Loaded detection prompt from {prompt_file}")
                loaded = True

        if not loaded and not skip_synthesis:
            if bug_type in BUG_TYPE_EXAMPLES:
                print(f"\n[{bug_type}] Synthesizing detection prompt from {len(BUG_TYPE_EXAMPLES[bug_type])} example URLs...")
                synthesized = await synthesize_detection_prompt(
                    bug_type, BUG_TYPE_EXAMPLES[bug_type], model=model
                )
                if synthesized:
                    detection_prompts[bug_type] = build_detection_system_prompt(synthesized, bug_type)
                    # Save synthesized prompt for reuse
                    save_path = os.path.join(output_dir, f"{bug_type}_prompt.json")
                    with open(save_path, "w") as f:
                        json.dump(synthesized, f, indent=2, ensure_ascii=False)
                    print(f"  Saved synthesized prompt to {save_path}")

        # Fallback to generic prompt
        if bug_type not in detection_prompts:
            print(f"[{bug_type}] Using fallback detection prompt")
            detection_prompts[bug_type] = FALLBACK_SYSTEM_PROMPTS[bug_type]

    # --- Phase 2: Evaluate benchmark files ---
    all_results = {}
    total_files = sum(len(BUG_TYPE_FILES[bt]) for bt in bug_types if bt in BUG_TYPE_FILES)
    processed = 0

    for bug_type in bug_types:
        if bug_type not in BUG_TYPE_FILES:
            print(f"[WARN] Unknown bug type: {bug_type}, skipping.")
            continue

        files = BUG_TYPE_FILES[bug_type]
        system_prompt = detection_prompts[bug_type]
        results = []
        print(f"\n{'='*60}")
        print(f"Evaluating bug type: {bug_type} ({len(files)} files)")
        print(f"{'='*60}")

        for rel_path in files:
            file_path = resolve_file_path(rel_path)
            processed += 1
            print(f"\n[{processed}/{total_files}] Reviewing: {file_path.name}")

            result = await review_file(
                file_path, bug_type, system_prompt, model=model,
                timeout_seconds=timeout_seconds,
            )
            results.append(result)

            if result["status"] == "success":
                print(f"  Done in {result['elapsed_seconds']}s, cost=${result.get('cost_usd', 0):.4f}")
            elif result["status"] == "timeout":
                print(f"  TIMEOUT after {result['elapsed_seconds']}s (partial response saved)")
            else:
                print(f"  ERROR: {result.get('error', 'unknown')}")

        all_results[bug_type] = results

        # Save per-bug-type results
        out_file = os.path.join(output_dir, f"{bug_type}_results.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nSaved {bug_type} results to {out_file}")

    # Save combined results
    combined_file = os.path.join(output_dir, f"all_results_{timestamp}.json")
    with open(combined_file, "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\nSaved combined results to {combined_file}")

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
    parser = argparse.ArgumentParser(description="Evaluate Claude Code on bug detection benchmark")
    parser.add_argument(
        "--bug-types",
        nargs="+",
        choices=list(BUG_TYPE_FILES.keys()),
        default=None,
        help="Bug types to evaluate (default: all)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for results",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Model to use (e.g. claude-sonnet-4-20250514)",
    )
    parser.add_argument(
        "--skip-synthesis",
        action="store_true",
        help="Skip prompt synthesis, use fallback prompts directly",
    )
    parser.add_argument(
        "--prompt-dir",
        type=str,
        default=None,
        help="Directory with pre-synthesized prompt JSON files (e.g. BOF_prompt.json)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Per-file timeout in seconds (default: 300)",
    )
    args = parser.parse_args()

    asyncio.run(run_evaluation(
        bug_types=args.bug_types,
        output_dir=args.output_dir,
        model=args.model,
        skip_synthesis=args.skip_synthesis,
        prompt_dir=args.prompt_dir,
        timeout_seconds=args.timeout,
    ))


if __name__ == "__main__":
    main()
