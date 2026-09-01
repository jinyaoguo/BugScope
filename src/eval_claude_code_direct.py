"""
Evaluation script using Claude Code SDK to review C/C++ files for potential bugs.

Directly provides example bug report URLs as context during audit (no separate
guideline synthesis phase). Claude Code fetches the examples and uses them as
reference while reviewing each benchmark file.

Usage:
    # Run evaluation for all bug types
    unset CLAUDECODE && python eval_claude_code_direct.py --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Evaluate only specific bug types
    unset CLAUDECODE && python eval_claude_code_direct.py --bug-types OSO DBZ --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

    # Custom output directory
    unset CLAUDECODE && python eval_claude_code_direct.py --output-dir /path/to/results --model us.anthropic.claude-3-7-sonnet-20250219-v1:0

Note:
    - Must `unset CLAUDECODE` if running from within a Claude Code session to avoid nested session errors.
    - Must `conda activate py311` before running.
    - Model ID uses Bedrock format (e.g. us.anthropic.claude-3-7-sonnet-20250219-v1:0).
    - Results (JSON) are saved to --output-dir (default: result/claude_code_direct/).
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

# ---------------------------------------------------------------------------
# Benchmark files to evaluate
# ---------------------------------------------------------------------------
OSO_files = {
    "../benchmark/Reproduce/Cpp/OOB/redis/src/t_zset.c",
    "../benchmark/Reproduce/Cpp/OOB/qemu/contrib/elf2dmp/qemu_elf.c",
    "../benchmark/Reproduce/Cpp/OOB/systemd/src/basic/time-util.c",
}

NOF_files = {
    "../benchmark/Reproduce/Cpp/OOB/curl/lib/sendf.c",
    "../benchmark/Reproduce/Cpp/OOB/opcache/zend_accelerator_blacklist.c",
    "../benchmark/Reproduce/Cpp/OOB/openssl/crypto/bf/bf_ofb64.c",
}

ASO_files = {
    "../benchmark/Reproduce/Cpp/OOB/sapi/cli/php_cli_server.c",
    "../benchmark/Reproduce/Cpp/OOB/bfdd/control.c",
    "../benchmark/Reproduce/Cpp/OOB/libcpp/files.cc",
    "../benchmark/Reproduce/Cpp/OOB/ld/libdep_plugin.c",
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
    "../benchmark/Reproduce/Cpp/MLK/h3/src/apps/filters/h3.c",
    "../benchmark/Reproduce/Cpp/MLK/TrinityEmulator/contrib/elf2dmp/main.c",
    "../benchmark/Reproduce/Cpp/MLK/binutils/bucomm.c",
}

BUG_TYPE_FILES: Dict[str, set] = {
    "OSO": OSO_files,
    "NOF": NOF_files,
    "ASO": ASO_files,
    "DBZ": DBZ_files,
    "MLK": MLK_files,
}

# ---------------------------------------------------------------------------
# Example bug report URLs — provided directly to Claude Code during audit
# ---------------------------------------------------------------------------
OSO_examples = [
    "https://github.com/FRRouting/frr/issues/11624",
    "https://github.com/facebook/zstd/issues/3200",
    "https://github.com/systemd/systemd/issues/23258",
]

NOF_examples: List[str] = []
ASO_examples: List[str] = []

DBZ_examples = [
    "https://lore.kernel.org/linux-block/21cb65d1-b91a-2627-3824-292de3a7553a@suse.de/T/#t",
    "https://lore.kernel.org/linux-parisc/alpine.DEB.2.22.394.2105121353530.1204552@ramsan.of.borg/T/#t",
]

MLK_examples = [
    "https://github.com/memcached/memcached/pull/1216",
    "https://github.com/libuv/libuv/pull/4720",
]

BUG_TYPE_EXAMPLES: Dict[str, List[str]] = {
    "OSO": OSO_examples,
    "NOF": NOF_examples,
    "ASO": ASO_examples,
    "DBZ": DBZ_examples,
    "MLK": MLK_examples,
}

BUG_TYPE_FULL_NAME: Dict[str, str] = {
    "OSO": "Buffer Overflow (an out-of-bounds read or write beyond the upper bound of a buffer)",
    "NOF": "Buffer Underflow (a buffer access using a negative offset)",
    "ASO": "Allocation Size Overflow (allocation-size arithmetic wraps and produces an undersized buffer)",
    "DBZ": "Divide By Zero (integer division or modulo where the divisor could be zero without a proper guard)",
    "MLK": "Memory Leak (dynamically allocated memory via malloc/calloc/realloc/new not freed on all execution paths)",
}

# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def resolve_file_path(relative_path: str) -> Path:
    """Resolve a relative benchmark file path to absolute."""
    return (BASE_PATH / "src" / relative_path).resolve()


def build_system_prompt(bug_type: str) -> str:
    """Build system prompt that defines the auditor role."""
    bug_desc = BUG_TYPE_FULL_NAME[bug_type]
    return f"""You are a senior C/C++ security auditor specializing in {bug_desc} detection.

Your task is to review source code files and detect potential {bug_type} bugs.

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


def build_audit_prompt(file_path: Path, bug_type: str, example_urls: List[str]) -> str:
    """Build the audit prompt that includes example URLs directly."""
    bug_desc = BUG_TYPE_FULL_NAME[bug_type]
    urls_str = "\n".join(f"  - {url}" for url in example_urls)

    return f"""Please review the C/C++ source code file at: {file_path}

Your goal is to detect potential {bug_type} ({bug_desc}) bugs in this file.

Steps:
1. First, fetch and analyze the following real-world bug report examples to understand what {bug_type} bugs look like in practice:
{urls_str}
   For each example, identify the root cause, the buggy code pattern, and the fix applied.

2. Read the target file using the Read tool.

3. Identify functions, macros, types, and external calls that are relevant to potential {bug_type} bugs.

4. For any unclear definitions (macros, struct fields, helper functions, constants) referenced in the code, use Grep or Glob to search the surrounding project directory for their definitions so you can reason precisely. Limit your search to at most 3 lookups to stay focused.

5. After gathering sufficient context from both the examples and the target file, analyze the code and report any {bug_type} bugs you find. Use the patterns you learned from the real-world examples to guide your analysis.

Only report bugs with clear evidence based on the code and context you retrieved. Do not speculate."""


async def review_file(
    file_path: Path, bug_type: str, system_prompt: str, example_urls: List[str],
    model: str = None, timeout_seconds: int = 300,
) -> dict:
    """Run Claude Code to detect bugs, providing example URLs directly."""
    if not file_path.exists():
        return {
            "file": str(file_path),
            "bug_type": bug_type,
            "status": "error",
            "error": f"File not found: {file_path}",
        }

    # Find project root for cwd
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

    prompt = build_audit_prompt(file_path, bug_type, example_urls)

    options = ClaudeCodeOptions(
        system_prompt=system_prompt,
        max_turns=20,
        permission_mode="bypassPermissions",
        allowed_tools=["Read", "Grep", "Glob", "WebFetch", "Bash"],
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
    timeout_seconds: int = 300,
):
    """Evaluate benchmark files by providing example URLs directly during audit."""
    if bug_types is None:
        bug_types = list(BUG_TYPE_FILES.keys())
    if output_dir is None:
        output_dir = str(BASE_PATH / "result" / "claude_code_direct")

    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

    all_results = {}
    total_files = sum(len(BUG_TYPE_FILES[bt]) for bt in bug_types if bt in BUG_TYPE_FILES)
    processed = 0

    for bug_type in bug_types:
        if bug_type not in BUG_TYPE_FILES:
            print(f"[WARN] Unknown bug type: {bug_type}, skipping.")
            continue

        files = BUG_TYPE_FILES[bug_type]
        system_prompt = build_system_prompt(bug_type)
        example_urls = BUG_TYPE_EXAMPLES.get(bug_type, [])
        results = []

        print(f"\n{'='*60}")
        print(f"Evaluating bug type: {bug_type} ({len(files)} files)")
        print(f"  Examples provided: {len(example_urls)} URLs")
        print(f"{'='*60}")

        for rel_path in files:
            file_path = resolve_file_path(rel_path)
            processed += 1
            print(f"\n[{processed}/{total_files}] Reviewing: {file_path.name}")

            result = await review_file(
                file_path, bug_type, system_prompt, example_urls,
                model=model, timeout_seconds=timeout_seconds,
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
    parser = argparse.ArgumentParser(
        description="Evaluate Claude Code on bug detection benchmark (direct example mode)"
    )
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
        timeout_seconds=args.timeout,
    ))


if __name__ == "__main__":
    main()
