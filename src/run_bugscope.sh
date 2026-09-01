#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

print_usage() {
    echo "Usage:"
    echo "  bash $0 bugscan --project-path <path> --bug-type <type> [options]"
    echo
    echo "Required options:"
    echo "  --project-path <path>        C/C++ project directory"
    echo "  --bug-type <type>            OSO, NOF, ASO, MLK, or DBZ"
    echo
    echo "Optional options:"
    echo "  --language <language>        Programming language (default: Cpp)"
    echo "  --model-name <model>         LLM model name (default: gpt-4o-mini)"
    echo "  --temperature <value>        Inference temperature (default: 0.0)"
    echo "  --call-depth <number>        Inter-procedural call depth (default: 2)"
    echo "  --max-symbolic-workers <n>   Parsing workers (default: 10)"
    echo "  --max-neural-workers <n>     LLM workers (default: 1)"
    echo "  -h, --help                   Show this help message"
    echo
    echo "Example:"
    echo "  bash $0 bugscan \\"
    echo "    --project-path benchmark/Cpp/toy/MLK \\"
    echo "    --bug-type MLK \\"
    echo "    --model-name gpt-4o-mini"
}

require_option_value() {
    local option="$1"
    local value="${2:-}"
    if [[ -z "$value" || "$value" == --* ]]; then
        echo "Error: $option requires a value." >&2
        exit 1
    fi
}

if [[ $# -eq 0 ]]; then
    print_usage
    exit 1
fi

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    print_usage
    exit 0
fi

SCAN_TYPE="$1"
shift

LANGUAGE="Cpp"
PROJECT_PATH=""
BUG_TYPE=""
MODEL_NAME="gpt-4o-mini"
TEMPERATURE="0.0"
CALL_DEPTH="2"
MAX_SYMBOLIC_WORKERS="10"
MAX_NEURAL_WORKERS="1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --language)
            require_option_value "$1" "${2:-}"
            LANGUAGE="$2"
            shift 2
            ;;
        --project-path)
            require_option_value "$1" "${2:-}"
            PROJECT_PATH="$2"
            shift 2
            ;;
        --bug-type)
            require_option_value "$1" "${2:-}"
            BUG_TYPE="$2"
            shift 2
            ;;
        --model-name)
            require_option_value "$1" "${2:-}"
            MODEL_NAME="$2"
            shift 2
            ;;
        --temperature)
            require_option_value "$1" "${2:-}"
            TEMPERATURE="$2"
            shift 2
            ;;
        --call-depth)
            require_option_value "$1" "${2:-}"
            CALL_DEPTH="$2"
            shift 2
            ;;
        --max-symbolic-workers)
            require_option_value "$1" "${2:-}"
            MAX_SYMBOLIC_WORKERS="$2"
            shift 2
            ;;
        --max-neural-workers)
            require_option_value "$1" "${2:-}"
            MAX_NEURAL_WORKERS="$2"
            shift 2
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

if [[ "$SCAN_TYPE" != "bugscan" ]]; then
    echo "Error: the release version only supports the bugscan scan type." >&2
    exit 1
fi

if [[ "$LANGUAGE" != "Cpp" ]]; then
    echo "Error: the release version only supports C/C++ (--language Cpp)." >&2
    exit 1
fi

if [[ -z "$PROJECT_PATH" ]]; then
    echo "Error: --project-path is required." >&2
    exit 1
fi

if [[ ! -d "$PROJECT_PATH" ]]; then
    echo "Error: project directory does not exist: $PROJECT_PATH" >&2
    exit 1
fi

case "$BUG_TYPE" in
    OSO|NOF|ASO|MLK|DBZ)
        ;;
    *)
        echo "Error: --bug-type must be one of OSO, NOF, ASO, MLK, or DBZ." >&2
        exit 1
        ;;
esac

python3 "$SCRIPT_DIR/bugscope.py" \
    --scan-type "$SCAN_TYPE" \
    --language "$LANGUAGE" \
    --project-path "$PROJECT_PATH" \
    --bug-type "$BUG_TYPE" \
    --model-name "$MODEL_NAME" \
    --temperature "$TEMPERATURE" \
    --call-depth "$CALL_DEPTH" \
    --max-symbolic-workers "$MAX_SYMBOLIC_WORKERS" \
    --max-neural-workers "$MAX_NEURAL_WORKERS"
