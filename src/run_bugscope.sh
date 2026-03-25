#!/bin/bash

print_usage() {
    echo "Usage: $0 <scan-type> [options]"
    echo
    echo "Scan Types:"
    echo "  bugscan    - Perform general bug scanning"
    echo "  slicescan  - Perform slice-based scanning"
    echo
    echo "Required Options (for all scan types):"
    echo "  --language <lang>           Language to analyze"
    echo "  --project-path <path>       Path to the project"
    echo
    echo "Required Options (scan-type specific):"
    echo "  --bug-type <type>          Required for bugscan"
    echo "  --is-iterative             Required for bugscan"
    echo "  --is-backward              Required for slicescan"
    echo
    echo "Optional Options (with defaults):"
    echo "  --model-name <model>        Model to use (default: gpt-5-mini)"
    echo "  --temperature <temp>        Temperature setting (default: 0.0)"
    echo "  --call-depth <depth>        Call depth (default: 2)"
    echo "  --max-neural-workers <num>  Maximum neural workers (default: 30)"
    echo
    echo "Example commands:"
    echo "bash $0 bugscan --language Cpp --project-path ../benchmark/Cpp/htop --is-iterative"
}

# Check for help flag first
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    print_usage
    exit 0
fi

# Check for minimum arguments
if [[ $# -lt 1 ]]; then
    print_usage
    exit 1
fi

# Default values
SCAN_TYPE=$1
LANGUAGE=Cpp
MODEL=gpt-5-mini
BUG_TYPE=MLK
# PROJECT=lib
REPRODUCE=True
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
MAX_NEURAL_WORKERS=30

echo "Processing project: $PROJECT with checker: $BUG_TYPE"

case "$SCAN_TYPE" in
    bugscan)
        if [ "$REPRODUCE" = "True" ]; then
            if [ -z "$PROJECT" ]; then
                # No specific project provided, find all projects in the directory
                PROJECTS_DIR="../benchmark/Reproduce/${LANGUAGE}/${BUG_TYPE}/"
                for PROJECT_DIR in "$PROJECTS_DIR"/*; do
                    if [ -d "$PROJECT_DIR" ]; then
                        PROJECT_NAME=$(basename "$PROJECT_DIR")
                        echo "Processing project: $PROJECT_NAME"
                        python3 bugscope.py \
                          --language $LANGUAGE \
                          --model-name $MODEL \
                          --project-path "../benchmark/Reproduce/${LANGUAGE}/${BUG_TYPE}/${PROJECT_NAME}" \
                          --bug-type $BUG_TYPE \
                          --temperature 0.0 \
                          --scan-type bugscan \
                          --call-depth 3 \
                          --max-neural-workers "$MAX_NEURAL_WORKERS" > "../log/Reproduce/${BUG_TYPE}/${PROJECT_NAME}_${MODEL}_${TIMESTAMP}.log"
                    fi
                done
            else
                # Specific project provided
                python3 bugscope.py \
                  --language $LANGUAGE \
                  --model-name $MODEL \
                  --project-path "../benchmark/Reproduce/${LANGUAGE}/${BUG_TYPE}/${PROJECT}" \
                  --bug-type $BUG_TYPE \
                  --temperature 0.0 \
                  --scan-type bugscan \
                  --call-depth 3 \
                  --max-neural-workers "$MAX_NEURAL_WORKERS" > "../log/Reproduce/${BUG_TYPE}/${PROJECT}_${MODEL}_${TIMESTAMP}.log"
            fi
        else
            if [ ! -d "../log/runtime/${PROJECT}" ]; then
                mkdir -p "../log/runtime/${PROJECT}"
            fi
            python3 bugscope.py \
              --language $LANGUAGE \
              --model-name $MODEL \
              --project-path ../benchmark/${LANGUAGE}/${PROJECT} \
              --bug-type $BUG_TYPE \
              --temperature 0.0 \
              --scan-type bugscan \
              --call-depth 2 \
              --max-neural-workers "$MAX_NEURAL_WORKERS" > "../log/runtime/${PROJECT}/${BUG_TYPE}_${MODEL}_${TIMESTAMP}.log"
        fi
        ;;
esac
