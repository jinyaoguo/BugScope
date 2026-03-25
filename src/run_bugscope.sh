#!/bin/bash

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
PROJECT=htop
REPRODUCE=False
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
MAX_NEURAL_WORKERS=10

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
