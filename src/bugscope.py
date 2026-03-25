import argparse
import glob
import sys
from agent.bugscan import *
from agent.slicescan import *

from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *

from typing import List


default_bugscan_checkers = {
    "Cpp": ["BOF", "BUF", "AOF", "MLK", "NPD", "UAF", "DBZ", "i2c_msg", "fb_var_screeninfo", "i2c_smbus_data"],
}

class BugScope:
    def __init__(
        self,
        args: argparse.Namespace,
    ):
        """
        Initialize BatchScan object with project details.
        """
        # argument format check
        self.args = args
        is_input_valid, error_messages = self.validate_inputs()
    
        if not is_input_valid:
            print("\n".join(error_messages))
            exit(1)
        
        self.project_path = args.project_path
        self.language = args.language
        self.code_in_files = {}

        self.model_name = args.model_name
        self.temperature = args.temperature
        self.call_depth = args.call_depth
        self.max_symbolic_workers = args.max_symbolic_workers
        self.max_neural_workers = args.max_neural_workers

        self.bug_type = args.bug_type
        self.is_backward = args.is_backward
        self.is_iterative = args.is_iterative

        suffixs = []
        if self.language == "Cpp":
            suffixs = ["cpp", "cc", "hpp", "c", "h"]
        else:
            raise ValueError("Invalid language setting")
        
        # Load all files with the specified suffix in the project path
        self.traverse_files(self.project_path, suffixs)

        if self.language == "Cpp":
            self.ts_analyzer = Cpp_TSAnalyzer(self.code_in_files, self.language, self.max_symbolic_workers)
        return

    def start_repo_auditing(self) -> None:
        """
        Start the batch scan process.
        """
        if self.args.scan_type == "bugscan":
            while True:
                bugscan_agent = BugScanAgent(
                    self.bug_type,
                    self.project_path,
                    self.language,
                    self.ts_analyzer,
                    self.model_name,
                    self.temperature,
                    self.call_depth,
                    self.max_neural_workers
                )
                bugscan_agent.start_scan()
                if not self.is_iterative:
                    break

        if self.args.scan_type == "slicescan":
            slicescan_agent = SliceScanAgent(
                [],
                self.is_backward,
                self.project_path,
                self.language,
                self.ts_analyzer,
                self.model_name,
                self.temperature,
                self.call_depth,
                self.max_neural_workers
            )
            slicescan_agent.start_scan()
            print(slicescan_agent.get_agent_result())
        return
    

    def traverse_files(self, project_path: str, suffixs: List) -> None:
        """
        Traverse all files in the project path.
        """        
        for root, dirs, files in os.walk(project_path):
            excluded_dirs = {
                # Common
                '.git', '.vscode', '.idea', 'build', 'dist', 'out', 'bin',
                # Python
                '__pycache__', '.pytest_cache', '.mypy_cache', '.coverage', 'venv', 'env',
                # Java
                'target', '.gradle', '.m2', '.settings', 'classes',
                # C++
                'CMakeFiles', '.deps', 'Debug', 'Release', 'obj',
                # Go
                'vendor', 'pkg'
            }
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in excluded_dirs]
            
            
            for file in files:
                if any(file.endswith(f'.{suffix}') for suffix in suffixs):
                    file_path = os.path.join(root, file)    
                    # if not self.include_test_files:
                    if "test" in file_path.lower() or "example" in file_path.lower():
                        continue
                    
                    try:
                        with open(file_path, "r", encoding='utf-8', errors='ignore') as source_file:
                            source_file_content = source_file.read()
                            self.code_in_files[file_path] = source_file_content
                    except Exception as e:
                        print(f"Error reading file {file_path}: {e}")
        return

    def validate_inputs(self) -> Tuple[bool, List[str]]:
        err_messages = []

        # For each scan type, check required parameters.
        if self.args.scan_type == "bugscan":
            if not self.args.model_name:
                err_messages.append("Error: --model-name is required for bugscan.")
            if not self.args.bug_type:
                err_messages.append("Error: --bug-type is required for bugscan.")
        elif self.args.scan_type == "slicescan":
            if not self.args.is_backward:
                err_messages.append("Error: --is-backward is required for slicescan.")
            if not self.args.model_name:
                err_messages.append("Error: --inference-model-name is required for slicescan.")
        else:
            err_messages.append("Error: Unknown scan type provided.")
        return (len(err_messages) == 0, err_messages)
    
def configure_args():
    parser = argparse.ArgumentParser(
        description="BugScope: Run bugscan or slicescan"
    )
    parser.add_argument(
        "--scan-type",
        required=True,
        choices=["slicescan", "bugscan"],
        help="The type of scan to perform."
    )
    # Common parameters
    parser.add_argument("--project-path", required=True, help="Project path")
    parser.add_argument("--language", required=True, help="Programming language")
    parser.add_argument("--max-symbolic-workers", type=int, default=10, help="Max symbolic workers for parsing-based analysis")

    # Common parameters for slicescan and bugscan
    parser.add_argument("--model-name", help="The name of LLMs")
    parser.add_argument("--temperature", type=float, default=0.5, help="Temperature for inference")
    parser.add_argument("--call-depth", type=int, default=3, help="Call depth setting")
    parser.add_argument("--max-neural-workers", type=int, default=1, help="Max neural workers for prompting-based analysis")

    # Parameters for slicescan
    parser.add_argument("--is-backward", action="store_true", help="Flag for backward slicing")

    # Parameters for bugscan
    parser.add_argument("--bug-type", help="Bug type (for bugscan)")
    parser.add_argument("--is-iterative", action="store_true", help="Flag for iterative analysis with multiple rounds")

    args = parser.parse_args()
    return args


def main() -> None:
    args = configure_args()
    bugscope = BugScope(args)
    bugscope.start_repo_auditing()
    return


if __name__ == "__main__":
    main()
