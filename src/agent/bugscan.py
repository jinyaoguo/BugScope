import json
import os
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm 
import random

from agent.agent import *
from agent.slicescan import *

from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *

from tstool.bugscan_extractor.bugscan_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_BOF_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_BUF_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_AOF_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_DBZ_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_MLK_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_NPD_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_UAF_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_i2c_msg_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_fb_var_screeninfo_extractor import *
from tstool.bugscan_extractor.Cpp.Cpp_i2c_smbus_data_extractor import *

from llmtool.LLM_utils import *
from llmtool.bugscan.slice_inliner import *
from llmtool.bugscan.slice_bug_detector import *
from llmtool.bugscan.slice_bug_validator import *
from llmtool.utility.audit_request_formulator import *

from memory.semantic.bugscan_state import *
from memory.syntactic.function import *
from memory.syntactic.value import *

from ui.logger import *

BASE_PATH = Path(__file__).resolve().parents[2]

BOF_file = {
    "../benchmark/Reproduce/Cpp/BUF/curl/lib/sendf.c",
    "../benchmark/Reproduce/Cpp/BUF/zstd/programs/util.c",
    "../benchmark/Reproduce/Cpp/BOF/zstd/programs/util.c",
    "../benchmark/Reproduce/Cpp/AOF/sapi/cli/php_cli_server.c",
    "../benchmark/Reproduce/Cpp/BUF/opcache/zend_accelerator_blacklist.c",
    "../benchmark/Reproduce/Cpp/AOF/systemd/src/libsystemd-network/ndisc-router.c",
    "../benchmark/Reproduce/Cpp/BOF/zebra/kernel_netlink.c",
    "../benchmark/Reproduce/Cpp/AOF/bfdd/control.c",
    "../benchmark/Reproduce/Cpp/BOF/redis/src/t_zset.c",
    "../benchmark/Reproduce/Cpp/AOF/libcpp/files.cc",
    "../benchmark/Reproduce/Cpp/AOF/ld/libdep_plugin.c",
    "../benchmark/Reproduce/Cpp/BUF/openssl/crypto/bf/bf_ofb64.c",
    "../benchmark/Reproduce/Cpp/BOF/qemu/contrib/elf2dmp/qemu_elf.c",
    "../benchmark/Reproduce/Cpp/BOF/systemd/src/basic/time-util.c"
}

DBZ_file = {
    "../benchmark/Reproduce/Cpp/DBZ/libuv/src/unix/linux-core.c",
    "../benchmark/Reproduce/Cpp/DBZ/goaccess/src/gholder.c",
    "../benchmark/Reproduce/Cpp/DBZ/MagickCore/cache.c",
    "../benchmark/Reproduce/Cpp/DBZ/systemd/src/shared/creds-util.c",
    "../benchmark/Reproduce/Cpp/DBZ/vim/src/misc2.c",
    "../benchmark/Reproduce/Cpp/DBZ/openssl/crypto/pkcs12/p12_key.c",
    "../benchmark/Reproduce/Cpp/DBZ/gdb/amd64-tdep.c",
    "../benchmark/Reproduce/Cpp/DBZ/lib/math/rational.c",
    "../benchmark/Reproduce/Cpp/DBZ/block/blk-mq-cpumap.c",
    "../benchmark/Reproduce/Cpp/DBZ/agp/isoch.c",
    "../benchmark/Reproduce/Cpp/DBZ/video/logo/pnmtologo.c",
    "../benchmark/Reproduce/Cpp/DBZ/git/builtin/pack-objects.c"
}

MLK_file = {
    "../benchmark/Reproduce/Cpp/MLK/memcached/memcached.c",
    "../benchmark/Reproduce/Cpp/MLK/libsass/src/permutate.hpp",
    "../benchmark/Reproduce/Cpp/MLK/memcached-2/restart.c",
    "../benchmark/Reproduce/Cpp/MLK/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c",
    "../benchmark/Reproduce/Cpp/MLK/mm/damon/reclaim.c",
    "../benchmark/Reproduce/Cpp/MLK/rtl_433/src/sdr.c",
    "../benchmark/Reproduce/Cpp/MLK/libuv/docs/code/plugin/main.c",
    "../benchmark/Reproduce/Cpp/MLK/TrinityEmulator-2/hw/express-gpu/egl_display_wgl.c",
    "../benchmark/Reproduce/Cpp/MLK/TrinityEmulator/contrib/elf2dmp/main.c",
    "../benchmark/Reproduce/Cpp/MLK/binutils/bucomm.c"
}


class BugScanAgent(Agent):
    def __init__(self,
                bug_type: str,
                project_path,
                language,
                ts_analyzer: TSAnalyzer,
                model_name,
                temperature,
                call_depth,
                max_neural_workers = 1,
                agent_id: int = 0,
                ) -> None:
        self.bug_type = bug_type
        self.project_path = project_path
        self.project_name = project_path.split("/")[-1]
        self.language = language if language not in {"C", "Cpp"} else "Cpp"
        self.ts_analyzer = ts_analyzer

        self.model_name = model_name
        self.temperature = temperature
        
        self.call_depth = call_depth
        self.max_neural_workers = max_neural_workers
        self.MAX_QUERY_NUM = 5
        self.start_time = 0.0
        
        self.lock = threading.Lock()
        self.time_str = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())

        with self.lock:
            self.log_dir_path = f"{BASE_PATH}/log/bugscan-{self.model_name}/{self.language}--{self.project_name}/{self.time_str}-{agent_id}"
            if not os.path.exists(self.log_dir_path):
                os.makedirs(self.log_dir_path)
            self.logger = Logger(self.log_dir_path + "/" + "bugscan.log")

            self.result_dir_path = f"{BASE_PATH}/result/bugscan-{self.model_name}/{self.bug_type}/{self.language}--{self.project_name}/{self.time_str}-{agent_id}"
            if not os.path.exists(self.result_dir_path):
                os.makedirs(self.result_dir_path)

        # LLM tools used by BugScanAgent
        self.audit_request_formulator = AuditRequestFormulator("claude-3.5", self.temperature, self.language, self.MAX_QUERY_NUM, self.logger)
        self.slice_inliner = SliceInliner(self.model_name, self.temperature, self.language, self.MAX_QUERY_NUM, self.logger)
        self.intra_detector = SliceBugDetector(self.bug_type, self.model_name, self.temperature, self.language, self.MAX_QUERY_NUM, self.logger)
        self.validator = SliceBugValidator(self.bug_type, self.model_name, self.temperature, self.language, self.MAX_QUERY_NUM, self.logger)

        # LLM Agent instances created by BugScanAgent
        self.slice_scan_agents: List[SliceScanAgent] = []

        # Initialize the seeds
        self.seeds: List[Tuple[Value, bool]] = self.__obtain_extractor().extract_all()

        # Initialize the state
        self.state = BugScanState(self.seeds)
        return
    
    def __obtain_extractor(self) -> BugScanExtractor:
        if self.language == "Cpp":
            if self.bug_type == "BOF":
                return Cpp_BOF_Extractor(self.ts_analyzer)
            if self.bug_type == "BUF":
                return Cpp_BUF_Extractor(self.ts_analyzer)
            if self.bug_type == "AOF":
                return Cpp_AOF_Extractor(self.ts_analyzer)
            elif self.bug_type == "DBZ":
                return Cpp_DBZ_Extractor(self.ts_analyzer)
            elif self.bug_type == "MLK":
                return Cpp_MLK_Extractor(self.ts_analyzer)
            elif self.bug_type == "NPD":
                return Cpp_NPD_Extractor(self.ts_analyzer)
            elif self.bug_type == "UAF":
                return Cpp_UAF_Extractor(self.ts_analyzer)
            elif self.bug_type == "i2c_msg":
                return Cpp_i2c_msg_Extractor(self.ts_analyzer)
            elif self.bug_type == "fb_var_screeninfo":
                return Cpp_fb_var_screeninfo_Extractor(self.ts_analyzer)
            elif self.bug_type == "i2c_smbus_data":
                return Cpp_i2c_smbus_data_Extractor(self.ts_analyzer)
        return None


    def __retrieve_slice_inliner_inputs(self, slicescan_state: SliceScanState) -> List[SliceInlinerInput]:
        inputs = []

        self.logger.print_console("start to retrieve slice inliner inputs")

        root_function_ids = []
        for relevant_function_id in slicescan_state.relevant_functions:
            relevant_function = slicescan_state.relevant_functions[relevant_function_id]
            is_root_function = True
            if relevant_function.function_id in self.ts_analyzer.function_callee_caller_map:
                for caller_function_id in self.ts_analyzer.function_callee_caller_map[relevant_function.function_id]:
                    if caller_function_id in slicescan_state.relevant_functions:
                        is_root_function = False
                        break
            if is_root_function:
                root_function_ids.append(relevant_function_id)

        for root_function_id in root_function_ids:
            callees = self.ts_analyzer.get_all_transitive_callee_functions(self.ts_analyzer.function_env[root_function_id], 2 * self.call_depth + 2)
            
            relevant_functions = {
                callee.function_id: callee
                for callee in callees
                if callee.function_id in slicescan_state.relevant_functions
            }
            relevant_functions[root_function_id] = self.ts_analyzer.function_env[root_function_id]
            
            slice_items = []
            for (_, function_id, values, slice) in slicescan_state.intra_slices:
                slice_items.append((function_id, values, slice))

            function_caller_callee_map = {}
            for function_caller_id in self.ts_analyzer.function_caller_callee_map:
                if function_caller_id not in relevant_functions:
                    continue
                for function_callee_id in self.ts_analyzer.function_caller_callee_map[function_caller_id]:
                    if function_callee_id not in relevant_functions:
                        continue
                    if function_caller_id not in function_caller_callee_map:
                        function_caller_callee_map[function_caller_id] = set()
                    function_caller_callee_map[function_caller_id].add(function_callee_id)

            input = SliceInlinerInput(root_function_id, relevant_functions, slice_items, slicescan_state.global_slices, function_caller_callee_map)
            inputs.append(input)
        return inputs

    # TOBE deprecated
    def start_scan_sequential(self) -> None:
        self.logger.print_console("Start bug scanning...")

        self.seeds_in_scope = []
        for seed_value, is_backward in self.seeds:
            if seed_value.file in self.target_files:
                self.seeds_in_scope.append((seed_value, is_backward))

        self.state.update_seed_values_in_scope(self.seeds_in_scope)

        # Process each seed sequentially with a progress bar
        with tqdm(total=len(self.seeds_in_scope), desc="Processing Seeds", unit="seed") as pbar:
            for (seed_value, is_backward) in self.seeds_in_scope:
                seed_function = self.ts_analyzer.get_function_from_localvalue(seed_value)
                if seed_function is None:
                    pbar.update(1)
                    continue

                # (Key Step I): Start a slicescan agent for each seed
                slice_scan_agent = SliceScanAgent(
                    [seed_value], is_backward, self.project_path,
                    self.language, self.ts_analyzer,
                    self.model_name, self.temperature, self.call_depth, self.max_neural_workers
                )
                self.slice_scan_agents.append(slice_scan_agent)

                slice_scan_agent.start_scan()
                slice_scan_state = slice_scan_agent.get_agent_state()

                # Obtain all the inliner instances
                slice_inliner_inputs: List[SliceInlinerInput] = self.__retrieve_slice_inliner_inputs(slice_scan_state)

                # Inline each instance to obtain the abstraction of buggy code snippets
                for slice_inliner_input in slice_inliner_inputs:
                    # (Key Step II): Inline the slices
                    slice_inliner_output: SliceInlinerOutput = self.slice_inliner.invoke(slice_inliner_input)

                    if slice_inliner_output is None:
                        self.logger.print_log("Slice inliner output is None")
                        continue

                    # (Key Step III): Detect the bugs upon the inlined slices
                    intra_detector_input = SliceBugDetectorInput(seed_value.name, slice_inliner_output.inlined_snippet)
                    intra_detector_output: SliceBugDetectorOutput = self.intra_detector.invoke(intra_detector_input)

                    if intra_detector_output is None:
                        self.logger.print_log("Intra detector output is None")
                        continue

                    if not intra_detector_output.is_buggy:
                        continue
                    
                    # (Key Step IV): Validate the bug report.
                    validator_input = SliceBugValidatorInput(
                        slice_inliner_input.root_function_id, 
                        slice_inliner_input.relevant_functions, 
                        slice_inliner_input.global_variables,
                        slice_inliner_input.function_caller_to_callee_map,
                        intra_detector_output.explanation_str,
                    )
                    validator_output: SliceBugValidatorOutput = self.validator.invoke(validator_input)
                    if validator_output is None:
                        self.logger.print_log("Validator output is None")
                        continue

                    if validator_output.is_buggy:
                        # Construct the bug report and update the state
                        explanation = (
                            "Call tree: \n" + slice_inliner_input.tree_str + "\n"
                            + validator_output.explanation_str
                        )
                        bug_report = BugReport(self.bug_type, seed_value, slice_inliner_input.relevant_functions, explanation)
                        self.state.update_bug_report(bug_report)

                # Dump bug reports
                bug_report_dict = {bug_report_id: bug.to_dict() for bug_report_id, bug in self.state.bug_reports.items()}
                with open(self.result_dir_path + "/detect_info.json", 'w') as bug_info_file:
                    json.dump(bug_report_dict, bug_info_file, indent=4)

                # Update the progress bar
                pbar.update(1)

        # Final summary
        total_bug_number = len(self.state.bug_reports)
        self.logger.print_console(f"{total_bug_number} bug(s) was/were detected in total.")
        self.logger.print_console(f"The bug report(s) has/have been dumped to {self.result_dir_path}/detect_info.json")
        self.logger.print_console("The log files are as follows:")
        for log_file in self.get_log_files():
            self.logger.print_console(log_file)
        return
    
    def start_scan(self) -> None:
        self.start_time = time.time()
        self.logger.print_console("Start bug scanning...")

        # # Dump seed
        # for seed_value, is_backward in self.seeds:
        #     print(str(seed_value))
        # return
    
        # Process each seed in parallel with a progress bar
        self.seeds_in_scope = []
        # for seed_value, is_backward in self.seeds:
        #     if seed_value.file in self.target_files:
        #         self.seeds_in_scope.append((seed_value, is_backward))

        # # 1. Reproduce the bug
        # for seed_value, is_backward in self.seeds:
        #     if str(seed_value) in BOF_reproduce:
        #         self.seeds_in_scope.append((seed_value, is_backward))

        # 2. Reproduce the bug from a file
        if self.bug_type == "DBZ":
            for seed_value, is_backward in self.seeds:
                if seed_value.file in DBZ_file:
                    self.seeds_in_scope.append((seed_value, is_backward))

        elif self.bug_type == "MLK":
            for seed_value, is_backward in self.seeds:
                if seed_value.file in MLK_file:
                    self.seeds_in_scope.append((seed_value, is_backward))
        
        else:
            for seed_value, is_backward in self.seeds:
                if seed_value.file in BOF_file:
                    self.seeds_in_scope.append((seed_value, is_backward))

        # # 3. Scan new bug, if seed number > 100, simple 100 seeds
        # if len(self.seeds) > 100:
        #     sampled_seeds = random.sample(self.seeds, 100)
        #     for seed_value, is_backward in sampled_seeds:
        #         self.seeds_in_scope.append((seed_value, is_backward))
        #     self.logger.print_console(f"Sampled 100 seeds from {len(self.seeds)} total seeds")
        # else:
        #     for seed_value, is_backward in self.seeds:
        #         self.seeds_in_scope.append((seed_value, is_backward))
        #     self.logger.print_console(f"Using all {len(self.seeds)} seeds")

        # # 4. use all the seeds
        # for seed_value, is_backward in self.seeds:
        #     self.seeds_in_scope.append((seed_value, is_backward))
        # self.logger.print_console(f"Using all {len(self.seeds)} seeds")

        # ## Dump the seeds to a log file
        # seed_path = f"{BASE_PATH}/log/seeds/{self.language}--{self.project_name}/{self.bug_type}/{time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())}.log"
        # if not os.path.exists(os.path.dirname(seed_path)):
        #     os.makedirs(os.path.dirname(seed_path))
        # with open(seed_path, 'w') as seeds_file:
        #     for seed_value, is_backward in self.seeds_in_scope:
        #         seeds_file.write(f"{seed_value}\n")

        self.state.update_seed_values_in_scope(self.seeds_in_scope)

        with tqdm(total=len(self.seeds_in_scope), desc="Processing Seeds", unit="seed") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_neural_workers) as executor:
                futures = [
                    executor.submit(self.__process_seed, seed_value, is_backward, index)
                    for index, (seed_value, is_backward) in enumerate(self.seeds_in_scope)
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.print_log("Error processing seed:", e)
                    finally:
                        pbar.update(1)  # Update the progress bar after each seed is processed

        # Final summary
        total_bug_number = len(self.state.bug_reports)
        self.logger.print_console(f"{total_bug_number} bug(s) was/were detected in total.")
        self.logger.print_console(f"The bug report(s) has/have been dumped to {self.result_dir_path}/detect_info.json")
        self.logger.print_console("The log files are as follows:")
        for log_file in self.get_log_files():
            self.logger.print_console(log_file)
        
        self.print_cost()
        return

    """
    def start_scan(self) -> None:
        self.start_time = time.time()
        self.logger.print_console("Start bug scanning...")
    
        # Process each file in parallel with a progress bar
        self.files_in_scope = []

        # 2. Reproduce the bug from a file
        if self.bug_type == "DBZ":
            for file in self.ts_analyzer.fileContentDic.keys():
                if file in DBZ_file:
                    self.files_in_scope.append(file)

        elif self.bug_type == "MLK":
            for file in self.ts_analyzer.fileContentDic.keys():
                if file in MLK_file:
                    self.files_in_scope.append(file)

        else:
            for file in self.ts_analyzer.fileContentDic.keys():
                if file in BOF_file:
                    self.files_in_scope.append(file)

        with tqdm(total=len(self.files_in_scope), desc="Processing Files", unit="file") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_neural_workers) as executor:
                futures = [
                    executor.submit(self.__process_file, file_path)
                    for file_path in self.files_in_scope
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.print_log(f"Error processing file: {str(e)}")
                        self.logger.print_log(traceback.format_exc()) 
                    finally:
                        pbar.update(1)  # Update the progress bar after each file is processed
        total_bug_number = len(self.state.bug_reports)
        self.logger.print_console(f"{total_bug_number} bug(s) was/were detected in total.")
        self.logger.print_console(f"The bug report(s) has/have been dumped to {self.result_dir_path}/detect_info.json")
        self.logger.print_console("The log files are as follows:")
        for log_file in self.get_log_files():
            self.logger.print_console(log_file)
        
        self.print_cost()
        return
    """

    def __process_seed(self, seed_value: Value, is_backward: bool, seed_index: int) -> None:
        print(f"Processing seed: {seed_value} (is_backward: {is_backward})")
        seed_function = self.ts_analyzer.get_function_from_localvalue(seed_value)
        if seed_function is None:
            return

        # (Key Step I): Start a slicescan agent for the seed.
        slice_scan_agent = SliceScanAgent(
            [seed_value],
            is_backward,
            self.project_path,
            self.language,
            self.ts_analyzer,
            self.model_name,
            self.temperature,
            self.call_depth,
            self.max_neural_workers,
            seed_index
        )
        self.slice_scan_agents.append(slice_scan_agent)

        slice_scan_agent.start_scan()
        slice_scan_state = slice_scan_agent.get_agent_state()

        # Obtain all the inliner instances.
        slice_inliner_inputs: List[SliceInlinerInput] = self.__retrieve_slice_inliner_inputs(slice_scan_state)

        # Process slice_inliner_inputs in parallel
        with ThreadPoolExecutor(max_workers=self.max_neural_workers) as executor:
            futures = [
                executor.submit(self.__process_slice_inliner_input, slice_inliner_input, seed_value, seed_function)
                for slice_inliner_input in slice_inliner_inputs
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.print_log(f"Error processing slice inliner input: {str(e)}")
                    self.logger.print_log(traceback.format_exc())
        return
    
    # TODO: Do we need to consider the lock here?
    def __process_slice_inliner_input(self, slice_inliner_input: SliceInlinerInput, seed_value: Value, seed_function: Function) -> None:
        # Inline the slices.
        slice_inliner_output: SliceInlinerOutput = self.slice_inliner.invoke(slice_inliner_input)

        if slice_inliner_output is None:
            self.logger.print_log("Slice inliner output is None")
            return

        # Detect bugs upon the inlined slices.
        intra_detector_input = SliceBugDetectorInput(seed_value.name, slice_inliner_output.inlined_snippet, seed_function.function_name)
        intra_detector_output: SliceBugDetectorOutput = self.intra_detector.invoke(intra_detector_input)

        if intra_detector_output is None:
            self.logger.print_log("Intra detector output is None")
            return

        if not intra_detector_output.is_buggy:
            return

        # Validate the bug report.
        validator_input = SliceBugValidatorInput(
            slice_inliner_input.root_function_id, 
            slice_inliner_input.relevant_functions, 
            slice_inliner_input.global_variables,
            slice_inliner_input.function_caller_to_callee_map,
            intra_detector_output.explanation_str,
        )
        validator_output: SliceBugValidatorOutput = self.validator.invoke(validator_input)
        if validator_output is None:
            self.logger.print_log("Validator output is None")
            return

        # Construct the bug report and update the state
        explanation = (
            "Call tree: \n" + slice_inliner_input.tree_str + "\n"
            + slice_inliner_output.inlined_snippet + "\n"
            + intra_detector_output.explanation_str + "\n"
        )
        bug_report = BugReport(self.bug_type, seed_value, slice_inliner_input.relevant_functions, explanation, is_LLM_confirmed_true=validator_output.is_buggy)
        self.state.update_bug_report(bug_report)
        bug_report_dict = {bug_report_id: bug.to_dict() for bug_report_id, bug in self.state.bug_reports.items()}
        with open(self.result_dir_path + "/detect_info.json", 'w') as bug_info_file:
            json.dump(bug_report_dict, bug_info_file, indent=4)
        self.print_cost()

        return

    def __process_file(self, file_name) -> None:
        """
        Ablation Study
        """
        intra_detector_input = SliceBugDetectorInput("", self.ts_analyzer.fileContentDic[file_name], "")
        intra_detector_output: SliceBugDetectorOutput = self.intra_detector.invoke(intra_detector_input)

        if intra_detector_output is None:
            self.logger.print_log("Intra detector output is None")
            return

        if not intra_detector_output.is_buggy:
            return

        relevant_functions = {}
        for id, func in self.ts_analyzer.function_env.items():
            if func.file_path == file_name:
                relevant_functions[id] = func

        # Validate the bug report.
        validator_input = SliceBugValidatorInput(
            root_function_id=-1,
            relevant_functions=relevant_functions,
            global_variables=[],
            function_caller_to_callee_map={},
            bug_report=intra_detector_output.explanation_str
        )
        validator_output: SliceBugValidatorOutput = self.validator.invoke(validator_input)
        if validator_output is None:
            self.logger.print_log("Validator output is None")
            return

        # Construct the bug report and update the state
        explanation = (
            intra_detector_output.explanation_str
        )
        bug_report = BugReport(self.bug_type, None, {}, explanation, is_LLM_confirmed_true=validator_output.is_buggy)
        self.state.update_bug_report(bug_report)
        bug_report_dict = {bug_report_id: bug.to_dict() for bug_report_id, bug in self.state.bug_reports.items()}
        with open(self.result_dir_path + "/detect_info.json", 'w') as bug_info_file:
            json.dump(bug_report_dict, bug_info_file, indent=4)
        self.print_cost()

        return
        
    def get_agent_state(self) -> BugScanState:
        return self.state
    
    def get_log_files(self) -> List[str]:
        log_files = []
        log_files.append(self.log_dir_path + "/" + "bugscan.log")
        for slice_scan_agent in self.slice_scan_agents:
            log_files.append(slice_scan_agent.log_dir_path + "/" + "slicescan.log")
        return log_files
        
    def print_cost(self):
        self.logger.print_console("=" * 100)
        self.logger.print_console(f"Cost: Input_token, Output_token, Query_num")
        slice_input_token = 0
        slice_output_token = 0
        slice_query_num = 0
        for slice_scan_agent in self.slice_scan_agents:
            slice_input_token += slice_scan_agent.intra_slicer.input_token_cost
            slice_output_token += slice_scan_agent.intra_slicer.output_token_cost
            slice_query_num += slice_scan_agent.intra_slicer.total_query_num

        total_input_token_cost = slice_input_token + self.slice_inliner.input_token_cost + self.intra_detector.input_token_cost + self.validator.input_token_cost
        total_output_token_cost = slice_output_token + self.slice_inliner.output_token_cost + self.intra_detector.output_token_cost + self.validator.output_token_cost
        total_total_query_num = slice_query_num + self.slice_inliner.total_query_num + self.intra_detector.total_query_num + self.validator.total_query_num

        self.logger.print_console(f"Slice Retriever: {slice_input_token}, {slice_output_token}, {slice_query_num}")
        self.logger.print_console(f"Slice Inliner : {self.slice_inliner.input_token_cost}, {self.slice_inliner.output_token_cost}, {self.slice_inliner.total_query_num}")
        self.logger.print_console(f"Intra Detector: {self.intra_detector.input_token_cost}, {self.intra_detector.output_token_cost}, {self.intra_detector.total_query_num}")
        self.logger.print_console(f"Validator     : {self.validator.input_token_cost}, {self.validator.output_token_cost}, {self.validator.total_query_num}")
        self.logger.print_console(f"Total         : {total_input_token_cost}, {total_output_token_cost}, {total_total_query_num}")
        self.logger.print_console(f"Total cost time (s): {time.time() - self.start_time}")
        self.logger.print_console("=" * 100)