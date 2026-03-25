from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..bugscan_extractor import *


class Cpp_BUG_Extractor(BugScanExtractor):
    def find_seeds(self, function: Function) -> List[Tuple[Value, bool]]:
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_name = function.file_path

        # The nodes we are interested in for this extractor

        spec_apis = {}          # specific user-defined APIs
        seeds = []              # store the tuples of (Value, is_backward)
        # Extract seeds


        
        return seeds
