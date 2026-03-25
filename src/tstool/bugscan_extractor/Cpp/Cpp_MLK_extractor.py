from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..bugscan_extractor import *

class Cpp_MLK_Extractor(BugScanExtractor):
    def find_seeds(self, function: Function) -> List[Tuple[Value, bool]]:
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_name = function.file_path
    
        nodes = find_nodes_by_type(root_node, "call_expression")
        nodes.extend(find_nodes_by_type(root_node, "new_expression"))

        """
        Extract the seeds for Memory Leak Detection from the source code.
        1. malloc, realloc, calloc
        2. strdup, strndup
        3. asprintf, vasprintf
        4. new
        5. getline
        """
        mem_allocations = {"malloc", "calloc", "realloc", "strdup", "strndup", "asprintf", "vasprintf", "getline"}
        spec_apis = {"nfp_cpp_area_alloc", "damon_new_ctx", "xmalloc"}          # specific user-defined APIs that allocate memory
        seeds = []
        for node in nodes:
            is_seed_node = False
            if node.type == "new_expression":
                is_seed_node = True
            if node.type == "call_expression":
                for child in node.children:
                    if child.type == "identifier":
                        name = child.text.decode("utf8")
                        if name in mem_allocations or name in spec_apis:
                            is_seed_node = True

            if is_seed_node:
                line_number = source_code[: node.start_byte].count("\n") + 1
                name = node.text.decode("utf8")
                seeds.append((Value(name, line_number, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), False))
                if file_name == "../benchmark/Reproduce/Cpp/MLK/mm/damon/reclaim.c":
                    print(f"Debug: {name} in {file_name}")
        return seeds     
