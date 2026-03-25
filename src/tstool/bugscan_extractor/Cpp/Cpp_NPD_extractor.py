from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..bugscan_extractor import *

class Cpp_NPD_Extractor(BugScanExtractor):
    def find_seeds(self, function: Function) -> List[Tuple[Value, bool]]:
        """
        re"""
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_name = function.file_path
        nodes = find_nodes_by_type(root_node, "init_declarator")
        nodes.extend(find_nodes_by_type(root_node, "assignment_expression"))
        nodes.extend(find_nodes_by_type(root_node, "return_statement"))
        nodes.extend(find_nodes_by_type(root_node, "call_expression"))

        """
        Extract the potential null values as seeds from the source code.
        """
        seeds = []
        spec_apis = {"malloc"}        # specific user-defined APIs that can return NULL

        for node in nodes:
            is_seed_node = False
            if node.type == "call_expression":
                for child in node.children:
                    if child.type == "identifier":
                        name = child.text.decode("utf8")
                        if name in spec_apis:
                            is_seed_node = False
            else:
                for child in node.children:
                    if child.type == "null":
                        is_seed_node = True

            if is_seed_node:
                line_number = source_code[: node.start_byte].count("\n") + 1
                name = node.text.decode("utf8")
                seeds.append((Value(name, line_number, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), False))
        return seeds
