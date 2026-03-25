from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..bugscan_extractor import *


class Cpp_DBZ_Extractor(BugScanExtractor):
    def find_seeds(self, function: Function) -> List[Tuple[Value, bool]]:
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_name = function.file_path

        nodes= find_nodes_by_type(root_node, "binary_expression")
        nodes.extend(find_nodes_by_type(root_node, "call_expression"))

        spec_apis = {}          # specific user-defined APIs
        seeds = []
        for node in nodes:
            is_seed_node = False
            if node.type == "binary_expression":
                operator = node.children[1].type
                if operator != "/" and operator != "%":
                    continue
                divisor = node.children[2]
                if divisor.type == "number_literal" and divisor.text.decode("utf8") != "0":
                    continue
                is_seed_node = True
            if node.type == "call_expression":
                for child in node.children:
                    if child.type == "identifier":
                        name = child.text.decode("utf8")
                        if name in spec_apis:
                            is_seed_node = True

            if is_seed_node:
                line_number = source_code[: node.start_byte].count("\n") + 1
                name = node.text.decode("utf8")
                if "\n" in name:
                    name_lines = name.split("\n")
                    for line in name_lines:
                        line = line.strip()
                    name = "".join(name_lines)
                seeds.append((Value(name, line_number, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), True))
        return seeds
