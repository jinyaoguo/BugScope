from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..bugscan_extractor import *


class Cpp_fb_var_screeninfo_Extractor(BugScanExtractor):
    def find_seeds(self, function: Function) -> List[Tuple[Value, bool]]:
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_name = function.file_path

        # The nodes we are interested in for this extractor
        seeds = []              # store the tuples of (Value, is_backward)

        # Known macros/functions that may use pixclock as divisor
        division_macros = {"PICOS2KHZ", "PICOS2KHZ_MIN", "PICOS2KHZ_MAX"}

        # First, check if function has a parameter of fb_var_screeninfo type
        param_declarations = find_nodes_by_type(root_node, "parameter_declaration")
        has_fb_var_param = False

        for param in param_declarations:
            struct_nodes = find_nodes_by_type(param, "struct_specifier")
            for struct_node in struct_nodes:
                type_id_nodes = find_nodes_by_type(struct_node, "type_identifier")
                for type_id in type_id_nodes:
                    if type_id.text.decode() == "fb_var_screeninfo":
                        has_fb_var_param = True
                        break

        if not has_fb_var_param:
            return seeds

        # Look for pixclock field access
        field_exprs = find_nodes_by_type(root_node, "field_expression")
        for field_expr in field_exprs:
            field_ids = find_nodes_by_type(field_expr, "field_identifier")
            for field_id in field_ids:
                if field_id.text.decode() == "pixclock":
                    # Found a pixclock field access
                    line_no = source_code[:field_expr.start_byte].count('\n') + 1

                    # Check if this field is used in a known division macro
                    parent = field_expr.parent
                    while parent and parent != root_node:
                        if parent.type == "call_expression":
                            call_id = [c for c in parent.children if c.type == "identifier"]
                            if call_id and call_id[0].text.decode() in division_macros:
                                text = parent.text.decode()
                                seeds.append((Value(text, line_no, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), True))
                                break
                        # Also check for direct division operations
                        elif parent.type == "binary_expression":
                            op_nodes = [c for c in parent.children if c.type == "/"]
                            if op_nodes:
                                text = parent.text.decode()
                                seeds.append((Value(text, line_no, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), True))
                                break
                        parent = parent.parent

                    # If not found in a known division context, still track it as a seed
                    # for completeness, but with lower priority
                    if not any(seed[0].name == field_expr.text.decode() for seed in seeds):
                        text = field_expr.text.decode()
                        seeds.append((Value(text, line_no, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), True))

        return seeds
