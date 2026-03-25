from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..bugscan_extractor import *


class Cpp_i2c_msg_Extractor(BugScanExtractor):
    def find_seeds(self, function: Function) -> List[Tuple[Value, bool]]:
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_name = function.file_path

        # The nodes we are interested in for this extractor
        seeds = []  # store the tuples of (Value, is_backward)

        # Find parameter declarations that match struct i2c_msg array pattern
        param_decls = find_nodes_by_type(root_node, "parameter_declaration")
        i2c_msg_params = {}

        for param in param_decls:
            struct_specs = [c for c in param.children if c.type == "struct_specifier"]
            array_decls = [c for c in param.children if c.type == "array_declarator"]

            for struct_spec in struct_specs:
                if b"i2c_msg" in struct_spec.text:
                    for array_decl in array_decls:
                        id_nodes = [c for c in array_decl.children if c.type == "identifier"]
                        if id_nodes:
                            param_name = id_nodes[0].text.decode()
                            i2c_msg_params[param_name] = True

        # Find all field expressions that access the buf field of an i2c_msg array element
        field_exprs = find_nodes_by_type(root_node, "field_expression")

        for field_expr in field_exprs:
            field_id_nodes = [c for c in field_expr.children if c.type == "field_identifier"]

            # Check if this accesses a 'buf' field
            if any(field_id.text.decode() == "buf" for field_id in field_id_nodes):
                # Check if the field expression is on an i2c_msg array element
                subscript_exprs = [c for c in field_expr.children if c.type == "subscript_expression"]
                for subscript_expr in subscript_exprs:
                    id_nodes = [c for c in subscript_expr.children if c.type == "identifier"]
                    for id_node in id_nodes:
                        if id_node.text.decode() in i2c_msg_params:
                            # Now check if this buf field is being accessed with an index
                            parent = field_expr.parent
                            if parent and parent.type == "subscript_expression":
                                # We found a pattern like msg[i].buf[j]
                                line_no = source_code[:parent.start_byte].count("\n") + 1
                                text = parent.text.decode()
                                seeds.append((Value(text, line_no, ValueLabel.BUF_ACCESS_EXPR, file_name), True))

                            # Also check if this field is used in a binary expression
                            # This catches cases where the buf is accessed but not directly indexed
                            if not seeds and field_expr.parent and field_expr.parent.type == "binary_expression":
                                line_no = source_code[:field_expr.start_byte].count("\n") + 1
                                text = field_expr.text.decode()
                                seeds.append((Value(text, line_no, ValueLabel.BUF_ACCESS_EXPR, file_name), True))

        return seeds