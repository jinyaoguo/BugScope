from tstool.analyzer.TS_analyzer import *
from tstool.analyzer.Cpp_TS_analyzer import *
from ..bugscan_extractor import *


class Cpp_SYN_Extractor(BugScanExtractor):
    def find_seeds(self, function: Function) -> List[Tuple[Value, bool]]:
        root_node = function.parse_tree_root_node
        source_code = self.ts_analyzer.code_in_files[function.file_path]
        file_name = function.file_path

        # The nodes we are interested in for this extractor
        seeds = []  # store the tuples of (Value, is_backward)

        # Find parameter nodes that might be i2c_smbus_data
        parameter_nodes = find_nodes_by_type(root_node, "parameter_declaration")
        i2c_smbus_params = []

        # Identify parameters of type i2c_smbus_data
        for param in parameter_nodes:
            union_nodes = find_nodes_by_type(param, "union_specifier")
            for union_node in union_nodes:
                type_id_nodes = find_nodes_by_type(union_node, "type_identifier")
                for type_id in type_id_nodes:
                    if type_id.text.decode() == "i2c_smbus_data":
                        # Find the parameter name
                        id_nodes = find_nodes_by_type(param, "identifier")
                        if id_nodes:
                            param_name = id_nodes[-1].text.decode()
                            i2c_smbus_params.append(param_name)

        # Find potentially vulnerable expressions using data->block[0]
        for param_name in i2c_smbus_params:
            # Find field expressions that access the param
            field_expressions = find_nodes_by_type(root_node, "field_expression")
            for field_expr in field_expressions:
                if len(field_expr.children) >= 3:
                    # Check if accessing the parameter
                    id_node = field_expr.children[0]
                    if id_node.type == "identifier" and id_node.text.decode() == param_name:
                        # Check if accessing the block field
                        field_id = field_expr.children[2]
                        if field_id.type == "field_identifier" and field_id.text.decode() == "block":
                            # Now look for the parent expression to see if it's being indexed
                            parent = field_expr.parent
                            if parent and parent.type == "subscript_expression":
                                # Check if specifically accessing index 0
                                sub_args = find_nodes_by_type(parent, "subscript_argument_list")
                                for sub_arg in sub_args:
                                    number_literals = find_nodes_by_type(sub_arg, "number_literal")
                                    if any(num.text.decode() == "0" for num in number_literals):
                                        # Found data->block[0] pattern
                                        # Get the line number (1-based)
                                        line_no = source_code[:parent.start_byte].count('\n') + 1
                                        expr_text = parent.text.decode()

                                        # Find if this is part of a binary expression (e.g., data->block[0] + 1)
                                        if parent.parent and parent.parent.type == "binary_expression":
                                            expr_text = parent.parent.text.decode()
                                            line_no = source_code[:parent.parent.start_byte].count('\n') + 1

                                        # We use forward analysis (is_backward = False)
                                        seeds.append((Value(expr_text, line_no, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), False))

        # Also look for direct assignment expressions with i2c_smbus_data->block[0]
        assignment_nodes = find_nodes_by_type(root_node, "assignment_expression")
        for assign in assignment_nodes:
            if len(assign.children) >= 3:
                right_side = assign.children[2]
                sub_exprs = find_nodes_by_type(right_side, "subscript_expression")

                for sub_expr in sub_exprs:
                    field_exprs = find_nodes_by_type(sub_expr, "field_expression")
                    for field_expr in field_exprs:
                        if len(field_expr.children) >= 3:
                            id_node = field_expr.children[0]
                            field_id = field_expr.children[2]

                            if (id_node.type == "identifier" and id_node.text.decode() in i2c_smbus_params and
                                field_id.type == "field_identifier" and field_id.text.decode() == "block"):

                                sub_args = find_nodes_by_type(sub_expr, "subscript_argument_list")
                                for sub_arg in sub_args:
                                    number_literals = find_nodes_by_type(sub_arg, "number_literal")
                                    if any(num.text.decode() == "0" for num in number_literals):
                                        line_no = source_code[:assign.start_byte].count('\n') + 1
                                        expr_text = assign.text.decode()
                                        seeds.append((Value(expr_text, line_no, ValueLabel.NON_BUF_ACCESS_EXPR, file_name), False))

        return seeds
