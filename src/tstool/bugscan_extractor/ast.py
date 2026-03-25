import tree_sitter
from tree_sitter import Language
from pathlib import Path

BASE_PATH = Path(__file__).resolve().parents[3]

def print_nodes(
    node: tree_sitter.Node,
    source_bytes: bytes,
    depth: int = 0,
    max_text_len: int = 80
) -> str:
    """
    Print node information in an indented tree format:
      - type: node type
      - [row:col - row:col]: start/end position in source code
      - text: source text corresponding to the node (escaped newlines, truncated if too long)
      - children: number of direct child nodes
    """
    indent = "  " * depth
    start_row, start_col = node.start_point
    end_row, end_col     = node.end_point

    # Raw text, escape newlines and truncate if too long
    raw = source_bytes[node.start_byte:node.end_byte].decode("utf8", errors="replace")
    text = raw.replace("\n", "\\n")
    if len(text) > max_text_len:
        text = text[: max_text_len // 2] + "…" + text[- max_text_len // 2 :]

    # Build string representation of the current node
    result = (
        f"{indent}{node.type}"
        f"  [{start_row}:{start_col} → {end_row}:{end_col}]"
        f"  children={len(node.children)}"
        f"  text='{text}'\n"
    )

    # Recursively collect strings from child nodes
    for child in node.children:
        result += print_nodes(child, source_bytes, depth + 1, max_text_len)

    return result


def get_AST(
    code: str,
    language_name: str,
) -> str:
    language_path = BASE_PATH / "lib/build/my-languages.so"

    # Initialize tree-sitter parser
    parser = tree_sitter.Parser()

    if language_name == "C":
        language = Language(str(language_path), "c")
    elif language_name == "Cpp":
        language = Language(str(language_path), "cpp")
    elif language_name == "Java":
        language = Language(str(language_path), "java")
    elif language_name == "Python":
        language = Language(str(language_path), "python")
    elif language_name == "Go":
        language = Language(str(language_path), "go")
    else:
        raise ValueError("Invalid language setting")
    parser.set_language(language)

    source_bytes = code.encode("utf8")
    tree = parser.parse(source_bytes)
    return print_nodes(tree.root_node, source_bytes)


print(get_AST(
    code="int main() { int a = 0; return a; }",
    language_name="C"
))