from ast_nodes import *

class CodeGenerator:
    def generate(self, node):

        if isinstance(node, Program):
            code = ""
            for stmt in node.statements:
                code += self.generate(stmt) + "\n"
            return code.strip()

        elif isinstance(node, Assign):
            return f"{self.generate(node.target)} = {self.generate(node.value)}"

        elif isinstance(node, Call):
            args = ", ".join(self.generate(arg) for arg in node.args)
            # ✅ Fixed: func is a string, not a Name object
            func_name = node.func if isinstance(node.func, str) else self.generate(node.func)
            return f"{func_name}({args})"

        elif isinstance(node, BinaryExpression):
            return f"{self.generate(node.left)} + {self.generate(node.right)}"

        elif isinstance(node, Name):
            return node.id

        elif isinstance(node, Literal):
            return f'"{node.value}"'

        else:
            raise Exception(f"Unsupported AST node: {type(node).__name__}")