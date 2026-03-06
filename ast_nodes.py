# ast/ast_nodes.py

class ASTNode: #base class to allow all nodes to inherit frpom one common type
    pass

class Program(ASTNode): #root of ast 
    #Program
 #├── Assign(user, input())
 #├── Assign(query, BinaryExpression)
 #├── Call(execute)
 #└── Call(print) 
 #So Program node contains entire program.
    def __init__(self, statements): #constructor
        self.statements = statements

class Assign(ASTNode): #represents variable=expression eg. user = input() ast created Assign(
    #Name("user"),
    #Call("input", [])
#)
    def __init__(self, target, value):
        self.target = target
        self.value = value

class Name(ASTNode):
    def __init__(self, id):
        self.id = id

class Call(ASTNode): #represent function call , import to regognize source , sink
    def __init__(self, func, args):
        self.func = func
        self.args=args

class Literal(ASTNode): #used inside binary exp "abc" or "select *from table" etc
    def __init__(self, value):
        self.value = value

class Sanitize(ASTNode): #This is used in sanitization phase. in main.py if sanitizer.inject(ast)
    def __init__(self, variable):
        self.variable = variable
class BinaryExpression: #represenys concatenation important because in query also it may have in between some tainted sources
    def __init__(self, left, right):
        self.left = left
        self.right = right
#ast_nodes.py defines the structure of the Abstract Syntax Tree. During parsing, the parser creates objects like Program, Assign, Call, Name, Literal, and BinaryExpression. These nodes represent the syntactic structure of the source code. Later, the taint analyzer, sink detector, and sanitization engine traverse and modify this AST before the secure code is generated.        
# ===== AST PRINTER =====
def print_ast(node, indent=0):
    prefix = "  " * indent
    if isinstance(node, Program):
        print(f"{prefix}Program")
        for stmt in node.statements:
            print_ast(stmt, indent + 1)

    elif isinstance(node, Assign):
        print(f"{prefix}Assign")
        print(f"{prefix}  target: Name({node.target.id})")
        print(f"{prefix}  value:")
        print_ast(node.value, indent + 2)

    elif isinstance(node, Call):
        print(f"{prefix}Call: {node.func}()")
        for i, arg in enumerate(node.args):
            print(f"{prefix}  arg[{i}]:")
            print_ast(arg, indent + 2)

    elif isinstance(node, BinaryExpression):
        print(f"{prefix}BinaryExpression (+)")
        print(f"{prefix}  left:")
        print_ast(node.left, indent + 2)
        print(f"{prefix}  right:")
        print_ast(node.right, indent + 2)

    elif isinstance(node, Name):
        print(f"{prefix}Name({node.id})")

    elif isinstance(node, Literal):
        print(f"{prefix}Literal(\"{node.value}\")")

    elif isinstance(node, Sanitize):
        print(f"{prefix}Sanitize({node.variable})")

    else:
        print(f"{prefix}[Unknown node: {type(node).__name__}]")