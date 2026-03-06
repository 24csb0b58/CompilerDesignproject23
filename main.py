#main.py
from lexical import lexer # converts to tokens
from parser import Parser # converts tokens to ast
from symbol_table import SymbolTable #store variable and tracks tainted status
from taint_engine import TaintAnalyzer # marks input() and all as tainted
from sink_detector import SinkDetector # checks if tainted data reaches excute() or print()
from sanitization_engine import SanitizationEngine #automatically inserts sanitization engine
from code_generator import CodeGenerator #converts modified ast to source code
from ast_nodes import print_ast   # <-- import AST printer
#reading input
with open("test.py", "r") as f:
    code = f.read() # stores whole code as a string name 'code'

tokens = lexer(code) # same string code broken into tokens , remove whitespaces , identifies variable and function calls 
parser = Parser(tokens) 
ast = parser.parse() # build ast


print("\n" + "="*50)
print("     AST (Before Sanitization)")
print("="*50)
print_ast(ast)
print("="*50)
# Step 1: Taint analysis
symtab = SymbolTable() #creates empty sybmbol table
taint = TaintAnalyzer(symtab) #create taint analyzer , passes symbol table so it can update taint info
taint.analyze(ast) #core step 1. walks through ast , finds soursec like input (),marks variable as tainted , propagates taint throung assignment

# prints symbol table before sanitization
symtab.display("SYMBOL TABLE (Before Sanitization)")

# Step 2: Sink detection
sink = SinkDetector(symtab) # create sink detector object , passes symboltable to check taint status
sink.detect(ast) # walks through ast , checks dangerous function execute ,print(), if  argument is tainted -> prints warning 
#after coming from the sink detector it goes to sanitization engine and injects sanitize
# Print vulnerability report
sink.print_vulnerabilities()

# Print data flow graph
sink.print_data_flow_graph()

# Step 3: Sanitization injection
sanitizer = SanitizationEngine(symtab)
sanitizer.inject(ast) # this modifies ast 

# Generate secure code
generator = CodeGenerator() #creates an object for code generator
secure_code = generator.generate(ast) # converts ast->python source code string

print("\n===== SECURE SANITIZED CODE =====")
print(secure_code) # displays final code 