#at this point symbol table is empty and ast is ready 
from ast_nodes import *

class TaintAnalyzer: #holds reference to the same symbol table created in main.py
    def __init__(self, symbol_table):
        self.symtab = symbol_table

    def get_expr_sources(self, expr):
        """Recursively collect all variable names used in expression"""
        sources = []
        if isinstance(expr, Name):
            sources.append(expr.id)
        elif isinstance(expr, BinaryExpression):
            sources.extend(self.get_expr_sources(expr.left))
            sources.extend(self.get_expr_sources(expr.right))
        elif isinstance(expr, Call):
            for arg in expr.args:
                sources.extend(self.get_expr_sources(arg))
        return sources

    def is_expr_tainted(self, expr):
        if isinstance(expr, Name):
            return self.symtab.is_tainted(expr.id)
        elif isinstance(expr, BinaryExpression):
            return self.is_expr_tainted(expr.left) or self.is_expr_tainted(expr.right)
        elif isinstance(expr, Call):
            for arg in expr.args:
                if isinstance(arg, Name) and self.symtab.is_tainted(arg.id):
                    return True
        return False

    def analyze(self, node): #recursive traversal , it walks through AST nodes
        if isinstance(node, Program): #recursively analyses every statement in order , forward analysis (top to bottom)
            for stmt in node.statements:
                self.analyze(stmt)

        elif isinstance(node, Assign): #if first time seeing variable add it to symbol table
            var_name = node.target.id
            self.symtab.declare(var_name)

            # Case 1: x = input() 
            if isinstance(node.value, Call) and node.value.func == "input":  # source=None → taint_sources = [var] , if rhs is input() -> this is source
                self.symtab.mark_tainted(var_name)  #now mark it as tainted

            # Case 2: x = sanitize_*(...)
            elif isinstance(node.value, Call) and isinstance(node.value.func, str) and node.value.func.startswith("sanitize"):
                self.symtab.overwrite(var_name) #if smtg is marked tainted then sanitize it and remove taint

            # Case 3: x = expression (b = a  OR  c = "..." + b)
            else:
                if self.is_expr_tainted(node.value): #checks recursively
                    #  FIX: use propagate_taint to carry root sources forward
                    expr_vars = self.get_expr_sources(node.value) #So if user is tainted:
                    #query becomes tainted
                    
                    self.symtab.propagate_taint(var_name, expr_vars)
                else:
                    self.symtab.overwrite(var_name)

        elif isinstance(node, Call):
            for arg in node.args:
                if isinstance(arg, Name) and self.symtab.is_tainted(arg.id):
                    print(f"[!] Tainted data used in call to {node.func}") # just a warning actual vulnerability decision is done later by sink detector
