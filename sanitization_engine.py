from ast_nodes import Assign, Name, Call, Program, BinaryExpression
#AST is built
#Symbol table contains TAINTED variables
#SinkDetector already reported vulnerabilities
#Now we FIX the problem
class SanitizationEngine: #receive same symbol symbol table used earlier
    def __init__(self, symbol_table):
        self.symtab = symbol_table
        self.sanitized_vars = set() #prevents duplicate sanitization

    def get_tainted_vars_in_expr(self, expr):
        """Recursively find all tainted variable names in an expression"""
        tainted = []
        if isinstance(expr, Name):
            if self.symtab.is_tainted(expr.id):
                tainted.append(expr.id)
        elif isinstance(expr, BinaryExpression):
            tainted.extend(self.get_tainted_vars_in_expr(expr.left))
            tainted.extend(self.get_tainted_vars_in_expr(expr.right))
        elif isinstance(expr, Call):
            for arg in expr.args:
                tainted.extend(self.get_tainted_vars_in_expr(arg))
        return tainted

    def sanitize_program(self, program):
        # Step 1: Find all root taint sources and what type of sanitization they need
        sql_sources = set() #stores original root variable , not query because main cause of sink is user
        xss_sources = set()

        for stmt in program.statements:
            if isinstance(stmt, Call):
                # SQL sink
                if stmt.func == "execute":
                    for arg in stmt.args:
                        tainted_vars = self.get_tainted_vars_in_expr(arg) #check if query is tainted if yes
                        for var in tainted_vars:
                            for src in self.symtab.get_taint_sources(var): #now check did query came from user
                                sql_sources.add(src)

                # XSS sink
                elif stmt.func == "print":
                    for arg in stmt.args:
                        tainted_vars = self.get_tainted_vars_in_expr(arg)
                        for var in tainted_vars:
                            for src in self.symtab.get_taint_sources(var):
                                xss_sources.add(src)

        # Step 2: Rebuild statements, injecting sanitization RIGHT AFTER source assignment
        new_statements = []

        for stmt in program.statements:
            new_statements.append(stmt)

            if isinstance(stmt, Assign) and isinstance(stmt.target, Name):
                var_name = stmt.target.id

                # Inject sanitize_sql after SQL taint source
                if var_name in sql_sources and var_name not in self.sanitized_vars:
                    sanitize_stmt = Assign(
                        Name(var_name),
                        Call("sanitize_sql", [Name(var_name)])
                    )
                    new_statements.append(sanitize_stmt)
                    self.symtab.mark_sanitized_sql(var_name)
                    self.sanitized_vars.add(var_name)

                # Inject sanitize_xss after XSS taint source
                elif var_name in xss_sources and var_name not in self.sanitized_vars:
                    sanitize_stmt = Assign(
                        Name(var_name),
                        Call("sanitize_xss", [Name(var_name)])
                    )
                    new_statements.append(sanitize_stmt)
                    self.symtab.mark_sanitized_xss(var_name)
                    self.sanitized_vars.add(var_name)

        program.statements = new_statements
        return program

    def inject(self, program):
        return self.sanitize_program(program)
