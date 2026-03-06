#symbol_table.py
class SymbolTable:
    def __init__(self): #two empty list are created
        # Stores variable -> state
        # States: CLEAN, TAINTED, SANITIZED_SQL, SANITIZED_XSS
        self.table = {}

        # Stores variable -> list of original taint sources
        self.taint_sources = {}

    # -------------------------------
    # Variable Declaration
    # -------------------------------
    def declare(self, var):
        if var not in self.table:
            self.table[var] = "CLEAN"
            self.taint_sources[var] = []

    # -------------------------------
    # Mark variable as tainted
    # -------------------------------
    def mark_tainted(self, var, source=None):
        self.table[var] = "TAINTED"

        # If no source provided, variable is its own source
        if source is None:
            self.taint_sources[var] = [var] #taint_sources tracking
        else:
            # If source is list, extend
            if isinstance(source, list):
                self.taint_sources[var] = list(set(source))
            else:
                self.taint_sources[var] = [source]

    def mark_sanitized_sql(self, var):
        self.table[var] = "SANITIZED_SQL"

    def mark_sanitized_xss(self, var):
        self.table[var] = "SANITIZED_XSS"

    # Check if variable is tainted
    
    def is_tainted(self, var):
        return self.table.get(var) == "TAINTED"

    
    # Check if SQL sanitized
    
    def is_sanitized_sql(self, var):
        return self.table.get(var) == "SANITIZED_SQL"

    
    # Check if XSS sanitized
   
    def is_sanitized_xss(self, var):
        return self.table.get(var) == "SANITIZED_XSS"

   
    # Get taint sources (dependency tracking)
    
    def get_taint_sources(self, var):
        return self.taint_sources.get(var, [])


    # Propagate taint from one variable to another
    #if user is tainted and query contain user than it is also tainted and its taint source becomes user, 
    #forward data flow analysis
    def propagate_taint(self, target, sources):
        """
        target = variable being assigned
        sources = list of variables used in expression
        """

        tainted_sources = []

        for var in sources:
            if self.is_tainted(var):
                tainted_sources.extend(self.get_taint_sources(var))

        if tainted_sources:
            self.mark_tainted(target, tainted_sources)
        else:
            self.table[target] = "CLEAN"
            self.taint_sources[target] = []

   
    # Overwrite variable (removes taint)
    #variable gets reassigned safely
    def overwrite(self, var):
        self.table[var] = "CLEAN"
        self.taint_sources[var] = []
    # Print symbol table
    
    def display(self,title="SYMBOL TABLE"):
        print("===== SYMBOL TABLE =====")
        print("Variable\tState")
        print("-----------------------------")
        for var, state in self.table.items():
            print(f"{var}\t\t{state}")