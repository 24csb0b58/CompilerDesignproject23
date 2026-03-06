# sink_detector.py
from ast_nodes import *

class SinkDetector:
    def __init__(self, symbol_table):
        self.symtab = symbol_table
        self.vulnerabilities = []   # collect all vulns
        self.data_flow_edges = []   # collect all flow edges

    def detect(self, node):
        if isinstance(node, Program):
            for stmt in node.statements:
                self.detect(stmt)

        elif isinstance(node, Call):
            # XSS SINK
            if node.func == "print":
                for arg in node.args:
                    if isinstance(arg, Name) and self.symtab.is_tainted(arg.id):
                        sources = self.symtab.get_taint_sources(arg.id)
                        vuln = {
                            "type": "XSS",
                            "sink": "print()",
                            "tainted_var": arg.id,
                            "root_sources": sources
                        }
                        self.vulnerabilities.append(vuln)
                        for src in sources:
                            self.data_flow_edges.append((src, arg.id, "print()", "XSS"))

            # SQL INJECTION SINK
            elif node.func == "execute":
                for arg in node.args:
                    if isinstance(arg, Name) and self.symtab.is_tainted(arg.id):
                        sources = self.symtab.get_taint_sources(arg.id)
                        vuln = {
                            "type": "SQL Injection",
                            "sink": "execute()",
                            "tainted_var": arg.id,
                            "root_sources": sources
                        }
                        self.vulnerabilities.append(vuln)
                        for src in sources:
                            self.data_flow_edges.append((src, arg.id, "execute()", "SQL Injection"))

    def print_vulnerabilities(self):
        print("\n" + "="*50)
        print("       VULNERABILITY DETECTION REPORT")
        print("="*50)
        if not self.vulnerabilities:
            print("  [✓] No vulnerabilities detected.")
        else:
            for i, v in enumerate(self.vulnerabilities, 1):
                print(f"\n  [!] Vulnerability #{i}")
                print(f"      Type        : {v['type']}")
                print(f"      Sink        : {v['sink']}")
                print(f"      Tainted Var : {v['tainted_var']}")
                print(f"      Root Source : {', '.join(v['root_sources'])}")
        print("="*50)

    def print_data_flow_graph(self):
        print("\n" + "="*50)
        print("           DATA FLOW GRAPH")
        print("="*50)
        if not self.data_flow_edges:
            print("  No tainted data flows detected.")
        else:
            print("  Format: [SOURCE] --> [VARIABLE] --> [SINK] (VulnType)\n")
            for (src, var, sink, vtype) in self.data_flow_edges:
                if src == var:
                    # direct flow: source goes straight to sink
                    print(f"  [ {src} (input) ]  -->  [ {sink} ]  ⚠ {vtype}")
                else:
                    print(f"  [ {src} (input) ]  -->  [ {var} ]  -->  [ {sink} ]  ⚠ {vtype}")
        print("="*50)