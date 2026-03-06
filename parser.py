# parser.py : parser uses clasees in ast to make tree , every time it recognizes smt it creats object from these classes
from ast_nodes import *
class Parser:
    def __init__(self, tokens):  
        self.tokens = tokens #stores the full token list
        self.pos = 0 #start reading the tokens from begining 
    def current_token(self):
        return self.tokens[self.pos]
    def eat(self, token_type):
        token = self.current_token()
        if token[0] == token_type:
            self.pos += 1
            return token
        else:
            raise SyntaxError(f"Expected {token_type}, got {token[0]}")
    def parse(self):
        statements = [] #creates empty list to store AST nodes
        while self.current_token()[0] != "EOF": #keep parsing  until end of file
            if self.current_token()[0] == "NEWLINE": #this removes newline tokens
                self.eat("NEWLINE")
            else:
                statements.append(self.parse_statement()) #this is where real parsing happens
        return Program(statements)
    def parse_statement(self):
        if self.current_token()[0] == "ID":
            next_token = self.tokens[self.pos + 1]
            # Assignment
            if next_token[0] == "ASSIGN":
                return self.parse_assignment()
            # Function call
            elif next_token[0] == "LPAREN":
                return self.parse_expression()
        raise SyntaxError("Invalid statement")
    def parse_assignment(self):
        name = self.eat("ID")[1]
        self.eat("ASSIGN")
        value = self.parse_expression()
        return Assign(Name(name), value)
    def parse_expression(self):
        node = self.parse_term()
        # Handle concatenation ( + )
        while self.current_token()[0] == "PLUS":
            self.eat("PLUS")
            right = self.parse_term()
            node = BinaryExpression(node, right)
        return node
    def parse_term(self):
        token = self.current_token()
        # String literal
        if token[0] == "STRING":
            return Literal(self.eat("STRING")[1].strip('"'))
        # Variable or function call
        elif token[0] == "ID":
            name = self.eat("ID")[1]
            # Function call
            if self.current_token()[0] == "LPAREN":
                self.eat("LPAREN")
                args = []
                if self.current_token()[0] != "RPAREN":
                    args.append(self.parse_expression())
                self.eat("RPAREN")
                return Call(name, args)
            return Name(name)
        else:
            raise SyntaxError("Invalid expression")
#The parser performs recursive descent parsing. It consumes tokens sequentially, applies grammar rules to distinguish assignments and function calls, builds AST nodes like Assign, Call, BinaryExpression, and Literal, and finally returns a Program node containing all parsed statements.