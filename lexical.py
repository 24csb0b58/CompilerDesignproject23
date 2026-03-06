#regex is a pattern matching language used to identify text pattens in string
import re #pythons re module to match patterns like for regex which matches smtg belongs to some range or not 
from typing import List, Tuple

token_specification = [
    ('COMMENT',  r'#[^\n]*'),   #  ADD THIS - skips # comments
    ('STRING',   r'"[^"]*"'),
    ('NUMBER',   r'\d+'),
    ('ID',       r'[A-Za-z_]\w*'),
    ('ASSIGN',   r'='),
    ('PLUS',     r'\+'),
    ('LPAREN',   r'\('),
    ('RPAREN',   r'\)'),
    ('COMMA',    r','),
    ('NEWLINE',  r'\n'),
    ('SKIP',     r'[ \t]+'),
    ('MISMATCH', r'.'),
]

Token = Tuple[str, str]
#from lexical import lexer this loads this function ntg runs rn just import 
def lexer(code: str) -> List[Token]:
    tokens = []
    regex_parts = []
    for name, regex in token_specification:
        regex_parts.append(f"(?P<{name}>{regex})") #named grp in regex (?P<ID>[A-Za-z_]\w*)
    master_regex = re.compile("|".join(regex_parts)) #creates one big regex so python can scan entire program and classify tokens (id pattern)|(string pattenn) like this
    
    for match in master_regex.finditer(code): #scans full program left to right
        kind = match.lastgroup # this gives token type name
        value = match.group()
        if kind in ("SKIP", "COMMENT"):   #  Skip both whitespace and comments
            continue
        elif kind == "MISMATCH":
            raise RuntimeError(f"Unexpected character: {value}")
        else:
            tokens.append((kind, value))
    
    tokens.append(("EOF", "")) # helps parser know where input ended
    return tokens