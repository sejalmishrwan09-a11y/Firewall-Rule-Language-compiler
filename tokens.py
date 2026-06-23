from enum import Enum, auto


class TokenType(Enum):
    ACTION   = "ACTION"     
    PROTOCOL = "PROTOCOL"  
    FROM     = "FROM"
    TO       = "TO"
    PORT     = "PORT"
    IP       = "IP"         
    NUMBER   = "NUMBER"     
    ANY      = "ANY"
    EOF      = "EOF"


class Token:
    def __init__(self, type_: TokenType, value, line: int, col: int = 0):
        self.type  = type_
        self.value = value
        self.line  = line
        self.col   = col

    def __repr__(self):
        return f"Token({self.type.value}, {self.value!r}, L{self.line}:C{self.col})"
