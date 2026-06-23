from tokens import TokenType, Token
from ast_nodes import (
    PolicyAST, RuleNode,
    ActionNode, ProtocolNode,
    AnyNode, IPNode, CIDRNode, PortNode,
)

class ParseError(Exception):
    def __init__(self, message, line, col=0):
        super().__init__(f"[ParseError] Line {line}, Col {col}: {message}")
        self.line = line
        self.col  = col

class Parser:
    def __init__(self, tokens):
        self.tokens   = tokens
        self.position = 0

    @property
    def _current(self) -> Token:
        return self.tokens[self.position]

    def _peek(self, offset=1) -> Token:
        idx = self.position + offset
        return self.tokens[idx] if idx < len(self.tokens) else self.tokens[-1]

    def _advance(self) -> Token:
        tok = self._current
        if tok.type != TokenType.EOF:
            self.position += 1
        return tok

    def _expect(self, token_type: TokenType) -> Token:
        tok = self._current
        if tok.type != token_type:
            raise ParseError(
                f"Expected {token_type.value} but got "
                f"'{tok.value}' ({tok.type.value})",
                tok.line, tok.col
            )
        return self._advance()

    def _check(self, token_type: TokenType) -> bool:
        return self._current.type == token_type

    def parse(self) -> PolicyAST:
        ast = PolicyAST()

        while not self._check(TokenType.EOF):
            rule = self._parse_rule()
            ast.rules.append(rule)

        self._expect(TokenType.EOF)
        return ast

    def _parse_rule(self) -> RuleNode:
        line = self._current.line
        col  = self._current.col

        action      = self._parse_action()
        protocol    = self._parse_protocol()
        source      = self._parse_from_clause()
        destination = self._parse_to_clause()
        port        = self._parse_port_clause()

        return RuleNode(
            action=action,
            protocol=protocol,
            source=source,
            destination=destination,
            port=port,
            line=line,
            col=col,
        )

    def _parse_action(self) -> ActionNode:
        tok = self._expect(TokenType.ACTION)
        return ActionNode(value=tok.value, line=tok.line, col=tok.col)

    def _parse_protocol(self) -> ProtocolNode:
        tok = self._expect(TokenType.PROTOCOL)
        return ProtocolNode(value=tok.value, line=tok.line, col=tok.col)

    def _parse_from_clause(self):
        self._expect(TokenType.FROM)
        return self._parse_address()

    def _parse_to_clause(self):
        self._expect(TokenType.TO)
        return self._parse_address()

    def _parse_address(self):
        tok = self._current

        if tok.type == TokenType.ANY:
            self._advance()
            return AnyNode(line=tok.line, col=tok.col)

        if tok.type == TokenType.IP:
            self._advance()
            raw = tok.value

            if '/' in raw:
                # CIDR notation
                network, prefix_str = raw.split('/', 1)
                return CIDRNode(
                    value=raw,
                    network=network,
                    prefix_len=int(prefix_str),
                    line=tok.line,
                    col=tok.col,
                )
            else:
                return IPNode(value=raw, line=tok.line, col=tok.col)

        raise ParseError(
            f"Expected address (ANY / IP / CIDR) but got "
            f"'{tok.value}' ({tok.type.value})",
            tok.line, tok.col
        )

    def _parse_port_clause(self) -> PortNode | None:
        if not self._check(TokenType.PORT):
            return None

        port_tok = self._advance()                  
        num_tok  = self._expect(TokenType.NUMBER)

        return PortNode(
            number=num_tok.value,
            line=port_tok.line,
            col=port_tok.col,
        )
