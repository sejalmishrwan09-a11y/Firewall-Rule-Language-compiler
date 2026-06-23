import re
from tokens import Token, TokenType

class LexerError(Exception):
    def __init__(self, message, line, col):
        super().__init__(f"[LexError] Line {line}, Col {col}: {message}")
        self.line = line
        self.col  = col

class Lexer:
    def __init__(self, text):
        self.source = text
        self.pos    = 0
        self.line   = 1
        self.col    = 1

    def _current(self):
        """Return the character at the current position, or '' at EOF."""
        if self.pos < len(self.source):
            return self.source[self.pos]
        return ''

    def _peek(self, offset=1):
        """Look ahead without consuming."""
        idx = self.pos + offset
        if idx < len(self.source):
            return self.source[idx]
        return ''

    def _advance(self):
        """Consume one character and advance position/line/col counters."""
        ch = self.source[self.pos]
        self.pos += 1
        if ch == '\n':
            self.line += 1
            self.col   = 1
        else:
            self.col  += 1
        return ch

    def _skip_whitespace_and_comments(self):
        """
        Consume spaces, tabs, newlines, and # line comments.
        Called at the start of every token scan.
        """
        while self.pos < len(self.source):
            ch = self._current()

            if ch in (' ', '\t', '\r', '\n'):
                self._advance()

            elif ch == '#':
                while self.pos < len(self.source) and self._current() != '\n':
                    self._advance()

            else:
                break

    def _read_word(self):
        """
        Consume a contiguous run of letters, digits, dots, underscores,
        and forward-slashes (for CIDR notation like 192.168.1.0/24).
        Returns the raw string.
        """
        start = self.pos
        while self.pos < len(self.source) and \
              self._current() in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/':
            self._advance()
        return self.source[start:self.pos]

    def _classify_word(self, word, line, col):
        """
        Given a raw word token, decide its TokenType.
        This is the symbol-table lookup stage of the lexer.
        """
        upper = word.upper()

        if upper in ('ALLOW', 'DENY'):
            return Token(TokenType.ACTION, upper, line, col)

        if upper in ('TCP', 'UDP', 'ICMP'):
            return Token(TokenType.PROTOCOL, upper, line, col)

        if upper == 'FROM':
            return Token(TokenType.FROM, upper, line, col)

        if upper == 'TO':
            return Token(TokenType.TO, upper, line, col)

        if upper == 'PORT':
            return Token(TokenType.PORT, upper, line, col)

        if upper == 'ANY':
            return Token(TokenType.ANY, upper, line, col)

        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}/\d{1,2}', word):
            return Token(TokenType.IP, word, line, col)      # CIDR stored as IP token

        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', word):
            return Token(TokenType.IP, word, line, col)

        if re.fullmatch(r'\d+', word):
            return Token(TokenType.NUMBER, int(word), line, col)

        raise LexerError(f"Unknown token '{word}'", line, col)

    def tokenize(self):
        """
        Scan the entire source and return a list of Token objects.
        The list always ends with an EOF token.

        This is the method called by the Parser.
        """
        tokens = []

        while True:
            self._skip_whitespace_and_comments()

            if self.pos >= len(self.source):
                break

            tok_line = self.line
            tok_col  = self.col

            ch = self._current()

            if ch.isalpha() or ch.isdigit():
                word = self._read_word()
                tok  = self._classify_word(word, tok_line, tok_col)
                tokens.append(tok)
            else:
                raise LexerError(
                    f"Unexpected character '{ch}'", tok_line, tok_col
                )

        tokens.append(Token(TokenType.EOF, None, self.line, self.col))
        return tokens

    def token_stream_repr(self):
        """
        Return a human-readable string of the token stream.
        Used by the CLI --tokens flag and the web playground.
        """
        toks = self.tokenize()
        lines = []
        for t in toks:
            if t.type == TokenType.EOF:
                lines.append(f"  {'EOF':12}  (end of file)")
            else:
                lines.append(
                    f"  {t.type.value:12}  {str(t.value):25}  "
                    f"line {t.line}, col {t.col}"
                )
        return "\n".join(lines)
