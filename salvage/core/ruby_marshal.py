"""Парсер Ruby Marshal (формат 4.8) — для .rxdata/.rvdata/.rvdata2 без Ruby.

Декодирует в питоновские структуры и обратно. Незнакомые классы становятся
обёрткой MRubyObj (имя класса + поля), поэтому ничего не теряется и JSON
остаётся человекочитаемым.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


class MarshalError(ValueError):
    pass


@dataclass
class MRubyObj:
    """Объект пользовательского класса: {"__class__": name, "ivars": {...}}."""
    class_name: str
    ivars: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {"__class__": self.class_name,
                "ivars": {k: to_jsonable(v) for k, v in self.ivars.items()}}


@dataclass(frozen=True)
class MRubySymbol:
    name: str


@dataclass
class MRubyUserDef:
    class_name: str
    data: bytes


@dataclass
class MRubyExtended:
    """'_' (extended): объект с добавленным модулем — храним и модуль, и данные."""
    module: str
    value: Any


_NIL = object()


class _Reader:
    __slots__ = ("b", "p", "symbols", "objects")

    def __init__(self, data: bytes):
        self.b = data
        self.p = 0
        self.symbols: list[str] = []
        self.objects: list[Any] = []

    # --- примитивы ---
    def byte(self) -> int:
        if self.p >= len(self.b):
            raise MarshalError("unexpected EOF")
        v = self.b[self.p]
        self.p += 1
        return v

    def read(self, n: int) -> bytes:
        if n < 0 or self.p + n > len(self.b):
            raise MarshalError("unexpected EOF")
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    # --- формат ---
    def parse(self) -> Any:
        major = self.byte()
        minor = self.byte()
        if major != 4:
            raise MarshalError(f"неподдерживаемая версия Marshal: {major}.{minor}")
        return self._value()

    def _long(self) -> int:
        c = self.read(1)[0]
        return int.from_bytes(c.to_bytes(1, "little", signed=True), "little", signed=True)

    def _fixnum(self) -> int:
        """Строго по marshal.c: тег N в 1..4 => N байт little-endian SIGNED;
        5 => отрицательное 3..4 байта; 6..127 => c-5; 128..255 => c-251."""
        c = self.byte()
        if c == 0:
            return 0
        if 1 <= c <= 4:
            return int.from_bytes(self.read(c), "little", signed=True)
        if c == 5:
            n = self.byte()  # 3 или 4
            return int.from_bytes(self.read(n), "little", signed=True)
        if 6 <= c <= 127:
            return c - 5
        return c - 251

    def _symbol_body(self) -> str:
        """Разбор тела символа при уже прочитанном теге (':'/'e'/'o' и т.п.)."""
        c = self.byte()
        if c == 0x3a:
            name = self._string_bytes().decode("utf-8", "replace")
            self.symbols.append(name)
            return name
        if c == 0x3b:
            idx = self._fixnum()
            if 0 <= idx < len(self.symbols):
                return self.symbols[idx]
        raise MarshalError(f"bad symbol tag 0x{c:02x}")

    def _symbol(self) -> str:
        c = self.byte()
        if c == 0x3a:  # ':'
            name = self._string_bytes().decode("utf-8", "replace")
            self.symbols.append(name)
            return name
        if c == 0x3b:  # ';'
            idx = self._fixnum()
            if 0 <= idx < len(self.symbols):
                return self.symbols[idx]
        raise MarshalError(f"bad symbol tag 0x{c:02x}")

    def _string_bytes(self) -> bytes:
        ln = self._fixnum()
        if ln < 0 or self.p + ln > len(self.b):
            raise MarshalError("bad string length")
        return self.read(ln)

    def _value(self) -> Any:
        t = self.byte()
        return self._value_with(t)

    def _value_with(self, t: int) -> Any:
        if t == 0x30:  # '0'
            self.objects.append(None)
            return None
        if t == 0x54:  # 'T'
            self.objects.append(True)
            return True
        if t == 0x46:  # 'F'
            self.objects.append(False)
            return False
        if t == 0x69:  # 'i'
            v = self._fixnum()
            self.objects.append(v)
            return v
        if t == 0x3a:  # ':'
            name = self._string_bytes().decode("utf-8", "replace")  # тег уже прочитан
            self.symbols.append(name)
            sym = MRubySymbol(name)
            self.objects.append(sym)
            return sym
        if t == 0x22:  # '"'
            sv = self._string_bytes().decode("utf-8", "replace")
            self.objects.append(sv)
            return sv
        if t == 0x49:  # 'I' (строка с кодировкой)
            c = self.byte()
            if c == 0x22:
                raw = self._string_bytes()
            elif c == 0x3a:  # data — символ
                raw = self._string_bytes().decode("utf-8", "replace").encode("utf-8")
                self.symbols.append(raw.decode("utf-8", "replace"))
            else:
                raw = self._string_bytes()
            self._ivars()  # ivar'ы строки (E=true, encoding="UTF-8", ...)
            sv = raw.decode("utf-8", "replace")
            self.objects.append(sv)
            return sv
        if t == 0x5b:  # '['
            n = self._fixnum()
            arr: list[Any] = []
            self.objects.append(arr)
            for _ in range(max(0, n)):
                arr.append(self._value())
            return arr
        if t == 0x7b:  # '{'
            n = self._fixnum()
            d: dict[Any, Any] = {}
            self.objects.append(d)
            for _ in range(max(0, n)):
                k = self._value()
                v = self._value()
                d[_hashable(k)] = v
            return d
        if t == 0x6c:  # 'l'
            sign = self.byte()
            n = self._fixnum()
            val = 0
            for i in range(max(0, n)):
                val |= int.from_bytes(self.read(2), "little") << (16 * i)
            v = -val if sign == 0x2d else val
            self.objects.append(v)
            return v
        if t == 0x66:  # 'f'
            raw = self._string_bytes()
            v = float(raw.decode("ascii", "replace"))
            self.objects.append(v)
            return v
        if t == 0x40:  # '@'
            idx = self._fixnum()
            return self.objects[idx] if 0 <= idx < len(self.objects) else None
        if t == 0x3b:  # ';'
            idx = self._fixnum()
            name = self.symbols[idx] if 0 <= idx < len(self.symbols) else "?"
            sym = MRubySymbol(name)
            self.objects.append(sym)
            return sym
        if t == 0x6f:  # 'o'
            self.objects.append(None)
            cls = self._symbol()
            obj = MRubyObj(cls)
            self.objects[-1] = obj
            obj.ivars = self._ivars()
            return obj
        if t in (0x55, 0x75):  # 'U' / 'u'
            self.objects.append(None)
            cls = self._symbol()
            raw = self.read(max(0, self._fixnum()))
            obj = MRubyUserDef(cls, raw)
            self.objects[-1] = obj
            return obj
        if t in (0x63, 0x6d):  # 'c' / 'm'
            self.objects.append(None)
            name = (self._string_bytes().decode("utf-8", "replace")
                    if t == 0x63 else self._symbol())
            obj = MRubyObj(name)
            self.objects[-1] = obj
            return obj
        if t == 0x65:  # 'e'
            self.objects.append(None)
            mod = self._symbol()
            val = self._value()
            obj = MRubyExtended(mod, val)
            self.objects[-1] = obj
            return obj
        if t == 0x43:  # 'C' — подкласс встроенного типа
            self.objects.append(None)
            self._symbol()  # имя класса теряем, значение сохраняем
            val = self._value()
            self.objects[-1] = val
            return val
        if t == 0x53:  # 'S' struct
            self.objects.append(None)
            cls = self._symbol()
            obj = MRubyObj("Struct:" + cls)
            self.objects[-1] = obj
            obj.ivars = self._ivars()
            return obj
        if t == 0x2f:  # '/'
            raw = self._string_bytes()
            self.byte()
            obj = MRubyUserDef("Regexp", raw)
            self.objects.append(obj)
            return obj
        raise MarshalError(f"неизвестный тег 0x{t:02x} на позиции {self.p - 1}")

    def _ivars(self) -> dict[str, Any]:
        n = self._fixnum()
        out: dict[str, Any] = {}
        for _ in range(n):
            name = self._symbol()
            out[name] = self._value()
        return out


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------

def loads(data: bytes) -> Any:
    if data[:1] not in (b"\x04",):
        raise MarshalError("данные не похожи на Ruby Marshal (первый байт != 4)")
    return _Reader(data).parse()


def to_jsonable(v: Any, _depth: int = 0) -> Any:
    if _depth > 200:
        return "…"
    if isinstance(v, MRubySymbol):
        return v.name
    if isinstance(v, MRubyObj):
        return v.to_json()
    if isinstance(v, MRubyUserDef):
        return {"__class__": v.class_name,
                "bytes": v.data[:4096].hex(),
                "truncated": len(v.data) > 4096}
    if isinstance(v, MRubyExtended):
        return {"__module__": v.module, "value": to_jsonable(v.value, _depth + 1)}
    if isinstance(v, dict):
        return {_key(k): to_jsonable(val, _depth + 1) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [to_jsonable(x, _depth + 1) for x in v]
    if isinstance(v, bytes):
        return {"__bytes__": v[:4096].hex()}
    return v


def _hashable(k: Any) -> Any:
    if isinstance(k, MRubySymbol):
        return k.name
        return k
    if isinstance(k, (str, int, float, bool)) or k is None:
        return k
    return k


def _key(k: Any) -> str:
    if isinstance(k, MRubySymbol):
        return k.name
    if isinstance(k, str):
        return k
    return str(to_jsonable(k))


# ---------------------------------------------------------------------------
# Запись (для round-trip: JSON → Marshal)
# ---------------------------------------------------------------------------

class _Writer:
    def __init__(self) -> None:
        self.out = bytearray()

    def w(self, b: bytes) -> None:
        self.out.extend(b)

    def fixnum(self, i: int) -> None:
        """Кодирование fixnum. Допустимо любое корректное представление,
        но лучше минимальное: 1..4 байта signed, иначе тег 5."""
        if i == 0:
            self.w(b"\x00")
            return
        if 0 < i < 123:
            self.w(bytes([i + 5]))
            return
        if -123 < i < 0:
            self.w(bytes([(i - 5) & 0xFF]))
            return
        for n in (1, 2, 3):
            lo, hi = -(2 ** (8 * n - 1)), 2 ** (8 * n - 1) - 1
            if lo <= i <= hi:
                self.w(bytes([n]) + i.to_bytes(n, "little", signed=True))
                return
        if -(2 ** 31) <= i <= 2 ** 31 - 1:
            self.w(b"\x04" + i.to_bytes(4, "little", signed=True))
            return
        # вне 32 бит: тег 5 + длина 3/4 тоже подходит для больших отрицательных,
        # но для огромных используем bignum
        self.bignum(i)

    def bignum(self, i: int) -> None:
        sign = b"+" if i >= 0 else b"-"
        val = abs(i)
        words = []
        while val:
            words.append(val & 0xFFFF)
            val >>= 16
        self.w(b"l" + sign)
        self.fixnum(len(words))
        for wd in words:
            self.w(struct.pack("<H", wd))

    def sym(self, name: str) -> None:
        raw = name.encode("utf-8")
        self.w(b":")
        self.fixnum(len(raw))
        self.w(raw)

    def str(self, s: str) -> None:
        raw = s.encode("utf-8")
        self.w(b'"')
        self.fixnum(len(raw))
        self.w(raw)

    def value(self, v: Any) -> None:
        if v is None:
            self.w(b"0")
        elif v is True:
            self.w(b"T")
        elif v is False:
            self.w(b"F")
        elif isinstance(v, int):
            lo32, hi32 = -(2 ** 31), 2 ** 31 - 1
            if -(2 ** 23) <= v <= 2 ** 23 - 1:
                self.w(b"i")
                self.fixnum(v)
            elif lo32 <= v <= hi32:
                # корректно и как 'i'+тег 5(4), и как bignum — берём компактное i-форму
                self.w(b"i")
                self.w(b"\x05\x04" + v.to_bytes(4, "little", signed=True))
            else:
                self.bignum(v)
        elif isinstance(v, float):
            raw = repr(v).encode()
            self.w(b"f")
            self.fixnum(len(raw))
            self.w(raw)
        elif isinstance(v, str):
            if any(ord(c) > 127 for c in v):
                raw = v.encode("utf-8")
                self.w(b"I")  # строка с кодировкой UTF-8
                self.w(b'"')
                self.fixnum(len(raw))
                self.w(raw)
                self.fixnum(2)      # ivar'ы: E (UTF-8) и encoding
                self.sym("E")
                self.w(b"T")        # :E => true (UTF-8)
                self.sym("encoding")
                self.str("UTF-8")
            else:
                self.str(v)
        elif isinstance(v, list):
            self.w(b"[")
            self.fixnum(len(v))
            for x in v:
                self.value(x)
        elif isinstance(v, dict):
            self.w(b"{")
            self.fixnum(len(v))
            for k, val in v.items():
                self.sym(str(k))
                self.value(val)
        else:
            self.str(str(v))


def dumps(v: Any) -> bytes:
    w = _Writer()
    w.w(b"\x04\x08")
    w.value(v)
    return bytes(w.out)


def json_to_marshal(data: Any) -> bytes:
    """JSON-совместимая структура → Marshal (объекты {__class__, ivars} восстанавливаются)."""
    def conv(x: Any) -> Any:
        if isinstance(x, dict):
            if "__class__" in x and "ivars" in x:
                return MRubyObj(x["__class__"], {k: conv(v) for k, v in x["ivars"].items()})
            return {k: conv(v) for k, v in x.items()}
        if isinstance(x, list):
            return [conv(i) for i in x]
        return x

    root = conv(data)

    class _W(_Writer):
        def value(self, v: Any) -> None:  # type: ignore[override]
            if isinstance(v, MRubyObj):
                self.w(b"o")
                self.sym(v.class_name)
                self.fixnum(len(v.ivars))
                for k, val in v.ivars.items():
                    self.sym(str(k))
                    self.value(val)
                return
            if isinstance(v, MRubySymbol):
                self.sym(v.name)
                return
            super().value(v)

    w = _W()
    w.w(b"\x04\x08")
    w.value(root)
    return bytes(w.out)
