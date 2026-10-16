"""Small, read-only ELF32 reader for SH-4 executables and objects (EM_SH, little endian)."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

EM_SH = 42
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE = 0x1, 0x2, 0x4, 0x10
SHT_PROGBITS, SHT_NOBITS = 1, 8
STT_OBJECT, STT_FUNC = 1, 2


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Elf:
    def __init__(self, data: bytes, name="ELF"):
        self.data, self.name = data, str(name)
        if data[:4] != b"\x7fELF" or data[4] != 1:
            raise ValueError(f"{name}: expected an ELF32 file")
        if data[5] != 1:
            raise ValueError(f"{name}: expected a little-endian SH-4 ELF (-ml)")
        (self.type, machine, _, self.entry, _, shoff, self.flags, _, _, _,
         shsize, shnum, shstr) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        if machine != EM_SH:
            raise ValueError(f"{name}: expected SuperH (e_machine={EM_SH}), found {machine}")
        if shsize != 40 or not shnum or shstr >= shnum:
            raise ValueError(f"{name}: unsupported or missing section table")
        self.sections = []
        for i in range(shnum):
            values = struct.unpack_from("<10I", data, shoff + i * shsize)
            self.sections.append(dict(zip(
                ("name_offset", "type", "flags", "address", "offset", "size", "link", "info", "align", "entsize"),
                values), index=i))
        strings = self.section_data(self.sections[shstr])
        for section in self.sections:
            section["name"] = self.string(strings, section["name_offset"])
        self.symbols = []
        for section in self.sections:
            if section["type"] != 2:  # SHT_SYMTAB
                continue
            strings = self.section_data(self.sections[section["link"]])
            for offset in range(section["offset"], section["offset"] + section["size"], 16):
                stname, address, size, info, other, shndx = struct.unpack_from("<IIIBBH", data, offset)
                self.symbols.append(dict(name=self.string(strings, stname), address=address, size=size,
                                         type=info & 15, bind=info >> 4, other=other, section=shndx))

    @classmethod
    def read(cls, path):
        return cls(Path(path).read_bytes(), path)

    @staticmethod
    def string(data, offset):
        end = data.find(b"\0", offset)
        if offset >= len(data) or end < 0:
            raise ValueError("bad ELF string offset")
        return data[offset:end].decode("utf-8", errors="replace")

    def section_data(self, section):
        start, size = section["offset"], section["size"]
        if start + size > len(self.data):
            raise ValueError(f"{self.name}: section outside file")
        return self.data[start:start + size]

    def executable(self):
        return [s for s in self.sections
                if s["flags"] & (SHF_ALLOC | SHF_EXECINSTR) == SHF_ALLOC | SHF_EXECINSTR and s["size"] and s["type"] == 1]

    def allocated(self):
        """Sections that occupy memory at run time: code, data and bss."""
        return [s for s in self.sections
                if s["flags"] & SHF_ALLOC and s["size"] and s["type"] in (SHT_PROGBITS, SHT_NOBITS)]

    def halfword(self, address):
        """The 16-bit instruction word at `address` in an executable section,
        trying the P1 alias when the address is a P0/P2/P3 mirror."""
        for candidate in dict.fromkeys((address, (address & 0x1FFFFFFF) | 0x80000000)):
            for section in self.executable():
                if section["address"] <= candidate and candidate + 2 <= section["address"] + section["size"]:
                    return struct.unpack_from("<H", self.data, section["offset"] + candidate - section["address"])[0]
        return None

    def halfwords(self, address, size):
        """(address, halfword) pairs of an executable range, or [] outside the ELF."""
        for section in self.executable():
            if section["address"] <= address and address + size <= section["address"] + section["size"]:
                start = section["offset"] + address - section["address"]
                values = struct.unpack_from(f"<{size // 2}H", self.data, start)
                return [(address + 2 * i, v) for i, v in enumerate(values)]
        return []


def input_elfs(path):
    """Yield (member, Elf) for an object file or every ELF member of an ar archive."""
    data = Path(path).read_bytes()
    if data.startswith(b"\x7fELF"):
        yield "", Elf(data, path)
        return
    if not data.startswith(b"!<arch>\n"):
        raise ValueError(f"{path}: expected an ELF object or an ordinary ar archive (thin archives unsupported)")
    offset, names = 8, b""
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError(f"{path}: malformed archive")
        name = header[:16].decode("ascii").strip()
        size = int(header[48:58])
        body = data[offset + 60:offset + 60 + size]
        if len(body) != size:
            raise ValueError(f"{path}: truncated archive member")
        offset += 60 + size + size % 2
        if name == "//":
            names = body
            continue
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue
        if name.startswith("#1/"):
            length = int(name[3:])
            name, body = body[:length].decode().rstrip("\0"), body[length:]
        elif name.startswith("/"):
            index = int(name[1:])
            end = names.find(b"/\n", index)
            if end < 0:
                raise ValueError(f"{path}: bad archive long name")
            name = names[index:end].decode()
        else:
            name = name.rstrip("/")
        if body.startswith(b"\x7fELF"):
            yield name, Elf(body, f"{path}({name})")
