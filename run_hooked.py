#!/usr/bin/env python3.11
"""
Execute the chall module with hooked eval to capture the flag logic.
This uses Python 3.11 which can properly load c2cext.

Strategy: hook builtins.eval to intercept the decrypted code objects,
then execute the module but intercept the flag check.
"""
import sys, os, importlib, importlib.util, marshal, types, base64
import builtins, dis

CHALL_PYC = "/mnt/c/Users/sq/Desktop/c2c/not-malicious-extension/extracted/chall.pyc"
C2CEXT_SO = "/mnt/c/Users/sq/Desktop/c2c/not-malicious-extension/extracted/c2cext.cpython-311-x86_64-linux-gnu.so"
OUTDIR = "/mnt/c/Users/sq/Desktop/c2c/not-malicious-extension/decrypted/"
os.makedirs(OUTDIR, exist_ok=True)

# Load c2cext
spec = importlib.util.spec_from_file_location("c2cext", C2CEXT_SO)
c2cext = importlib.util.module_from_spec(spec)
sys.modules['c2cext'] = c2cext
spec.loader.exec_module(c2cext)

# Hook eval
_real_eval = builtins.eval
code_objects = []

def hooked_eval(code, *args, **kwargs):
    n = len(code_objects)
    
    if isinstance(code, str):
        # This is evaluated Python source code
        sys.stderr.write(f"[HOOK] eval #{n}: str ({len(code)} chars)\n")
        if len(code) < 500:
            sys.stderr.write(f"  Content: {code[:300]}\n")
        
        # Save to file
        with open(os.path.join(OUTDIR, f"eval_{n}.py"), 'w') as f:
            f.write(code)
            
    elif isinstance(code, types.CodeType):
        sys.stderr.write(f"[HOOK] eval #{n}: code({code.co_name})\n")
    
    result = _real_eval(code, *args, **kwargs)
    code_objects.append((n, code, result))
    
    if isinstance(result, types.CodeType):
        sys.stderr.write(f"[HOOK] eval #{n} -> code({result.co_name})\n")
        
        # Disassemble the result
        disasm_path = os.path.join(OUTDIR, f"disasm_{n}_{result.co_name}.txt")
        with open(disasm_path, 'w') as f:
            old_stdout = sys.stdout
            sys.stdout = f
            try:
                print(f"=== Code: {result.co_name} ===")
                print(f"  filename: {result.co_filename}")
                print(f"  argcount: {result.co_argcount}")
                print(f"  varnames: {result.co_varnames}")
                print(f"  names: {result.co_names}")
                print(f"  consts: {[c if not isinstance(c, types.CodeType) else f'<code {c.co_name}>' for c in result.co_consts]}")
                print()
                dis.dis(result)
                print()
                # Also dump nested code objects
                for c in result.co_consts:
                    if isinstance(c, types.CodeType):
                        print(f"\n  === Nested: {c.co_name} ===")
                        print(f"    varnames: {c.co_varnames}")
                        print(f"    names: {c.co_names}")
                        print(f"    consts: {[x if not isinstance(x, types.CodeType) else f'<code {x.co_name}>' for x in c.co_consts]}")
                        print()
                        dis.dis(c)
            finally:
                sys.stdout = old_stdout
        
        sys.stderr.write(f"  Disassembly saved to {disasm_path}\n")
        
        # Save marshal
        with open(os.path.join(OUTDIR, f"code_{n}_{result.co_name}.marshal"), 'wb') as f:
            f.write(marshal.dumps(result))
    
    return result

builtins.eval = hooked_eval

# Also hook input to provide a test value
_real_input = builtins.input
def hooked_input(prompt=''):
    sys.stderr.write(f"[HOOK] input('{prompt}') -> returning 'C2C{{test}}'\n")
    return 'C2C{test}'
builtins.input = hooked_input

# Also hook print
_real_print = builtins.print
def hooked_print(*args, **kwargs):
    sys.stderr.write(f"[HOOK] print: {args}\n")
    _real_print(*args, **kwargs)
builtins.print = hooked_print

# Now execute chall.pyc
print("[*] Loading and executing chall module...", file=sys.stderr)

with open(CHALL_PYC, "rb") as f:
    pyc_data = f.read()
code = marshal.loads(pyc_data[16:])

# Execute the module code
try:
    exec(code, {'__name__': '__main__', '__builtins__': builtins})
except Exception as e:
    sys.stderr.write(f"[*] Module execution failed: {e}\n")
    import traceback
    traceback.print_exc(file=sys.stderr)

print(f"\n[*] Intercepted {len(code_objects)} eval calls", file=sys.stderr)
print(f"[*] Results saved to {OUTDIR}", file=sys.stderr)
