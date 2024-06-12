from Crypto.Cipher import AES, DES, ARC4, Blowfish
from idaapi import decompile, get_bytes, patch_bytes
from ida_funcs import add_func
import ida_hexrays
import ida_bytes
import idaapi
import idc

def decrypt_aes(data, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(data)

def decrypt_des(data, key, iv):
    des = DES.new(key, DES.MODE_CBC, iv)
    return des.decrypt(data)

def decrypt_blowfish(data, key, iv):
    blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return blowfish.decrypt(data)

def decrypt_arc4(data, key, iv):
    arc4 = ARC4.new(key)
    return arc4.decrypt(data)

def decrypt_xor(data, key, iv):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

function_table = {
    0x1800: (decrypt_aes, 32, 16),
    0x1C00: (decrypt_aes, 24, 16),
    0x2000: (decrypt_aes, 16, 16),
    0x2400: (decrypt_des, 8, 8),
    0x2800: (decrypt_blowfish, 16, 8),
    0x2C00: (decrypt_arc4, 16, 0),
    0x3000: (decrypt_xor, 16, 0)
}

def reanalyze_range(start_ea, end_ea):
    idc.del_items(start_ea, idc.DELIT_EXPAND, end_ea - start_ea)
    ea = start_ea
    while ea < end_ea:
        if idc.create_insn(ea):
            ea = idc.next_head(ea)
        else:
            ea += 1


def decrypt_data_and_create_function(ea, func, key, iv=b''):
    data = get_bytes(ea, 0x400)
    decrypted_data = func(data, key, iv)
    patch_bytes(ea, decrypted_data)
    reanalyze_range(ea, 0x400+ea)
    idaapi.auto_wait()
    add_func(ea)
    return ea

def get_word_length(x):
    t = x.type.dstr()
    if '[' not in t and '*' not in t:
        return 1
    if '[' in t: t = t.split('[')[0]
    if '64' in t or 'QWORD' in t:
        return 8
    elif '32' in t or 'DWORD' in t:
        return 4
    elif '16' in t or 'WORD' in t:
        return 2
    else:
        return 1


def get_expr_value(expr):
    if expr.op == ida_hexrays.cot_num:
        return expr.n.value
    elif expr.op == ida_hexrays.cot_obj:
        return expr.obj_ea
    elif expr.op == ida_hexrays.cot_var:
        return expr.v.idx
    elif expr.op == ida_hexrays.cot_call:
        return f"call to {idaapi.get_name(expr.x.obj_ea)}"
    elif expr.op == ida_hexrays.cot_ref:
        return get_expr_value(expr.x)
    elif expr.op == ida_hexrays.cot_cast:
        return get_expr_value(expr.x)
    elif expr.op == ida_hexrays.cot_add:
        x = get_expr_value(expr.x)
        return x + expr.y.n._value * get_word_length(expr.x)
    elif expr.op == ida_hexrays.cot_sub:
        x = get_expr_value(expr.x)
        return x - expr.y.n._value * get_word_length(expr.x)
    elif expr.op == ida_hexrays.cot_idx:
        x = get_expr_value(expr.x)
        return x + expr.y.n._value * get_word_length(expr.x)
    # 处理更多的表达式类型
    else:
        print(f"Unsupported expression type: {expr.opname}")
        return str(expr)
    
def process_function(ea, path=''):
    idaapi.auto_wait()
    cfunc = decompile(ea)
    print(f"Decompiled function at {hex(ea)}")
    print(cfunc)
    if "Correct" in f"{cfunc}":
        print(path)
        exit()
    if "Wrong" in f"{cfunc}":
        return
    cinsn = cfunc.body
    assert cinsn.op == ida_hexrays.cit_block, "Not a block instruction"
    scanf_expr = cinsn.cblock[0].cexpr
    assert scanf_expr.op == ida_hexrays.cot_call, "Not a call instruction"
    format_str_addr = get_expr_value(scanf_expr.a[0])
    print(f"function name: {idaapi.get_name(scanf_expr.x.obj_ea)}")
    print(f"Format string address: {hex(format_str_addr)}")
    format_str = get_bytes(format_str_addr, 4)
    format_str = format_str.strip(b'\x00')
    input_length = int(format_str[1:-1].decode())

    if_block = cinsn.cblock[1]
    cases = []
    j = 1
    for i in range(6):
        assert if_block.op == ida_hexrays.cit_if, f"Iteration {i}: Not an if instruction {if_block.opname}"
        if_block = if_block.cif
        cond_expr = if_block.expr
        then_expr = if_block.ithen
        cases.append((cond_expr, then_expr))
        if if_block.ielse is None or if_block.ielse.op != ida_hexrays.cit_block:
            print(f"Iteration {i}: No else block")
            # print(f"{then_expr.opname}")
            # print(f"{then_expr.cblock[0].cexpr.opname}")
            # if then_expr.op == ida_hexrays.cit_block and then_expr.cblock[0].op == ida_hexrays.cit_if:
            #     print(f"Iteration {i}: Nested if")
            #     if_block = then_expr.cblock[0]
            #     cinsn = then_expr
            #     j = 0
            # else:
            if_block = cinsn.cblock[j+1]
            j += 1
        else:
            if len(if_block.ielse.cblock) > 1:
                cinsn = if_block.ielse
                j = 0
            if_block = if_block.ielse.cblock[0]

    for cond_expr, then_expr in cases:
        assert cond_expr.op == ida_hexrays.cot_lnot, f"{cond_expr.opname}: Not a negation expression"
        strncmp_expr = cond_expr.x
        assert strncmp_expr.op == ida_hexrays.cot_call, "Not a call instruction"
        cmp_str_addr = get_expr_value(strncmp_expr.a[1])
        cmp_str = get_bytes(cmp_str_addr, input_length).decode()

        assert then_expr.op == ida_hexrays.cit_block, "Not a block instruction"
        decrypt_expr = then_expr.cblock[0].cexpr
        assert decrypt_expr.op == ida_hexrays.cot_call, "Not a call instruction"
        call_function_addr = get_expr_value(decrypt_expr.a[0])
        decrypt_function_addr = decrypt_expr.x.obj_ea
        if decrypt_function_addr not in function_table:
            print(f"Unsupported decryption function at {hex(decrypt_function_addr)}")
            print(f"{hex(call_function_addr)}")

        func, keylen, ivlen = function_table[decrypt_function_addr]
        key = get_bytes(get_expr_value(decrypt_expr.a[1]), keylen)
        if ivlen > 0:
            iv = get_bytes(get_expr_value(decrypt_expr.a[2]), ivlen)
        else:
            iv = b''
        decrypt_data_and_create_function(call_function_addr, func, key, iv)

        process_function(call_function_addr, path + cmp_str)

    for stmt in cinsn.cblock:
        print(stmt.opname)

start_addr = 0x187C00
idc.del_items(0x3400, idc.DELIT_EXPAND, start_addr - 0x3400)
for key in function_table:
    idaapi.auto_wait()
    decompile(key)
process_function(start_addr)
