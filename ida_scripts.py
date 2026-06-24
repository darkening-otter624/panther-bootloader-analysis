"""
IDA Pro Python scripts for Meta Quest 3S ABL research
Target: LinuxLoader (extracted from abl_a partition, firmware v79)
Architecture: ARM64 PE32+
"""

import idc
import idautils
import idaapi


def find_der_certs(min_size=100):
    """Find embedded DER encoded certificates or public keys."""
    print("[*] Searching for DER blobs (0x30 0x82 header)...")
    for seg in idautils.Segments():
        ea = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        while ea < end:
            b0 = idc.get_wide_byte(ea)
            b1 = idc.get_wide_byte(ea + 1)
            if b0 == 0x30 and b1 == 0x82:
                size = (idc.get_wide_byte(ea + 2) << 8) | idc.get_wide_byte(ea + 3)
                if size > min_size:
                    print(f"  DER blob @ 0x{ea:X}, payload size: {size} bytes, total: {size+4}")
                    for xref in idautils.XrefsTo(ea):
                        func = idaapi.get_func(xref.frm)
                        if func:
                            print(f"    xref: {idc.get_func_name(func.start_ea)} @ 0x{func.start_ea:X}")
            ea += 1


def find_auth_functions():
    """Find functions referencing unlock/auth/token related strings."""
    print("[*] Searching for unlock/auth related strings and their referencing functions...")
    keywords = [b'unlock', b'token', b'verify', b'sign', b'auth', b'flashing']
    for s in idautils.Strings():
        content = str(s)
        if any(k.decode() in content.lower() for k in keywords):
            print(f"  0x{s.ea:X}: {content}")
            for xref in idautils.XrefsTo(s.ea):
                func = idaapi.get_func(xref.frm)
                if func:
                    print(f"    in: {idc.get_func_name(func.start_ea)} @ 0x{func.start_ea:X}")


def dump_meta_pubkey(output_path='/tmp/meta_unlock_pubkey.der'):
    """Dump Meta's embedded RSA public key from the ABL."""
    ea = 0xA85B3  # offset in LinuxLoader, firmware v79
    b2 = idc.get_wide_byte(ea + 2)
    b3 = idc.get_wide_byte(ea + 3)
    size = (b2 << 8) | b3
    total = size + 4
    data = bytes([idc.get_wide_byte(ea + i) for i in range(total)])
    with open(output_path, 'wb') as f:
        f.write(data)
    print(f"[+] Dumped {total} bytes to {output_path}")
    print(f"[+] First bytes: {data[:8].hex()}")
    print(f"[*] Inspect with: openssl pkey -in {output_path} -inform DER -text -noout -pubin")


def find_padding_constants_in_functions(func_addrs):
    """
    Find RSA padding mode constants within specific functions.
    RSA_PKCS1_PADDING = 1
    RSA_NO_PADDING = 3
    RSA_PKCS1_PSS_PADDING = 6
    """
    padding_names = {1: 'PKCS1v1.5', 3: 'NO_PADDING', 6: 'PSS'}
    for func_ea in func_addrs:
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        print(f"\n[*] {idc.get_func_name(func_ea)} @ 0x{func_ea:X}")
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for i in range(4):
                op = idc.get_operand_value(head, i)
                if op in padding_names:
                    mnem = idc.print_insn_mnem(head)
                    if mnem in ['MOV', 'MOVZ', 'BL']:
                        print(f"  0x{head:X}: {mnem} value={op} ({padding_names[op]})")


def trace_calls(start_ea, depth=0, max_depth=8, visited=None):
    """Recursively trace call graph from a starting function."""
    if visited is None:
        visited = set()
    if depth > max_depth or start_ea in visited:
        return
    visited.add(start_ea)
    name = idc.get_func_name(start_ea)
    print("  " * depth + f"-> {name} @ 0x{start_ea:X}")
    func = idaapi.get_func(start_ea)
    if func:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            s = idc.get_strlit_contents(idc.get_operand_value(head, 1), -1, idc.STRTYPE_C)
            if s and any(k in s.lower() for k in [b'unlock', b'token', b'verify', b'sign', b'auth']):
                print("  " * depth + f"   [STR] {s}")
            if idc.print_insn_mnem(head) == 'BL':
                callee = idc.get_operand_value(head, 0)
                trace_calls(callee, depth + 1, max_depth, visited)


# Known function map (firmware v79, panther/Quest 3S)
KNOWN_FUNCTIONS = {
    0x64734: 'VerifyUnlockToken',
    0x66878: 'PKCS7Verify',
    0x678CC: 'LoadTrustedKey',
    0x5C9BC: 'FastbootOemUnlockHandler',
    0x5B738: 'CheckUnlockAllowed',
    0x64F84: 'ParseBootloaderScript',
    0x63570: 'DoUnlock',
    0x3F23C: 'IsDeviceUnlocked',       # returns dword_DB5A8 & 1
    0x3F24C: 'IsDeviceCriticalUnlocked',
    0x408E4: 'SetUnlockValue',
    0x409F4: 'SetUnlockCriticalValue',
    0x5E458: 'PrintDeviceInfo',
}

META_PUBKEY_OFFSET = 0xA85B3  # in LinuxLoader
UNLOCK_STATE_GLOBAL = 0xDB5A8  # dword_DB5A8, bit0=unlocked, bit1=critical_unlocked


if __name__ == '__main__':
    print("Quest 3S ABL Research Scripts")
    print("Firmware: v79 | Device: panther (Quest 3S)")
    print("=" * 50)
