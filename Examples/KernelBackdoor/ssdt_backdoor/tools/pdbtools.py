import struct
import ctypes
import uuid
import pefile
import urllib.request
import os
from collections import namedtuple

class S_PUB32_Record(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Offset", ctypes.c_uint32),
        ("Section", ctypes.c_uint16),
    ]
    
SymbolInfo = namedtuple('SymbolInfo', ['name', 'section_index', 'section_offset', 'flags'])
    
def get_public_symbol(pdb_path, symbol_name):
    # Open pdb file
    with open(pdb_path, "rb") as f:
        data = f.read()

    # Search for the symbol string
    name_bytes = symbol_name if isinstance(symbol_name, bytes) else symbol_name.encode()
    index = data.find(name_bytes)
    # Is it found something?
    if index == -1:
        # Not? Raise an exception
        raise ValueError(f"[!] Symbol '{symbol_name.decode()}' not found in PDB")
    
    # Calculate record start
    record_start = index - ctypes.sizeof(S_PUB32_Record)
    # Get record bytes without the name
    record_bytes = data[record_start : index]
    # Parse the record
    record = S_PUB32_Record.from_buffer_copy(record_bytes)

    return SymbolInfo(
        name=symbol_name,
        section_index=record.Section,
        section_offset=record.Offset,
        flags=record.Flags
    )

def download_file_pdb(file_path):
    # Open PE file
    pe = pefile.PE(file_path)

    # PE have debug dir?
    if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        # No? Return exception
        raise ValueError(f"[!] No debug data found in {file_path}")

    # Parse PDB directory
    pdb_path = None
    for entry in pe.DIRECTORY_ENTRY_DEBUG:
        # Is it CV entry?
        if entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            data = entry.entry
            data_bytes = data.__pack__()

            # Check CVSig
            if data_bytes[:4] == b'RSDS':
                # Get signature bytes
                guid_bytes = data_bytes[4:20]
                # Get Age value
                age = struct.unpack("<I", data_bytes[20:24])[0]
                # Get PDB file name
                pdb_path = data_bytes[24:].split(b'\x00')[0].decode(errors="ignore")
                # Convert signature to guid
                guid_obj = uuid.UUID(bytes_le=guid_bytes)
                guid_str = guid_obj.hex.upper()
                break

    # We found pdb info?
    if not pdb_path:
        # No? Abort!
        raise ValueError(f"[!] No CodeView PDB info found in {file_path}")

    # Craft pdb url
    pdb_url = f"https://msdl.microsoft.com/download/symbols/{os.path.basename(pdb_path)}/{guid_str}{age:X}/{os.path.basename(pdb_path)}"
    
    # Download pdb
    print(f"[*] Downloading PDB from {pdb_url}...")
    urllib.request.urlretrieve(pdb_url, pdb_path)
    print("[+] Download complete")
    
    return pdb_path

def get_symbol_file_offset(file_path, symbol_info):
    # Load the PE file
    pe = pefile.PE(file_path)
    
    # Check if the section index is valid.
    if symbol_info.section_index < 1 or symbol_info.section_index > len(pe.sections):
        raise ValueError(f"[!] Invalid section index {symbol_info.section_index}. File has {len(pe.sections)} sections.")
    
    # Get the corresponding section 
    section = pe.sections[symbol_info.section_index - 1]

    # Calculate file offset
    file_offset = section.PointerToRawData + (symbol_info.section_offset)
    return file_offset