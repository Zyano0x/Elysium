import pefile

def get_export_address(pe_path, export_name):
    pe = pefile.PE(pe_path)

    # Check if the PE file has an export table
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        # Loop through the export symbols
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # Decode the name and check if it matches the requested export name
            if export.name and export.name.decode().lower() == export_name.lower():
                # Yes? Return an export object then
                return export
        raise ValueError(f"[!] Export '{export_name}' not found in {pe_path}")
    else:
        raise ValueError(f"[!] No export table found in {pe_path}")