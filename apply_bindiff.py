import idaapi
import idc
import re
import csv
import os

def sanitize_name(name: str) -> str:
    """
    Clean and format a C++ symbol into an IDA-compatible function name.
    """
    # Handle destructor pattern: Class::~Class()
    destructor_match = re.match(r"(?P<class>\w+)::~\1\s*\(\)", name)
    if destructor_match:
        return f"{destructor_match.group('class')}_destructor"

    # Remove parameter list: e.g., func(int, char) → func
    name = re.sub(r'\(.*?\)', '', name)

    # Remove template parameters: e.g., vector<int> → vector
    name = re.sub(r'<.*?>', '', name)

    # Replace C++ scope resolution
    name = name.replace("::", "_")

    # Replace pointer/reference notation
    name = name.replace("*", "ptr").replace("&", "ref")

    # Remove whitespace
    name = name.strip()

    # Replace any remaining invalid characters with underscores
    name = re.sub(r'[^a-zA-Z0-9_]', '_', name)

    # Condense multiple underscores
    name = re.sub(r'__+', '_', name)

    return name.strip('_')

# Ask user to select input file
filename = idaapi.ask_file(False, "*.txt", "Select BinDiff Match File")
if not filename:
    print("No file selected.")
else:
    log_file = os.path.splitext(filename)[0] + "_renamed_log.csv"
    renamed_count = 0
    skipped_count = 0
    failed_count = 0

    with open(filename, 'r') as f, open(log_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Address", "Original Name", "New Name", "Full Symbol"])

        for line in f:
            if line.strip() == "" or line.startswith("#"):
                continue

            parts = line.strip().split("\t")
            if len(parts) < 7:
                continue

            try:
                primary_ea = int(parts[3], 16)
                old_name = parts[4]
                raw_new_name = parts[6]

                sanitized_name = sanitize_name(raw_new_name)

                # Skip if sanitized name is a reserved auto-name
                if re.match(r'^(sub|loc|off)_[0-9A-Fa-f]+$', sanitized_name):
                    print(f"[!] Skipping reserved auto-name: {sanitized_name}")
                    skipped_count += 1
                    continue

                current_name = idc.get_name(primary_ea)

                if current_name.startswith("sub_") or current_name == "":
                    success = idc.set_name(primary_ea, sanitized_name, idc.SN_CHECK)
                    if success:
                        comment = f"Renamed by BinDiff: originally '{old_name}', matched symbol: '{raw_new_name}'"
                        idc.set_func_cmt(primary_ea, comment, 0)
                        csv_writer.writerow([hex(primary_ea), old_name, sanitized_name, raw_new_name])
                        print(f"[✓] {hex(primary_ea)}: {old_name} → {sanitized_name}")
                        renamed_count += 1
                    else:
                        print(f"[!] Failed to rename {hex(primary_ea)} to '{sanitized_name}' (conflict or reserved?)")
                        failed_count += 1
                else:
                    print(f"[=] Skipped {hex(primary_ea)} ({current_name}), already renamed")
                    skipped_count += 1

            except Exception as e:
                print(f"[!] Error processing line: {line.strip()} - {str(e)}")
                failed_count += 1

    print(f"\nSummary:")
    print(f"✔ Renamed: {renamed_count}")
    print(f"✘ Failed : {failed_count}")
    print(f"⏭ Skipped: {skipped_count}")
    print(f"📄 Log written to: {log_file}")
