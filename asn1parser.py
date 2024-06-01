import argparse
import base64

def parse_asn1(data, recursive_octet_string=False):
    def print_data(description, data, index, length=None):
        hex_chunk = ' '.join(f'{b:02x}' for b in data[index:index + (length or 1)])
        ascii_chunk = ''.join(chr(b) if 32 <= b <= 127 else '.' for b in data[index:index + (length or 1)])
        print(f"{description} at index {index}: [0x] {hex_chunk} ({ascii_chunk})")

    def print_tag(tag, tag_number, class_bits, pc_bit, index):
        class_str = ["Universal", "Application", "Context-specific", "Private"][class_bits]
        form_str = ["Primitive", "Constructed"][pc_bit]
        print(f"\nTag 0x{tag:02x} at index {index} [class = {class_str} ({class_bits}), form = {form_str} ({pc_bit}), tag number = {tag_number}]: ", end="")

    def parse_element(data, i):
        tag = data[i]
        class_bits = (tag >> 6) & 0x03
        pc_bit = (tag >> 5) & 0x01
        tag_number = tag & 0x1F

        print_tag(tag, tag_number, class_bits, pc_bit, i)

        if class_bits == 0:  # Universal
            return parse_universal(tag_number, data, i)
        elif class_bits == 1:  # Application
            return read_generic(data, i, "Application")
        elif class_bits == 2:  # Context-specific
            return read_generic(data, i, "Context-specific")
        elif class_bits == 3:  # Private
            return read_generic(data, i, "Private")

    def parse_universal(tag_number, data, i):
        if tag_number == 0x01:  # BOOLEAN
            return read_boolean(data, i)
        elif tag_number == 0x02:  # INTEGER
            return read_integer(data, i)
        elif tag_number == 0x03:  # BIT STRING
            return read_string(data, i, "BitString")
        elif tag_number == 0x04:  # OCTET STRING
            return read_octet_string(data, i)
        elif tag_number == 0x05:  # NULL
            return read_null(data, i)
        elif tag_number == 0x06:  # OBJECT IDENTIFIER
            return read_generic(data, i, "ObjectIdentifier")
        elif tag_number == 0x07:  # ObjectDescriptor
            return read_generic(data, i, "ObjectDescriptor")
        elif tag_number == 0x08:  # EXTERNAL
            return read_external(data, i)
        elif tag_number == 0x09:  # REAL
            return read_generic(data, i, "Real")
        elif tag_number == 0x0A:  # ENUMERATED
            return read_integer(data, i)
        elif tag_number == 0x0B:  # EMBEDDED PDV
            return read_embedded_pdv(data, i)
        elif tag_number == 0x0C:  # UTF8String
            return read_string(data, i, "Utf8String", 'utf-8')
        elif tag_number == 0x10:  # SEQUENCE and SEQUENCE OF
            return read_sequence(data, i)
        elif tag_number == 0x11:  # SET and SET OF
            return read_set(data, i)
        elif tag_number == 0x12:  # NumericString
            return read_string(data, i, "NumericString", 'ascii')
        elif tag_number == 0x13:  # PrintableString
            return read_string(data, i, "PrintableString", 'ascii')
        elif tag_number == 0x14:  # TIME
            return read_generic(data, i, "Time")
        elif tag_number == 0x16:  # IA5String
            return read_string(data, i, "IA5String", 'ascii')
        elif tag_number == 0x17:  # UTCTime
            return read_string(data, i, "UTCTime", 'ascii')
        elif tag_number == 0x18:  # GeneralizedTime
            return read_string(data, i, "GeneralizedTime", 'ascii')
        elif tag_number == 0x19:  # GraphicString
            return read_string(data, i, "GraphicString", 'ascii')
        elif tag_number == 0x1A:  # VisibleString
            return read_string(data, i, "VisibleString", 'ascii')
        elif tag_number == 0x1B:  # GeneralString
            return read_string(data, i, "GeneralString", 'ascii')
        elif tag_number == 0x1C:  # UniversalString
            return read_string(data, i, "UniversalString", 'utf-32-be')
        elif tag_number == 0x1D:  # CHARACTER STRING
            return read_generic(data, i, "CharacterString")
        elif tag_number == 0x1E:  # BMPString
            return read_string(data, i, "BMPString", 'utf-16-be')
        elif tag_number == 0x1F:  # DATE
            return read_generic(data, i, "Date")
        elif tag_number == 0x20:  # TIME-OF-DAY
            return read_generic(data, i, "TimeOfDay")
        elif tag_number == 0x21:  # DATE-TIME
            return read_generic(data, i, "DateTime")
        elif tag_number == 0x22:  # DURATION
            return read_generic(data, i, "Duration")
        elif tag_number == 0x23:  # TeletexString, T61String
            return read_string(data, i, "TeletexString", 'ascii')
        elif tag_number == 0x24:  # VideotexString
            return read_string(data, i, "VideotexString", 'ascii')
        elif tag_number == 0x25:  # GraphicString
            return read_string(data, i, "GraphicString", 'ascii')
        elif tag_number == 0x26:  # VisibleString
            return read_string(data, i, "VisibleString", 'ascii')
        elif tag_number == 0x27:  # GeneralString
            return read_string(data, i, "GeneralString", 'ascii')
        elif tag_number == 0x28:  # UniversalString
            return read_string(data, i, "UniversalString", 'utf-32-be')
        elif tag_number == 0x29:  # CHARACTER STRING
            return read_generic(data, i, "CharacterString")
        elif tag_number == 0x2A:  # RELATIVE-OID
            return read_generic(data, i, "RelativeOID")
        elif tag_number == 0x80:  # CHOICE (constructed context-specific tag)
            return read_choice(data, i)
        else:
            print(f"Unexpected universal tag number: 0x{tag_number:02x} at index {i} (skipping)")
            return None, i + 1  # Skip invalid byte and continue

    def read_length(data, i):
        if i >= len(data):
            print(f"\nReached end of data while reading length at index {i}.")
            return 0, i + 1
        length = data[i]
        print_data("Length byte", data, i)
        i += 1
        if length & 0x80:  # Long form
            num_bytes = length & 0x7F
            length = 0
            if i + num_bytes > len(data):
                print(f"\nReached end of data while reading long form length at index {i}.")
                return 0, i + num_bytes
            print_data(f"  Long form length ({num_bytes} bytes)", data, i, num_bytes)
            for _ in range(num_bytes):
                length = (length << 8) | data[i]
                i += 1
        print(f"  Length: {length}")
        return length, i

    def read_generic(data, i, tag_name):
        print(f"{tag_name} tag")
        i += 1
        length, i = read_length(data, i)
        end_index = i + length
        if end_index > len(data):
            print(f"\nReached end of data while reading {tag_name} tag value at index {i}. Returning available data.")
            end_index = len(data)
        print_data(f"{tag_name} value", data, i, length)
        value = data[i:end_index]
        i += length
        return (tag_name, value), i

    def read_boolean(data, i):
        (tag_name, value), new_i = read_generic(data, i, "Boolean")
        value = value[0] != 0 if len(value) > 0 else None
        return (tag_name, value), new_i

    def read_integer(data, i):
        (tag_name, value), new_i = read_generic(data, i, "Integer")
        value = int.from_bytes(value, byteorder='big') if len(value) > 0 else None
        return (tag_name, value), new_i

    def read_string(data, i, tag_name, encoding=None):
        (tag_name, value), new_i = read_generic(data, i, tag_name)
        if encoding is not None:
            try:
                value = value.decode(encoding)
            except UnicodeDecodeError as e:
                print(f"Warning: Invalid {tag_name} string at index {i} (skipping): {e}")
        return (tag_name, value), new_i

    def read_octet_string(data, i):
        (tag_name, value), new_i = read_generic(data, i, "OctetString")
        if recursive_octet_string:
            print(f"Attempting to parse {tag_name} value as ASN.1:")
            nested_items = parse_asn1(value, recursive_octet_string=True)
            return (tag_name, nested_items), new_i
        return (tag_name, value), new_i

    def read_null(data, i):
        print("NULL tag")
        i += 1
        length, i = read_length(data, i)
        if length != 0:
            print(f"Warning: Expected length 0, got {length} at index {i} (skipping length bytes)")
            i += length
        return ("NULL", None), i

    def read_sequence(data, i):
        print("SEQUENCE tag")
        i += 1
        length, i = read_length(data, i)
        print_data("SEQUENCE content", data, i, length)
        end = i + length
        items = []
        while i < end:
            item, new_i = parse_element(data, i)
            if item is not None:
                items.append(item)
            i = new_i
        return ("SEQUENCE", items), i

    def read_set(data, i):
        print("SET tag")
        i += 1
        length, i = read_length(data, i)
        print_data("SET content", data, i, length)
        end = i + length
        items = []
        while i < end:
            item, new_i = parse_element(data, i)
            if item is not None:
                items.append(item)
            i = new_i
        return ("SET", items), i

    def read_choice(data, i):
        print("CHOICE tag")
        i += 1
        length, i = read_length(data, i)
        print_data("CHOICE value", data, i, length)
        value = data[i:i + length]
        i += length
        return ("CHOICE", value), i

    def read_embedded_pdv(data, i):
        print("EMBEDDED PDV tag")
        i += 1
        length, i = read_length(data, i)
        print_data("EMBEDDED PDV value", data, i, length)
        value = data[i:i + length]
        i += length
        return ("EMBEDDED PDV", value), i

    def read_external(data, i):
        print("EXTERNAL tag")
        i += 1
        length, i = read_length(data, i)
        print_data("EXTERNAL value", data, i, length)
        value = data[i:i + length]
        i += length
        return ("EXTERNAL", value), i

    # Handle data
    print_data("Initial data", data, 0, 16)
    items = []
    i = 0
    while i < len(data):
        item, new_i = parse_element(data, i)
        if item is not None:
            items.append(item)
        i = new_i
    return items

def print_asn1_structure(items, indent=0):
    for idx, item in enumerate(items):
        if isinstance(item[1], list):
            print(" " * indent + f"Item {idx}: {item[0]}")
            print_asn1_structure(item[1], indent + 2)
        else:
            print(" " * indent + f"Item {idx}: {item[0]} - {item[1]}")

# Load the data and parse it
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse ASN.1 file or content and optionally base64 decode the content.')
    parser.add_argument('-f', '--file_path', type=str, help='Path to the ASN.1 file.')
    parser.add_argument('-c', '--content', type=str, help='ASN.1 content directly as a string.')
    parser.add_argument('-b', '--base64', action='store_true', help='Base64 decode the content.')
    parser.add_argument('-r', '--recursive_octet_string', action='store_true', help='Recursively parse OCTET STRING content as ASN.1.')

    args = parser.parse_args()

    if args.file_path is None and args.content is None:
        parser.error('No action requested, add --file_path or --content')

    if args.content is not None:
        file_content = args.content.encode()
    else:
        with open(args.file_path, 'rb') as f:
            file_content = f.read()

    if args.base64:
        decoded_data = base64.b64decode(file_content)
    else:
        decoded_data = file_content

    # Parse the ASN.1 structure
    asn1_items = parse_asn1(decoded_data, recursive_octet_string=args.recursive_octet_string)
    if asn1_items:
        print("\nParsed ASN.1 structure:")
        print_asn1_structure(asn1_items)
    else:
        print("\nFailed to parse ASN.1 structure")
