import argparse
import base64

OID_NAMES = {
    '1.2.840.10040.4.1': 'DSA',
    '1.2.840.10040.4.3': 'DSA with SHA-1',
    '1.2.840.10045.2.1': 'EC Public Key',
    '1.2.840.10045.4.1': 'ECDSA with SHA-1',
    '1.2.840.10045.4.3.2': 'ECDSA with SHA-256',
    '1.2.840.10045.4.3.3': 'ECDSA with SHA-384',
    '1.2.840.10045.4.3.4': 'ECDSA with SHA-512',
    '1.2.840.113549.1.1.1': 'RSA Encryption',
    '1.2.840.113549.1.1.2': 'MD2 with RSA Encryption',
    '1.2.840.113549.1.1.3': 'MD4 with RSA Encryption',
    '1.2.840.113549.1.1.4': 'MD5 with RSA Encryption',
    '1.2.840.113549.1.1.5': 'SHA-1 with RSA Encryption',
    '1.2.840.113549.1.1.11': 'SHA-256 with RSA Encryption',
    '1.2.840.113549.1.1.12': 'SHA-384 with RSA Encryption',
    '1.2.840.113549.1.1.13': 'SHA-512 with RSA Encryption',
    '1.2.840.113549.1.1.14': 'SHA-224 with RSA Encryption',
    '1.2.840.113549.1.7.1': 'PKCS #7 Data',
    '1.2.840.113549.1.7.2': 'PKCS #7 Signed Data',
    '1.2.840.113549.1.7.3': 'PKCS #7 Enveloped Data',
    '1.2.840.113549.1.7.4': 'PKCS #7 Signed and Enveloped Data',
    '1.2.840.113549.1.7.5': 'PKCS #7 Digested Data',
    '1.2.840.113549.1.7.6': 'PKCS #7 Encrypted Data',
    '1.2.840.113549.1.9.1': 'Email Address',
    '1.2.840.113549.1.9.2': 'Unstructured Name',
    '1.2.840.113549.1.9.3': 'Content Type',
    '1.2.840.113549.1.9.4': 'Message Digest',
    '1.2.840.113549.1.9.5': 'Signing Time',
    '1.2.840.113549.1.9.6': 'Counter Signature',
    '1.2.840.113549.1.9.7': 'Challenge Password',
    '1.2.840.113549.1.9.8': 'Unstructured Address',
    '1.2.840.113549.1.9.14': 'Extension Request',

    '1.3.6.1.2.1.1.1': 'System Description (sysDescr)',
    '1.3.6.1.2.1.1.2': 'System Object ID (sysObjectID)',
    '1.3.6.1.2.1.1.3': 'System Uptime (sysUpTime)',
    '1.3.6.1.2.1.1.4': 'System Contact (sysContact)',
    '1.3.6.1.2.1.1.5': 'System Name (sysName)',
    '1.3.6.1.2.1.1.6': 'System Location (sysLocation)',
    '1.3.6.1.2.1.1.7': 'System Services (sysServices)',

    '2.5.4.3': 'Common Name (CN)',
    '2.5.4.5': 'Serial Number',
    '2.5.4.6': 'Country Name (C)',
    '2.5.4.7': 'Locality Name (L)',
    '2.5.4.8': 'State or Province Name (ST)',
    '2.5.4.9': 'Street Address',
    '2.5.4.10': 'Organization Name (O)',
    '2.5.4.11': 'Organizational Unit Name (OU)',
    '2.5.4.12': 'Title',
    '2.5.4.13': 'Description',
    '2.5.4.15': 'Business Category',
    '2.5.4.17': 'Postal Code',
    '2.5.4.42': 'Given Name',
    '2.5.4.43': 'Initials',
    '2.5.4.44': 'Generation Qualifier',
    '2.5.4.45': 'Unique Identifier',
    '2.5.4.46': 'DN Qualifier',
    '2.5.4.65': 'Pseudonym',
    '2.5.29.17': 'Subject Alternative Name (SAN)',
    '2.5.29.19': 'Basic Constraints (basicConstraints)',
    '2.16.840.1.113730.1.1': 'Netscape Cert Type',
    '2.16.840.1.113730.1.2': 'Netscape Base URL',
    '2.16.840.1.113730.1.3': 'Netscape Revocation URL',
    '2.16.840.1.113730.1.4': 'Netscape CA Revocation URL',
    '2.16.840.1.113730.1.7': 'Netscape Cert Renewal URL',
    '2.16.840.1.113730.1.8': 'Netscape CA Policy URL',
    '2.16.840.1.113730.1.12': 'Netscape SSL Server Name',
    '2.16.840.1.113730.1.13': 'Netscape Cert Sequence',
    '2.23.140.1.1': 'Extended Validation Certificates',

    '42.134.72.134.247.13.1.1.11': 'SHA-256 with RSA Signature (SHA256 RSA SIG)',
    '42.134.72.134.247.13.1.1.1': 'RSA Key Algorithm (RSA KEY ALG)',
}

OID_REPLACEMENTS = {
    '42': '1.2',
    '43': '1.3',
    '85': '2.5',
}

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
            return parse_universal(tag_number, pc_bit, data, i)
        elif class_bits == 1:  # Application
            return read_generic(data, i, f"Application ({tag_number})")
        elif class_bits == 2:  # Context-specific
            return parse_context_specific(tag_number, pc_bit, data, i)
        elif class_bits == 3:  # Private
            return read_generic(data, i, f"Private ({tag_number})")

    def parse_universal(tag_number, pc_bit, data, i):
        if tag_number == 0x01:  # BOOLEAN
            return read_boolean(data, i)
        elif tag_number == 0x02:  # INTEGER
            return read_integer(data, i)
        elif tag_number == 0x03:  # BIT STRING
            if pc_bit:  # Constructed
                return read_constructed(data, i, "BitString")
            else:
                return read_string(data, i, "BitString")
        elif tag_number == 0x04:  # OCTET STRING
            if pc_bit:  # Constructed
                return read_constructed(data, i, "OctetString")
            else:
                return read_octet_string(data, i)
        elif tag_number == 0x05:  # NULL
            return read_null(data, i)
        elif tag_number == 0x06:  # OBJECT IDENTIFIER
            return read_object_identifier(data, i)
        elif tag_number == 0x07:  # ObjectDescriptor
            return read_constructed(data, i, "ObjectDescriptor")
        elif tag_number == 0x08:  # EXTERNAL
            return read_constructed(data, i, "External")
        elif tag_number == 0x09:  # REAL
            return read_constructed(data, i, "Real")
        elif tag_number == 0x0A:  # ENUMERATED
            return read_integer(data, i)
        elif tag_number == 0x0B:  # EMBEDDED PDV
            return read_constructed(data, i, "Embedded PDV")
        elif tag_number == 0x0C:  # UTF8String
            return read_string(data, i, "Utf8String", 'utf-8')
        elif tag_number == 0x10:  # SEQUENCE and SEQUENCE OF
            return read_constructed(data, i, "Sequence")
        elif tag_number == 0x11:  # SET and SET OF
            return read_constructed(data, i, "Set")
        elif tag_number == 0x12:  # NumericString
            return read_string(data, i, "NumericString", 'ascii')
        elif tag_number == 0x13:  # PrintableString
            return read_string(data, i, "PrintableString", 'ascii')
        elif tag_number == 0x14:  # TIME
            return read_constructed(data, i, "Time")
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
            return read_constructed(data, i, "CharacterString")
        elif tag_number == 0x1E:  # BMPString
            return read_string(data, i, "BMPString", 'utf-16-be')
        elif tag_number == 0x1F:  # DATE
            return read_constructed(data, i, "Date")
        elif tag_number == 0x20:  # TIME-OF-DAY
            return read_constructed(data, i, "TimeOfDay")
        elif tag_number == 0x21:  # DATE-TIME
            return read_constructed(data, i, "DateTime")
        elif tag_number == 0x22:  # DURATION
            return read_constructed(data, i, "Duration")
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
            return read_constructed(data, i, "CharacterString")
        elif tag_number == 0x2A:  # RELATIVE-OID
            return read_constructed(data, i, "RelativeOID")
        elif tag_number == 0x80:  # CHOICE (constructed context-specific tag)
            return read_constructed(data, i, "CHOICE")
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

    def read_constructed(data, i, tag_name):
        print(f"{tag_name} (Constructed) tag")
        i += 1
        length, i = read_length(data, i)
        end_index = i + length
        if end_index > len(data):
            print(f"\nReached end of data while reading context-specific tag value at index {i}. Returning available data.")
            end_index = len(data)
        items = []
        while i < end_index:
            item, new_i = parse_element(data, i)
            if item is not None:
                items.append(item)
            i = new_i
        return (tag_name, items), i

    def read_null(data, i):
        print("NULL tag")
        i += 1
        length, i = read_length(data, i)
        if length != 0:
            print(f"Warning: Expected length 0, got {length} at index {i}. Ignoring length")
        return ("NULL", None), i

    def read_object_identifier(data, i):
        def get_human_readable_oid(oid):
            if oid in OID_NAMES:
                return OID_NAMES[oid]

            parts = oid.split('.')
            while len(parts) > 0:
                prefix = '.'.join(parts)
                if prefix in OID_REPLACEMENTS:
                    replacement = OID_REPLACEMENTS[prefix]
                    new_oid = oid.replace(prefix, replacement, 1)
                    return get_human_readable_oid(new_oid)
                parts.pop()

            return oid  # Return original OID if no human-readable name is found

        (tag_name, value), new_i = read_generic(data, i, "ObjectIdentifier")
        oid = ".".join(map(str, value))
        human_readable_oid = get_human_readable_oid(oid)
        if human_readable_oid == oid:
            return (tag_name, oid), new_i
        else:
            return (tag_name, f"{oid} ({human_readable_oid})"), new_i

    def parse_context_specific(tag_number, pc_bit, data, i):
        print(f"Context-specific tag {tag_number}")
        i += 1
        length, i = read_length(data, i)
        end_index = i + length
        if end_index > len(data):
            print(f"\nReached end of data while reading context-specific tag value at index {i}. Returning available data.")
            end_index = len(data)
        if pc_bit:  # Constructed
            items = []
            while i < end_index:
                item, new_i = parse_element(data, i)
                if item is not None:
                    items.append(item)
                i = new_i
            return (f"Context-specific ({tag_number})", items), i
        else:  # Primitive
            print_data(f"Context-specific ({tag_number}) value", data, i, length)
            value = data[i:end_index]
            i += length
            return (f"Context-specific ({tag_number})", value), i

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
