import argparse
import base64
import re
from typing import Callable, Tuple, Any, Optional

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

# Define the type for the reader functions
ReaderFunction = Callable[[bytes, int, int, str, Optional[str]], Tuple[str, Any, int]]

# Printing helpers

def print_data(description, data, index=0, length=None):
    hex_chunk = ' '.join(f'{b:02x}' for b in data[index:index + (length or 1)])
    ascii_chunk = ''.join(chr(b) if 32 <= b <= 127 else '.' for b in data[index:index + (length or 1)])
    print(f"{description} at index {index}: [0x] {hex_chunk} ({ascii_chunk})")

def print_tag(tag, tag_number, class_bits, pc_bit, index):
    class_str = ["Universal", "Application", "Context-specific", "Private"][class_bits]
    form_str = ["Primitive", "Constructed"][pc_bit]
    print(f"\n0x{tag:02x} at index {index} [class = {class_str} ({class_bits}), form = {form_str} ({pc_bit}), tag number = {tag_number}]: ", end="")

# Length reader

def read_length(data, i):
    if i >= len(data):
        print(f"\nReached end of data while reading length at index {i}.")
        return 0, i + 1
    length = data[i]
    print_data("  Length byte", data, i)
    i += 1
    if length & 0x80:  # Long form
        num_bytes = length & 0x7F
        length = 0
        if i + num_bytes > len(data):
            print(f"\nReached end of data while reading long form length at index {i}.")
            return 0, i + num_bytes
        print_data(f"    Long form length ({num_bytes} bytes)", data, i, num_bytes)
        for _ in range(num_bytes):
            length = (length << 8) | data[i]
            i += 1
    print(f"    Length: {length}")
    return length, i

# Universal tag readers

def read_generic(data, i, pc_bit, tag_name, encoding=None):
    print(f"{tag_name} tag")
    i += 1
    length, i = read_length(data, i)
    end_index = i + length
    if end_index > len(data):
        print(f"\nReached end of data while reading {tag_name} tag value at index {i}. Returning available data.")
        end_index = len(data)
    value = data[i:end_index]
    print_data(f"  Value:", data, i, length)
    
    if pc_bit:
        print(f"Parsing {tag_name} value as ASN.1:")
        nested_items = parse_elements(data, i, end_index)
        return (tag_name, nested_items), end_index
    if encoding:
        try:
            decoded_value = value.decode(encoding)
            print(f"  Decoded value: {decoded_value}")
            return (tag_name, decoded_value), end_index
        except UnicodeDecodeError as e:
            print(f"Invalid {tag_name} string at index {end_index}. Returning as OctetString. Error was: {e}")
    return (tag_name, value), end_index

def read_boolean(data, i, pc_bit, tag_name, encoding=None):
    (tag_name, value), new_i = read_generic(data, i, pc_bit, tag_name)
    value = value[0] != 0 if value else None
    print(f"  Decoded value: {value}")
    return (tag_name, value), new_i

def read_integer(data, i, pc_bit, tag_name, encoding=None):
    (tag_name, value), new_i = read_generic(data, i, pc_bit, tag_name)
    value = int.from_bytes(value, byteorder='big', signed=True) if value else None
    print(f"  Decoded value: {value}")
    return (tag_name, value), new_i

def read_null(data, i, pc_bit, tag_name, encoding=None):
    print(f"{tag_name} tag")
    i += 1
    length, i = read_length(data, i)
    if length != 0:
        print(f"Expected length 0, got {length} at index {i}. Ignoring length.")
    return (tag_name, None), i

def read_object_identifier(data, i, pc_bit, tag_name, encoding=None):
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

    (tag_name, value), new_i = read_generic(data, i, pc_bit, tag_name)
    oid = ".".join(map(str, value))
    human_readable_oid = get_human_readable_oid(oid)
    value = oid if human_readable_oid == oid else f"{human_readable_oid} ({oid})"
    print(f"  Decoded value: {value}")
    return (tag_name, value), new_i

def read_constructed(data, i, pc_bit, tag_name, encoding=None):
    print(f"{tag_name} tag")
    i += 1
    length, i = read_length(data, i)
    end_index = i + length
    if end_index > len(data):
        print(f"\nReached end of data while reading context-specific tag value at index {i}. Returning available data.")
        end_index = len(data)
    items = []
    while i < end_index:
        item, new_i = read_element(data, i)
        if item:
            items.append(item)
        i = new_i
    return (tag_name, items), i

UNIVERSAL_TAGS: dict[int, Tuple[ReaderFunction, str, Optional[str]]] = {
    0x01: (read_boolean, "Boolean"),
    0x02: (read_integer, "Integer"),
    0x03: (read_generic, "BitString"),
    0x04: (read_generic, "OctetString"),
    0x05: (read_null, "NULL"),
    0x06: (read_object_identifier, "ObjectIdentifier"),
    0x07: (read_constructed, "ObjectDescriptor"),
    0x08: (read_constructed, "External"),
    0x09: (read_constructed, "Real"),
    0x0A: (read_integer, "Enumerated"),
    0x0B: (read_constructed, "EmbeddedPDV"),
    0x0C: (read_generic, "UTF8String", 'utf-8'),
    0x10: (read_constructed, "Sequence"),
    0x11: (read_constructed, "Set"),
    0x12: (read_generic, "NumericString", 'ascii'),
    0x13: (read_generic, "PrintableString", 'ascii'),
    0x14: (read_generic, "T61String", 'ascii'),
    0x15: (read_generic, "VideotexString", 'ascii'),
    0x16: (read_generic, "IA5String", 'ascii'),
    0x17: (read_generic, "UTCTime", 'ascii'),
    0x18: (read_generic, "GeneralizedTime", 'ascii'),
    0x19: (read_generic, "GraphicString", 'ascii'),
    0x1A: (read_generic, "VisibleString", 'ascii'),
    0x1B: (read_generic, "GeneralString", 'ascii'),
    0x1C: (read_generic, "UniversalString", 'utf-32-be'),
    0x1D: (read_generic, "CharacterString", 'ascii'),
    0x1E: (read_generic, "BMPString", 'utf-16-be'),
    0x1F: (read_constructed, "Date"),
    0x20: (read_constructed, "TimeOfDay"),
    0x21: (read_constructed, "DateTime"),
    0x22: (read_constructed, "Duration"),
    0x23: (read_generic, "TeletexString", 'ascii'),
    0x24: (read_generic, "VideotexString", 'ascii'),
    0x25: (read_generic, "GraphicString", 'ascii'),
    0x26: (read_generic, "VisibleString", 'ascii'),
    0x27: (read_generic, "GeneralString", 'ascii'),
    0x28: (read_generic, "UniversalString", 'utf-32-be'),
    0x29: (read_constructed, "CharacterString"),
    0x2A: (read_constructed, "RelativeOID"),
}

def read_universal(data, i, pc_bit, tag_number):
    if tag_number in UNIVERSAL_TAGS:
        tag_info = UNIVERSAL_TAGS[tag_number]
        read_function = tag_info[0]
        tag_name = tag_info[1]
        encoding = tag_info[2] if len(tag_info) > 2 else None
        return read_function(data, i, pc_bit, tag_name, encoding)
    else:
        print(f"\nUnknown universal tag number: 0x{tag_number:02x} at index {i}. Reading as generic.")
        return read_generic(data, i, pc_bit, f"Unknown ({tag_number})")

# Context-specific tag reader

X509_CONTEXT_SPECIFIC_NAMES = {
    0: "Version",
    1: "Serial Number",
    2: "Signature Algorithm",
    3: "Issuer",
    4: "Validity",
    5: "Subject",
    6: "Subject Public Key Info",
    7: "Issuer Unique ID",
    8: "Subject Unique ID",
    9: "Extensions",
}

def read_context_specific(data, i, pc_bit, tag_number):
    tag_name = X509_CONTEXT_SPECIFIC_NAMES.get(tag_number, tag_number)
    tag_name = f"Context-specific ({tag_name})"
    print(f"{tag_name} tag")
    i += 1
    length, i = read_length(data, i)
    end_index = i + length
    if end_index > len(data):
        print(f"\nReached end of data while reading context-specific tag value at index {i}. Returning available data.")
        end_index = len(data)
    if pc_bit:  # Constructed
        items = []
        while i < end_index:
            item, new_i = read_element(data, i)
            if item:
                items.append(item)
            i = new_i
        return (tag_name, items), i
    else:  # Primitive
        print_data(f"  Value:", data, i, length)
        return (tag_name, data[i:end_index]), end_index

# Main parsing functions

def read_element(data, i):
    tag = data[i]
    class_bits = (tag >> 6) & 0x03
    pc_bit = (tag >> 5) & 0x01
    tag_number = tag & 0x1F

    print_tag(tag, tag_number, class_bits, pc_bit, i)

    if class_bits == 0:  # Universal
        return read_universal(data, i, pc_bit, tag_number)
    elif class_bits == 1:  # Application
        return read_generic(data, i, pc_bit, f"Application ({tag_number})")
    elif class_bits == 2:  # Context-specific
        return read_context_specific(data, i, pc_bit, tag_number)
    elif class_bits == 3:  # Private
        return read_generic(data, i, pc_bit, f"Private ({tag_number})")

def parse_elements(data, i, end_index=None):
    if not end_index:
        end_index = len(data)
    if end_index > len(data):
        print(f"\nReached end of data while reading ASN.1 elements at index {i}. Returning available data.")
        end_index = len(data)
    items = []
    while i < end_index:
        item, new_i = read_element(data, i)
        if item:
            items.append(item)
        i = new_i
    return items

def parse_asn1(data):
    print_data("Initial data", data, 0, 16)
    return parse_elements(data, 0)

# Print result

def print_asn1_structure(items, indent=0):
    for idx, item in enumerate(items):
        if isinstance(item[1], list):
            print(" " * indent + f"[{idx}] {item[0]}")
            print_asn1_structure(item[1], indent + 2)
        else:
            print(" " * indent + f"[{idx}] {item[0]}: {item[1]}")

# Main script

def main():
    parser = argparse.ArgumentParser(description='Parse ASN.1 file or content and optionally base64 decode the content.')
    parser.add_argument('-f', '--file_path', type=str, help='Path to the ASN.1 file.')
    parser.add_argument('-c', '--content', type=str, help='ASN.1 content directly as a string.')
    parser.add_argument('-b', '--base64', action='store_true', help='Base64 decode the content.')
    parser.add_argument('-s', '--strip-headers', action='store_true', help='Remove headers and footers like -----BEGIN CERTIFICATE-----.')

    args = parser.parse_args()

    if not args.file_path and not args.content:
        parser.error('No action requested, add --file_path or --content')

    file_content = args.content.encode() if args.content else open(args.file_path, 'rb').read()

    if args.strip_headers:
        # Remove all headers and footers like -----BEGIN CERTIFICATE-----
        file_content = re.sub(b"-----BEGIN [^-]+-----", b"", file_content)
        file_content = re.sub(b"-----END [^-]+-----", b"", file_content)
        # Remove any remaining whitespace or newlines
        file_content = re.sub(b"\s+", b"", file_content)

    decoded_data = base64.b64decode(file_content) if args.base64 else file_content

    # Parse the ASN.1 structure
    asn1_items = parse_asn1(decoded_data)
    if asn1_items:
        print("\nParsed ASN.1 structure:")
        print_asn1_structure(asn1_items)
    else:
        print("\nFailed to parse ASN.1 structure.")

if __name__ == "__main__":
    main()
