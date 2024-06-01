# ASN.1 Parser

This Python script decodes (possibly broken) ASN.1 (Abstract Syntax Notation One) encoded data.

## Features
- Parses ASN.1 encoded data from a file or directly from a string.
- Optionally base64 decodes the input data.
- Supports recursive parsing of nested ASN.1 structures.
- Can recursively parse `OCTET STRING` contents as ASN.1 if specified.
- Outputs the parsed ASN.1 structure in a formatted and readable way.

## Usage

### Command Line Arguments

- `-f`, `--file_path`: Path to the ASN.1 file.
- `-c`, `--content`: ASN.1 content directly as a string.
- `-b`, `--base64`: Base64 decode the content before parsing.
- `-r`, `--recursive_octet_string`: Recursively parse `OCTET STRING` content as ASN.1.

### Examples

#### Parse ASN.1 from a file

```bash
python asn1parser.py -f path/to/asn1file.der
```

#### Parse base64 encoded ASN.1 content from a file

```bash
python asn1parser.py -f path/to/asn1file.b64 -b
```

#### Parse ASN.1 content from a string

```bash
python asn1parser.py -c "your_asn1_content_here"
```

#### Recursively parse `OCTET STRING` content as ASN.1

```bash
python asn1parser.py -f path/to/asn1file.der -r
```

### Output

The parsed ASN.1 structure will be printed in a formatted and indented manner, making it easier to understand nested structures. For example:

```
Parsed ASN.1 structure:
Item 0: SEQUENCE
  Item 0: INTEGER - 12345
  Item 1: OCTET STRING
    Item 0: SEQUENCE
      Item 0: UTF8String - Example
      Item 1: INTEGER - 67890
```

## Functions

### `parse_asn1(data, recursive_octet_string=False)`

Parses the provided ASN.1 data.

- `data`: The ASN.1 encoded data as bytes.
- `recursive_octet_string`: If `True`, recursively parse `OCTET STRING` content as ASN.1.

### `print_asn1_structure(items, indent=0)`

Prints the parsed ASN.1 structure in a formatted manner.

- `items`: The parsed ASN.1 items.
- `indent`: The current indentation level (used for recursive calls).

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.
