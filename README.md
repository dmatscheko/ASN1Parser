# ASN.1 Parser

This Python script decodes (possibly broken) ASN.1 (Abstract Syntax Notation One) encoded data.

## Features
- Parses ASN.1 encoded data from a file or directly from a string.
- Optionally base64 decodes the input data.
- Supports recursive parsing of nested ASN.1 structures.
- Outputs the parsed ASN.1 structure in a formatted and readable way.

## Usage

### Command Line Arguments

- `-f`, `--file_path`: Path to the ASN.1 file.
- `-c`, `--content`: ASN.1 content directly as a string.
- `-b`, `--base64`: Base64 decode the content before parsing.
- `-s`, `--strip-headers`: Remove headers and footers like -----BEGIN CERTIFICATE-----.
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
Item 0: Sequence
  Item 0: Sequence
    Item 0: Context-specific (Version)
      Item 0: Integer - 2
    Item 1: Integer - 123456789
    Item 2: Sequence
      Item 0: ObjectIdentifier - 42.134.72.134.247.13.1.1.11 (SHA-256 with RSA Signature (SHA256 RSA SIG))
      Item 1: NULL - None
    Item 3: Sequence
      Item 0: Set
        Item 0: Sequence
          Item 0: ObjectIdentifier - 85.4.6 (Country Name (C))
          [...]
```

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.
