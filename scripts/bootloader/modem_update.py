import re
import cbor2
from argparse import ArgumentParser, FileType
import intelhex
import hashlib
from os import path, remove
from pathlib import Path
from zipfile import ZipFile
from pprint import pprint


PROTOCOL_VERSION = 1
ALG_ID = 1
ECDSA_SHA256 = -7
RSASSA_PSS = -37
BOOTLOADER_REGEX = r'[A-Fa-f0-9]*.ipc_dfu.signed_?[0-9\.]*.ihex'


def find_and_extract_hex_files(regexes, zip_file):
    zip_in = ZipFile(zip_file)

    hex_files = list()
    for r in regexes:
        matches = [zip_in.extract(x) for x in zip_in.namelist()
                   if re.search(r, x)]
        hex_files.extend(matches)
        if len(matches) == 0:
            raise RuntimeError(f"No matches found for regex '{r}'"
                               f"Files checked: "
                               f"{[x.filename for x in zip_in.filelist]}")
        elif len(matches) > 1:
            [remove(h) for h in hex_files]
            raise RuntimeError(f"Found more than 1 match for regex '{r}'"
                               f"Matches: {matches}")

    ret = [intelhex.IntelHex(x) for x in hex_files]

    [remove(h) for h in hex_files]

    return ret


def get_array_from_bytes(b, var='input', type='uint8_t'):
    return f'{type} {var} = ' \
           f'{{' \
           f'{" ".join([f"0x{b[i:i+2]}," for i in range(0, len(b), 2)])[:-1]}'\
           f'}};'


def get_segments_and_blob(hex_files, verbose):
    blob_string = b""
    segments = list()
    for ih in hex_files:
        for start, end in ih.segments():
            segments.extend((start, end - start))
            blob_string += ih.tobinarray(start=start, end=end - 1)

    segment_string = cbor2.dumps(segments)

    if verbose:
        print(f'''
/* Segments */
uint32_t expected[] = {{{' '.join([f'{hex(x)},' for x in segments])[:-1]}}};

/* Segments cbor hex (length {len(segment_string)} bytes):
 * {segment_string.hex()}
 */

/* Segments cbor array */
{get_array_from_bytes(segment_string.hex())}''')
    return segment_string, blob_string


def generate_manifest(hex_files, compatibility_flag, output_dir, verbose):

    segment_string, blob_string = get_segments_and_blob(hex_files, verbose)

    h = hashlib.sha256(blob_string).digest()
    manifest = list()
    manifest.append(PROTOCOL_VERSION)
    manifest.append(compatibility_flag)
    manifest.append(h)
    manifest.append(segment_string)

    manifest_string = cbor2.dumps(manifest)

    protected_header = cbor2.dumps({ALG_ID: RSASSA_PSS})

    sig_structure = list()
    sig_structure.append("Signature1")
    sig_structure.append(protected_header)
    sig_structure.append(b"") # external_aad
    sig_structure.append(manifest_string)
    sig_structure_string = cbor2.dumps(sig_structure)

    if verbose:
        print(f'''
/* Manifest:
 * Protocol version: {PROTOCOL_VERSION}
 * Compatibility: {compatibility_flag}
 * Hash: {h.hex()}
 * Segments: {segment_string.hex()}
 {pprint(sig_structure)}
 */

/* Manifest hex (length {len(manifest_string)} bytes):
 * {manifest_string.hex()}
 */

/* To be signed (length {len(sig_structure_string)} bytes):
 * {sig_structure_string.hex()}
 * hash: {hashlib.sha256(sig_structure_string).digest().hex()}
 {pprint(sig_structure)}
 */''')

    with open(path.join(output_dir, "blob.bin"), 'wb+') as f:
        f.write(blob_string)
        print(f"Stored blob of concatenated firmware to {f.name}")
    with open(path.join(output_dir, "manifest.bin"), 'wb+') as f:
        f.write(manifest_string)
        print(f"Stored manifest describing blob to {f.name}")
    with open(path.join(output_dir, "to_be_signed.bin"), 'wb+') as f:
        f.write(sig_structure_string)
        print(f"Stored signature structure of manifest to {f.name}")

    return manifest_string, blob_string


def generate_wrapper(manifest, signature, output_dir, verbose):
    protected_header = cbor2.dumps({ALG_ID: RSASSA_PSS})
    cose = list()
    cose.append(protected_header)
    cose.append({})  # Unprotected header: empty
    cose.append(manifest)  # Payload
    cose.append(signature)  # Signature

    wrapper_string = cbor2.dumps(cbor2.CBORTag(18, cose))

    if verbose:
        print(f'''
/* Wrapper:
 * Protected Header: {protected_header.hex()}
 * Unprotected: (empty)
 * Manifest: {manifest.hex()}
 * Signature: {signature.hex()}
 */

/* Wrapper hex (length {len(wrapper_string)} bytes):
 * {wrapper_string.hex()}
 */
uint8_t wrapper[] = {{{', '.join([f'{hex(x)}' for x in wrapper_string])}}};''')

    with open(path.join(output_dir, "wrapper.bin"), 'wb+') as f:
        f.write(wrapper_string)
        print(f"Stored wrapper of signature and manifest to {f.name}")

    return wrapper_string


def generate_update_bin(wrapper, blob, output_dir):
    with open(path.join(output_dir, "update.bin"), 'wb+') as f:
        f.write(wrapper + blob)
        print(f"Stored packed wrapper and blob (ie full update)"
              f" to {f.name}")


def get_hex_files(zip_or_hex_list, name_regex,):
    if len(zip_or_hex_list) == 1 and zip_or_hex_list[0].endswith(".zip"):
        if name_regex is None:
            raise RuntimeError("name-regex arg required when zip provided")
        return find_and_extract_hex_files(name_regex, zip_or_hex_list[0])
    else:
        return [intelhex.IntelHex(f) for f in zip_or_hex_list]


def parse_args():
    parser = ArgumentParser(description=
                            '''Generate a modem firmware update given the
binaries that should go into it.''')

    subparsers = parser.add_subparsers(dest="mode")
    manifest_parser = subparsers.add_parser("manifest")
    wrapper_parser = subparsers.add_parser("wrapper")

    manifest_parser.add_argument("-n", "--name-regex", required=False,
                                 help='''Regexes to match hex files. Note,
the order of these expressions decide the order in the payload. Example
\"s1.hex\" \"s2.hex\". Only required if "--input" arg is a zip file.''',
                                 default=[BOOTLOADER_REGEX,
                                          r'.*.segments.0.hex',
                                          r'.*.segments.1.hex'],
                                 nargs="+")

    manifest_parser.add_argument("-i", "--input", nargs='+', type=str,
                                 required=True, help="Path to release zip or "
                                 "input binary files (hex).")

    manifest_parser.add_argument("-c", "--compat", required=False, type=int,
                                 default=0, help="Compatibility tag.")

    manifest_parser.add_argument("-d", "--dummy-signature",
                                 action='store_true', default=False,
                                 help="Use dummy value for signature, and"
                                      " generate wrapper as well.")

    wrapper_parser.add_argument("-m", "--manifest", required=True,
                                type=FileType('rb'),
                                help="Manifest file as generated by the "
                                     "'manifest' command.")

    wrapper_parser.add_argument("-s", "--signature", required=True,
                                type=FileType('rb'),
                                help="Bin file containing the signature of the"
                                     " manifest.")

    wrapper_parser.add_argument("-b", "--blob", required=False,
                                type=FileType('rb'),
                                help="Bin file containing the concatenated"
                                     "firmware as generated by the 'manifest'"
                                     "command.")

    parser.add_argument("-o", "--output-dir", type=str, default=path.dirname(
        path.abspath(__file__)),
        help="Store generated files in specified directory.")

    parser.add_argument("-v", "--verbose", action='store_true',
                        help="Print header C struct, hex, and segments")

    return parser.parse_args()


def main():
    args = parse_args()
    manifest = None
    blob = None

    if args.output_dir:
        Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    if args.mode == "manifest":
        hex_files = get_hex_files(args.input, args.name_regex)
        manifest, blob = generate_manifest(hex_files, args.compat,
                                           args.output_dir, args.verbose)

    if args.mode == "wrapper" or \
            ("dummy_signature" in args and args.dummy_signature):
        if args.mode == "wrapper":
            signature = args.signature.read()
            manifest = args.manifest.read()
            if "blob" in args:
                blob = args.blob.read()
        else:
            signature = bytearray([0xff] * 256)
            print(f"Using dummy signature {signature.hex()}")

        wrapper = generate_wrapper(manifest, signature, args.output_dir,
                                   args.verbose)

        if blob:
            generate_update_bin(wrapper, blob, args.output_dir)

    elif args.mode is None:
        raise RuntimeError("No mode selected, check help text")


if __name__ == "__main__":
    main()
