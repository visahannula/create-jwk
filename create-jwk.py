#!/usr/bin/env python

import sys
import json
from jwcrypto import jwk
from datetime import date

def generate_keys():
    """ Generate keys. Return full key obj."""
    return jwk.JWK.generate(kty='RSA', size=4096)


def print_key(key):
    # exports the full key-pair
    key_full = key.export()

    print(f'Full key:\n{json.dumps(json.loads(key_full), indent=2)}')
    print('\n')
    print(f'Has asymmetric private key: {key.has_private}')
    print(f'Has asymmetric public key: {key.has_public}')

    if (key.has_private):
        # export private key
        key_private_part = key.export(private_key=True)
        print(f'Private part:\n{json.dumps(json.loads(key_private_part), indent=2)}')
        print('\n')
    if (key.has_public):
        # exports ONLY the public part.
        key_public_part = key.export(private_key=False)
        print(f'Public part:\n{json.dumps(json.loads(key_public_part), indent=2)}')

        print('\n')


def print_keys(key_set):
    if isinstance(key_set, list):
        for key in key_set:
            print_key(key)
    else:
        print_key(key_set)


def read_key_from_file(filename):
    with open(filename, 'r') as fn:
        full_key_json = json.load(fn)

    if full_key_json.get('keys', None):
        print("Input is keyset.")
        key_set = jwk.JWKSet()
        key_set.import_keyset(**full_key_json)
        full_key = key_set
    else:
        print("Input is not keyset.")
        full_key = jwk.JWK(**full_key_json)

    return full_key


def create_JWK(key):
    return jwk.JWKSet()


def write_file(file_name, content):
    options = ['full', 'private', 'public']

    for opt in options:
        fname = f'{file_name}_{opt}_{str(date.today())}.json'

        with open(fname, 'w') as fn:
            print(f'Writing to file: {fname}')

            match opt:
                case "full":
                    fn.write(str(content.export()))
                case "private":
                    fn.write(str(content.export_private()))
                case "public":
                    fn.write(str(content.export_public()))


def parse_args(my_name = None, first=None, second=None) -> tuple:
    """Parse arguments and return filename"""
    print(f'Got arguments: {first}, {second}')

    if not second or (first != '-o' and first != '-i'):
        print("Unknown arguments.\n")
        sys.exit(1)

    return (second, first)

def main():
    file_name, operation = (parse_args(*sys.argv))

    if operation == '-o':
        key_full = generate_keys()
        print_keys(key_full)
        write_file(file_name, key_full)
    else:
        key_full = read_key_from_file(file_name)
        print_keys(key_full)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Error: Provide in (-i) or out (-o) and filename.')
        print('Usage: create-jwk.py [-i|-o] filename')
        sys.exit(1)

    main()
