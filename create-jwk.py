import sys
import json
from jwcrypto import jwk
from datetime import date

# TODO: implement read file


def generate_keys():
    """ Generate and print keys. Return full key obj."""
    key = jwk.JWK.generate(kty='RSA', size=4096)

    # exports the full key-pair
    key_full = key.export()
    # export private key
    key_private_part = key.export(private_key=True)
    # exports ONLY the public part.
    key_public_part = key.export(private_key=False)

    print(f'Full key:\n{json.dumps(json.loads(key_full), indent=2)}')
    print('\n')
    print(f'Private part:\n{json.dumps(json.loads(key_private_part), indent=2)}')
    print('\n')
    print(f'Public part:\n{json.dumps(json.loads(key_public_part), indent=2)}')
    print('\n')

    return key


def write_file(file_name, content):
    options = [ 
        { 'fname': 'full', 'private_key': None }, 
        { 'fname': 'private', 'private_key': True},
        { 'fname': 'public', 'private_key': False } 
    ]

    for opt in options:
        fname = f'{file_name}_' + opt.get('fname') + '_' + str(date.today()) + '.json'
        priv = opt.get('private_key')

        with open(fname, 'w') as fn:
            print(f'Writing to file: {fname}\n')

            if priv is None:
                fn.write(str(content.export()))
            else:
                fn.write(str(content.export(private_key=priv)))


def parse_args(my_name = None, first=None, second=None):
    """Parse arguments and return filename"""
    print(f'Got arguments: {first}, {second}')
    if second and first == '-o':
        return second
    else:
        print(f'Unknown arguments.\n')
        sys.exit(1)


def main():
    file_name = parse_args(*sys.argv)
    key_full = generate_keys()
    write_file(file_name, key_full)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Provide in or out and filename.')
        sys.exit(1)

    main()
