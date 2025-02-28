import sys
from src.view_certificate import *

help_command = """
validate_cert -format DER|PEM cert1.pem cert2.pem ...

-format: DER or PEM, defines the format of your files
"""

def main(args):
    print(args)
    if len(args) < 3:
        print(help_command)
        sys.exit(1)
    if args[0] != "-format":
        print(help_command)
        sys.exit(1)

    file_format = args[1]
    if file_format not in "DERPEM":
        print(help_command)
        sys.exit(1)

    for file in args[2:]:
        view_certificate(file_format, file)

if __name__ == "__main__":
    main(sys.argv[1:])
    sys.exit(0)
