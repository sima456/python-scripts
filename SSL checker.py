import ssl
import argparse
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def check_certificate_info(hostname, verbose=False):
    context = ssl.create_default_context()
    cert = ssl.get_server_certificate((hostname, 443))
    x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
    print(f"Certificate for {hostname}:")
    print(f"\tSubject: {x509_cert.subject}")
    print(f"\tIssuer: {x509_cert.issuer}")
    print(f"\tValid from: {x509_cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\tValid until: {x509_cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\tSignature algorithm: {x509_cert.signature_algorithm_oid._name}")

    if verbose:
        public_key = x509_cert.public_key()
        key_size = public_key.key_size
        key_type = type(public_key).__name__
        print(f"\tPublic key type: {key_size} bits")
        print(f"\tPublic key algorithm: {key_type}")
        subject_alt_names = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if subject_alt_names:
            print(f"\tSubject alternative names: {subject_alt_names.value.get_values_for_type(x509.DNSName)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check SSL certificate information')
    parser.add_argument('hostname', type=str, help='The hostname of the website to check')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show verbose information')
    args = parser.parse_args()
    check_certificate_info(args.hostname, args.verbose)
