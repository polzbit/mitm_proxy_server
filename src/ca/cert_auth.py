
from os import path
from tempfile import mkdtemp
from OpenSSL.crypto import (X509Extension, X509,dump_privatekey, dump_certificate, load_certificate, load_privatekey,PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM


class CertificateAuthority(object):
    ''' Generate and sign certificates .pem files '''

    def __init__(self, ca_file, cache_dir=mkdtemp()):
        print(f"[*] Initializing Certificate-Authority... \n[*] Certificate file: {ca_file}\n[*] Cache directory:{cache_dir}")
        self.CERT_PREFIX = 'fake-cert'
        self.ca_file = ca_file
        self.cache_dir = cache_dir
        if not path.exists(ca_file):
            raise Exception(f"[!] No cert exists at {ca_file}" )
        else:
            self._read_ca(ca_file)

    def sign_certificate(self, cn):
        ''' Generate CA public/private key and use the private key to sign TLS certificate '''

        cnp = path.sep.join([self.cache_dir, f'{self.CERT_PREFIX}-{cn}.pem'])
        if path.exists(cnp):
            print(f"[!] Certificate already exists, certificate: {cn}")
        else:
            print(f"[*] Creating and signing certificate: {cn}")
            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(123)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))
                f.write(dump_certificate(FILETYPE_PEM, cert))

            print(f"[*] Certificate:{cn}\n[*] Location:{cnp}\n[*] Status: Created")

        return cnp

    def _read_ca(self, file):
        self.cert = load_certificate(FILETYPE_PEM, open(file).read())
        self.key = load_privatekey(FILETYPE_PEM, open(file).read())

    @staticmethod
    def generate_certificate(filepath, common_name):
        ''' Generate TLS certificate and private key '''

        if path.exists(filepath):
            print(f"[!] Certificate already exists at {filepath}")
            return
            
        filename, ext = path.splitext(filepath)
        pub_file = f'{filename}.pub'

        # Generate key
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        # Generate certificate
        cert = X509()
        cert.set_serial_number(1)
        cert.set_version(3)
        cert.get_subject().CN = common_name
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")
        with open(filepath, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
            f.write(dump_certificate(FILETYPE_PEM, cert))

        with open(pub_file, 'wb+') as pf:
            pf.write(dump_certificate(FILETYPE_PEM, cert))