# mostly stolen from https://stackoverflow.com/questions/61348501/tls-ssl-socket-python-server
import http.server
from http.server import HTTPServer, SimpleHTTPRequestHandler, SimpleHTTPRequestHandler
import ssl
import sys
import tempfile

from OpenSSL import crypto, SSL

## stolen from https://stackoverflow.com/questions/27164354/create-a-self-signed-x509-certificate-in-python
def cert_gen(certfile, keyfile):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    print("Generating key")
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "stateOrProvinceName"
    cert.get_subject().L = "localityName"
    cert.get_subject().O = "organizationName"
    cert.get_subject().OU = "organizationUnitName"
    cert.get_subject().CN = "commonName"
    cert.get_subject().emailAddress = "test@example.com"
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(certfile, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(keyfile, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    print("[**] certfile: %s\n[**] keyfile: %s" % (certfile, keyfile))


try:
    separator = "-" * 80
    addr = "0.0.0.0"
    port = 4444
    server_address = ("", 4444)
    with tempfile.NamedTemporaryFile(prefix="simpleserv_cert_", suffix=".pem", mode="w+b") as cert:
        with tempfile.NamedTemporaryFile(prefix="simpleserv_key_", suffix=".pem", mode="w+b") as key:
            cert_gen(cert.name, key.name)

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert.name, keyfile=key.name)
            httpd = http.server.HTTPServer(server_address, SimpleHTTPRequestHandler)

            httpd.socket = context.wrap_socket(
                httpd.socket, 
                server_side=True, 
                do_handshake_on_connect=True, 
                suppress_ragged_eofs=True, 
                server_hostname=None, 
                session=None
            )
            print("[**] Server running on https://%s:%d" % (addr, port))
            # Wait forever for incoming htto requests
            httpd.serve_forever()
except KeyboardInterrupt:
    print("^C received, shutting down the web server")
    server.socket.close()


