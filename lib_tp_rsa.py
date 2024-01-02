'''fonctions à utiliser dans le TP.'''

# Biliothèques fournies avec Python
# (voir https://docs.python.org/3/library/) 
import ssl
import socket
import json
from hashlib import sha256
from binascii import unhexlify

# Bibliothèque externe "cryptography"
# (voir https://cryptography.io)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding

# bibliothèque "tlslite-ng"
# https://github.com/tlsfuzzer/tlslite-ng
import tlslite
from tlslite.utils.cryptomath import invMod

def generer_premier(bits=16):
    '''renvoie un nombre premier pris au hasard de la taille demandée
    
    La longueur du premier en bits peut être donnée,
    par défaut elle est de 16 bits
    (par exemple le nombre premier 17 s'écrit « 10001 » en binaire
    donc sa taille en bits est de 5).
    '''

    return tlslite.utils.cryptomath.getRandomPrime(bits)

def sont_premiers_entre_eux(x, y):
    '''renvoie « True » si x et y sont premiers en eux, « False » sinon.

    Deux nombres sont premiers entre eux si leur seul diviseur commun est 1.
    Par exemple 10 a pour diviseurs 1, 2 et 5 et 21 a pour diviseurs 1, 3 et 7,
    donc 10 et 21 sont premiers entre eux.
    '''
    if tlslite.utils.cryptomath.gcd(x, y) == 1:
        return True
    else:
        return False

def inverse_modulo(x, n):
    '''renvoie l'inverse de x modulo n.
    
    y est l'inverse de x modulo n si et seulement si:
    x*y = 1 mod n

    pour qu'un nombre x ait un inverse modulo n,
    il faut que x et n soient premiers entre eux (voir fonction précédente).
    '''
    return tlslite.utils.cryptomath.invMod(x, n)

def encoder_msg_en_nombre(message, modulus):
    '''transforme un message (une chaîne d'octets) en nombre pour être signé avec RSA

    Le modulus que l'on compte utiliser doit être précisé
    (pour ajutster la taille du nombre que l'on produit
    à la taille du modulus).

    Si le modulus RSA est suffisament grand,
    l'algorithme d'encodage utilisé est celui conçu pour la signature RSA,
    appelé « EMSA-PKCS1-v1_5 » est décrit à l'adresse suivante:
    https://tools.ietf.org/html/rfc3447.html#section-9.2

    Sinon, si le modulus est trop petit
    (quand on utilise des petits nombres pour les exemples),
    on utilise un encodage beaucoup plus simple
    (et pas forcément très sécurisé, mais bon...)
    '''

    if isinstance(message, str):
        message = message.encode()

    # k is the length (in bytes) of the modulus
    k = (len(bin(modulus)) - 2) / 8
    assert k.is_integer()
    k = int(k)

    if k < 11 + (19 + 32):
        # modulus length is too short to apply EMSA-PKCS1-v1_5 encoding
        # (happens with toy parameters)
        # falling back to a simpler encoding
        EM_2 = sha256(message).digest()[:k-1]
        m_2 = int.from_bytes(EM_2, byteorder='big')
        return m_2

    # EMSA-PKCS1-v1_5 encoding
    # (Section 9.2 of same RFC 3447:
    # https://tools.ietf.org/html/rfc3447.html#section-9.2)

    M = message
    H = sha256(M).digest()
    # digest algorithm identifier 
    # (see note 1 in RFC 3447 Section 9.2)
    algoId = unhexlify('3031300d060960864801650304020105000420')
    T = algoId + H

    PS = b'\xff'*(k - len(T) - 3)
    EM_2 = b'\x00' + b'\x01' + PS + b'\x00' + T
    m_2 = int.from_bytes(EM_2, byteorder='big')

    return m_2

def charger_conversation_depuis_json(nom_fichier):
    '''lit le fichier JSON dont le chemin est donné en paramètre
    et renvoie son contenu décodé en objet Python'''
    with open(nom_fichier) as f:
        liste_messages = json.load(f)

    return liste_messages

def charger_cles_depuis_json(nom_fichier):
    '''même chose que 'charger_conversation_depuis_json' '''
    with open(nom_fichier) as f:
        cles_publiques = json.load(f)

    return cles_publiques

def recuperer_certificat(adresse):
    '''télécharge le certificat du site web donné en paramètre,
    et renvoie ce certificat
    et le certificat de l'autorité de certification qui l'a signé.

    Le site web donné en paramètre doit accepter le protocole HTTPS
    (sur le port 443)
    et fournir un certificat dont la signature est faite
    avec l'algorithme « sha256WithRSAEncryption ».
    '''

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect( (adresse, 443) )

        connection = tlslite.TLSConnection(sock)
        connection.handshakeClientCert()

        cert_chain = [
            x509.load_pem_x509_certificate(
                tlslite.utils.pem.pem(cert.bytes, name="CERTIFICATE").encode(),
                default_backend()
            )
            for cert in connection.session.serverCertChain.x509List
        ]

        cert_site  = cert_chain[0]
        cert_autorite = cert_chain[1]

        # we are only supporting sha256WithRSAEncryption
        assert cert_site.signature_algorithm_oid._name == 'sha256WithRSAEncryption'

    return cert_site, cert_autorite
