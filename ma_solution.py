from lib_tp_rsa import generer_premier, sont_premiers_entre_eux, inverse_modulo

def signer_rsa(M, D, N):
    S = pow(M,D,N)
    return S

def signature_rsa_est_valide(M, S, E, N):
    '''renvoie « True » si S est une signature du message M
    faite avec la clé privée correspondant à (E, N);
    sinon, renvoie « False »'''
    M_2 =pow(S, E, N)
    if M_2 == M:
        return True
    else:
        return False
 

def generer_cle_rsa():
    "génère une paire de clés RSA"
    E = 3

    nombre_max_tentatives = 5
    for i in range(nombre_max_tentatives):
        P = generer_premier()
        Q = generer_premier()

        N =P*Q
        phi_N =(P-1)*(Q-1)

        if ( P!= Q and sont_premiers_entre_eux(E,phi_N)):
            D = inverse_modulo(E,phi_N)
            return (E, D, N)
    raise Exception('toutes les tentatives ont échoué')
(E, D, N) = generer_cle_rsa()
M = 135 
faux_M = 28 
S = signer_rsa(M, D, N)
signature_rsa_est_valide(M, S, E, N)

def conversation_authentifiee(liste_messages, cles_publiques):
    resultat = str()
    for message in liste_messages:
        heure = message["heure"]
        exp = message["expéditeur"]
        msg = message["texte"]
        S = message["signature"]
        E, N = cles_publiques[exp]
        if signature_rsa_est_valide(msg, S, E, N) :
            sig_valide = "OK"
        else:
            sig_valide = "NON VALIDE !!!"
        resultat += f'# {heure} {exp} (signature {sig_valide}):'
        resultat += '\n'
        resultat += msg
        resultat += '\n\n'
    return resultat


def verifier_certificat_site(cert_site, cert_autorite):
    msg = cert_site.tbs_certificate_bytes
    S = cert_site.signature
    S = int.from_bytes(S, byteorder='big')
    N = cert_autorite.public_key().public_numbers().n
    E = cert_autorite.public_key().public_numbers().e
    if signature_rsa_est_valide(msg, S, E, N) :
        return True
    else:
        return False
