#!/usr/bin/env python3
import random, math
from Crypto.Util.number import getPrime, inverse, GCD, long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA


def generate_rsa_key_with_small_d(bits=1024):
    """
    Génère une clé RSA en choisissant directement un petit exposant privé d,
    de sorte que d < n^(1/4)/3, garantissant une vulnérabilité à l'attaque de Wiener.

    La méthode :
      1. Générer aléatoirement deux grands premiers p et q.
      2. Calculer n = p*q et φ(n) = (p-1)*(q-1).
      3. Déterminer la borne supérieure pour d : d < n^(1/4)/3.
      4. Choisir aléatoirement un d dans [2, borne_sup] tel que GCD(d, φ(n)) = 1.
      5. Calculer e = inverse(d, φ(n)).
    """
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    upper_bound = int(pow(n, 0.25) // 3)
    if upper_bound < 2:
        raise Exception("n trop petit pour imposer d vulnérable")
    while True:
        d = random.randint(2, upper_bound)
        if GCD(d, phi) == 1:
            break
    e = inverse(d, phi)
    return (n, e, d, p, q)


def main():
    bits = 1024  # Taille du module RSA
    n, e, d, p, q = generate_rsa_key_with_small_d(bits)

    # Export de la clé publique au format PEM (seuls n et e sont diffusés)
    pub_key = RSA.construct((n, e))
    with open("public.pem", "wb") as f:
        f.write(pub_key.exportKey("PEM"))

    # Le flag à chiffrer
    flag = b"CPU{FaiblesParametresPourRSA}"
    m = bytes_to_long(flag)
    if m >= n:
        raise Exception("Le flag est trop long pour ce module RSA.")

    # Chiffrement classique avec la clé publique : c = m^e mod n
    c = pow(m, e, n)
    with open("flag.enc", "w") as f:
        f.write(hex(c)[2:])  # en hexadécimal (sans le préfixe 0x)

    print("Challenge généré avec succès !")
    print("-> Clé publique dans 'public.pem'")
    print("-> Fichier chiffré dans 'flag.enc'")
    # Pour debug uniquement (à ne pas diffuser) :
    print("DEBUG : d =", d)


if __name__ == "__main__":
    main()
