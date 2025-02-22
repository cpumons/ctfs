#!/usr/bin/env python3
import math
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

def continued_fraction(numerator, denominator):
    """ Calcule le développement en fraction continue de numerator/denominator. """
    cf = []
    while denominator:
        a = numerator // denominator
        cf.append(a)
        numerator, denominator = denominator, numerator - a * denominator
    return cf

def convergents_from_cf(cf):
    """ Génère les convergents à partir d'un développement en fraction continue. """
    convergents = []
    for i in range(len(cf)):
        num, den = 1, 0
        for a in reversed(cf[:i+1]):
            num, den = a * num + den, num
        convergents.append((num, den))
    return convergents

def wiener_attack(e, n):
    """
    Implémente l'attaque de Wiener.
    Pour chaque convergent k/d de la fraction continue de e/n, on teste si
        d_candidate = d
    est le bon exposant privé.
    """
    cf = continued_fraction(e, n)
    convs = convergents_from_cf(cf)
    for k, d in convs:
        if k == 0:
            continue
        # On vérifie si (e*d - 1) est divisible par k
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # On calcule S = n - phi + 1 et le discriminant de x^2 - Sx + n = 0
        S = n - phi + 1
        discr = S * S - 4 * n
        if discr >= 0:
            t = math.isqrt(discr)
            if t * t == discr and (S + t) % 2 == 0:
                # On a trouvé d via l'attaque de Wiener
                return d
    return None

def main():
    # 1. Charger la clé publique depuis "public.pem"
    with open("public.pem", "rb") as f:
        pub_key = RSA.importKey(f.read())
    n = pub_key.n
    e = pub_key.e
    print("[*] Clé publique chargée.")
    print(f"    n = {n}")
    print(f"    e = {e}")

    # 2. Charger le ciphertext depuis "flag.enc"
    with open("flag.enc", "r") as f:
        ciphertext_hex = f.read().strip()
    c = int(ciphertext_hex, 16)
    print("[*] Ciphertext chargé.")

    # 3. Récupérer d par l'attaque de Wiener
    print("[*] Début de l'attaque de Wiener pour récupérer d ...")
    d = wiener_attack(e, n)
    if d is None:
        print("[-] Attaque de Wiener échouée.")
        return
    print(f"[*] Exposant privé trouvé: d = {d}")

    # 4. Déchiffrer le ciphertext
    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print("[*] Flag déchiffré :")
    print(flag.decode())

if __name__ == "__main__":
    main()
