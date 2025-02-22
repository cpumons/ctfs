from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes
from sympy import mod_inverse, gcd
from math import isqrt

def load_public_key(pem_file):
    try:
        with open(pem_file, 'rb') as f:
            public_key = RSA.importKey(f.read())
        print(f"Clé publique chargée : n={public_key.n}, e={public_key.e}")
        return public_key
    except Exception as e:
        print(f"Erreur lors du chargement de la clé publique : {e}")
        return None

def continued_fraction_expansion(a, b):
    expansion = []
    while b != 0:
        expansion.append(a // b)
        a, b = b, a % b
    return expansion

def convergents_from_continued_fraction(expansion):
    convergents = []
    for i in range(len(expansion)):
        if i == 0:
            convergents.append((expansion[0], 1))
        elif i == 1:
            convergents.append((expansion[0] * expansion[1] + 1, expansion[1]))
        else:
            p0, q0 = convergents[i - 2]
            p1, q1 = convergents[i - 1]
            p = expansion[i] * p1 + p0
            q = expansion[i] * q1 + q0
            convergents.append((p, q))
    return convergents

def wiener_attack(e, n):
    expansion = continued_fraction_expansion(e, n)
    convergents = convergents_from_continued_fraction(expansion)

    for k, d in convergents:
        if k == 0:
            continue
        phi_n = (e * d - 1) // k
        x = n - phi_n + 1
        discriminant = x * x - 4 * n
        if discriminant >= 0:
            t = isqrt(discriminant)
            if t * t == discriminant and (x + t) % 2 == 0:
                return d
    return None

def decrypt_rsa(ciphertext, public_key):
    try:
        n = public_key.n
        e = public_key.e

        # Convert ciphertext to an integer
        c = int.from_bytes(ciphertext, byteorder='big')
        print(f"Texte chiffré (en entier) : {c}")

        # Perform Wiener attack to find d
        d = wiener_attack(e, n)
        if d is None:
            print("L'attaque de Wiener a échoué.")
            return None

        print(f"Exposant privé calculé : d={d}")

        # Decrypt the message
        m = pow(c, d, n)

        # Convert the message back to bytes
        plaintext = long_to_bytes(m)

        return plaintext
    except Exception as e:
        print(f"Erreur lors du déchiffrement : {e}")
        return None

def main():
    public_key = load_public_key('public.pem')
    if public_key is None:
        return

    try:
        with open('flag.enc', 'rb') as f:
            ciphertext = f.read()
        print(f"Texte chiffré (en bytes) : {ciphertext}")
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier chiffré : {e}")
        return

    plaintext = decrypt_rsa(ciphertext, public_key)
    if plaintext:
        try:
            print("Decrypted message (as text):", plaintext.decode('utf-8'))
        except UnicodeDecodeError:
            print("Le message déchiffré n'est pas du texte UTF-8 valide.")
            print("Decrypted message (as bytes):", plaintext)

if __name__ == "__main__":
    main()
