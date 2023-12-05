import hashlib

def passwrd():
    while True:
        new_password = input("Entrez un mot de passe:")

        if len(new_password) < 8:
            print("Le mot de passe doit contenir au moins 8 caractères.")
            continue

        if not any(char.islower() for char in new_password):
            print("Le mot de passe doit contenir au moins une lettre minuscule.")
            continue

        if not any(char.isupper() for char in new_password):
            print("Le mot de passe doit contenir au moins une lettre majuscule.")
            continue

        if not any(char.isdigit() for char in new_password):
            print("Le mot de passe doit contenir au moins un chiffre.")
            continue

        if not any(not char.isalnum() for char in new_password):
            print("Le mot de passe doit contenir au moins un caractère spécial.")
            continue

        break

    return new_password

def encrypt_passwrd(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    encrypted_password = sha256.hexdigest()
    return encrypted_password


password = passwrd()
encrypted_password = encrypt_passwrd(password)
print("Mot de passe original :", password)
print("Mot de passe crypté (SHA-256) :", encrypted_password)



