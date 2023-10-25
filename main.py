import fernet as Fernet
import bcrypt


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def check_password(password, hashed_password):
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        print("Пароль верный")
    else:
        print("Пароль неверный")


if __name__ == '__main__':
    password = input("Введите пароль: ")
    hashed_password = hash_password(password)
    print("Хэшированный пароль:", hashed_password)
    password_to_check = input("Введите пароль для проверки: ")
    check_password(password_to_check, hashed_password)

    key = Fernet.generate_key()

    with open("key.key", "wb") as key_file:
        key_file.write(key)

    with open("key.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    with open("key.key", "rb") as key_file:
        key = key_file.read()
        return key


def encrypt_file(filename, key):
    cipher = Fernet(key)
    with open(filename, "rb") as file:
        data = file.read()
        encrypted_data = cipher.encrypt(data)
    with open(filename + ".encrypted", "wb") as file:
        file.write(encrypted_data)

def decrypt_file(filename, key):
    cipher = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
        decrypted_data = cipher.decrypt(encrypted_data)
    with open(filename[:-10], "wb") as file:
        file.write(decrypted_data)

if __name__ == '__main__':
    choice = input("Введите 'g', чтобы сгенерировать новый ключ или 'l', чтобы загрузить ключ из файла: ")
    if choice.lower() == "g":
        Fernet.generate_key()

        key = load_key()

    action = input("Введите 'e', чтобы зашифровать файл, или 'd', чтобы расшифровать файл: ")

    if action.lower() == "e":
        filename = input("Введите имя файла для шифрования: ")
        encrypt_file(filename, key)
        print("Файл успешно зашифрован.")
    elif action.lower() == "d":
        filename = input("Введите имя файла для расшифровки: ")
        decrypt_file(filename, key)
        print("Файл успешно расшифрован.")

