"""
AES-шифратор / дешифратор (консоль).
Шифрует и расшифровывает текст паролем, используя настоящий AES-256-GCM.

Как это работает (для объяснения учителю):
1. Из пароля через PBKDF2 (100 000 итераций, случайная соль) получается
   256-битный ключ AES.
2. Текст шифруется AES-256 в режиме GCM — это даёт и шифрование,
   и защиту от подделки (если файл/строку испортить, расшифровка
   честно скажет "неверный пароль или данные повреждены", а не
   выдаст мусор как настоящий текст).
3. Результат — одна строка в base64: соль + nonce + шифротекст.
   Её удобно копировать/пересылать/вставлять в сайт-шифратор (encryptor.html) —
   формат совпадает.

Запуск:  python cipher.py
"""

import base64
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_LEN = 16       # байт
NONCE_LEN = 12      # байт, стандарт для GCM
KEY_LEN = 32        # 256 бит
PBKDF2_ITERS = 100_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = salt + nonce + ciphertext
    return base64.b64encode(blob).decode("ascii")


def decrypt(token_b64: str, password: str) -> str:
    try:
        blob = base64.b64decode(token_b64)
    except Exception:
        raise ValueError("Это не похоже на зашифрованную строку (не base64).")

    if len(blob) < SALT_LEN + NONCE_LEN:
        raise ValueError("Строка слишком короткая — повреждена.")

    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Неверный пароль или данные повреждены.")
    return plaintext.decode("utf-8")


def ask_password(prompt: str) -> str:
    pwd = input(prompt).strip()
    while not pwd:
        print("Пароль не может быть пустым.")
        pwd = input(prompt).strip()
    return pwd


def menu():
    print("=" * 50)
    print("  AES-256 шифратор / дешифратор")
    print("=" * 50)
    print("1 - Зашифровать текст")
    print("2 - Расшифровать текст")
    print("0 - Выход")

    while True:
        choice = input("\nВыбери действие (0/1/2): ").strip()

        if choice == "1":
            text = input("Текст для шифрования: ")
            if not text:
                print("Пустой текст, шифровать нечего.")
                continue
            password = ask_password("Пароль для шифрования: ")
            token = encrypt(text, password)
            print("\nЗашифрованная строка (сохрани/перешли её):")
            print(token)

        elif choice == "2":
            token = input("Зашифрованная строка: ").strip()
            if not token:
                print("Пустая строка.")
                continue
            password = ask_password("Пароль: ")
            try:
                text = decrypt(token, password)
                print("\nРасшифрованный текст:")
                print(text)
            except ValueError as e:
                print(f"\nОшибка: {e}")

        elif choice == "0":
            print("Пока!")
            sys.exit(0)

        else:
            print("Нет такого пункта, выбери 0, 1 или 2.")


if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(0)
