"""
קובץ: crypto_utils.py
מימוש מנגנוני ההצפנה והפענוח בצד השרת באמצעות חבילת PyCryptodome (לפי דרישת עמוד 1 סעיף ד' ועמודים 8-9 במטלה).

הקובץ אחראי על:
1. ייצור מפתח סימטרי AES באורך 256 ביט (32 בתים).
2. אימות מפתח ציבורי RSA-1024 (באורך 160 בתים בפורמט X.509) שמתקבל מהלקוח.
3. הצפנת מפתח ה-AES באמצעות המפתח הציבורי של הלקוח (RSA) לשליחה בתשובות 1602 ו-1605.
4. פענוח קבצים שהוצפנו ב-AES-CBC עם וקטור אתחול (IV) מאופס של 16 בתים (בקשה 828).
"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

# הגדרת קבועי ההצפנה הסימטרית לפי עמוד 9 במטלה:
# אורך מפתח AES הוא 256 ביט (32 בתים), גודל בלוק הוא 16 בתים, וה-IV תמיד מאופס (16 בתים של אפסים).
AES_KEY_SIZE = 32
AES_BLOCK_SIZE = 16
ZERO_IV = b"\x00" * 16


# מימוש ייצור מפתח AES חדש באורך 256 ביט עבור לקוח (לפי עמוד 2 סעיף 4.ב ועמוד 9 במטלה)
def generate_aes_key() -> bytes:
    return get_random_bytes(AES_KEY_SIZE)


# בדיקת תקינות המפתח הציבורי RSA (160 בתים בפורמט X.509) שהתקבל מהלקוח (לפי עמודים 6, 8 ו-11 במטלה)
def validate_rsa_public_key(public_key_bytes: bytes) -> bool:
    try:
        RSA.import_key(public_key_bytes)
        return True
    except (ValueError, IndexError, TypeError):
        return False


# הצפנת מפתח ה-AES הסימטרי בעזרת המפתח הציבורי (RSA) של הלקוח (לפי עמוד 2 סעיף 4.ב ועמוד 8 בתשובות 1602 ו-1605)
def encrypt_aes_key_with_rsa(public_key_bytes: bytes, aes_key: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(aes_key)


# פענוח תוכן הקובץ המוצפן שהתקבל מהלקוח באמצעות AES-CBC עם IV מאופס (לפי עמוד 2 סעיף 4.ג ועמוד 9 במטלה)
def decrypt_file_aes_cbc(encrypted_data: bytes, aes_key: bytes) -> bytes:
    if not encrypted_data or len(encrypted_data) % AES_BLOCK_SIZE != 0:
        raise ValueError(f"Invalid encrypted file size ({len(encrypted_data)} bytes)")
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=ZERO_IV)
    decrypted_padded = cipher_aes.decrypt(encrypted_data)
    return unpad(decrypted_padded, AES_BLOCK_SIZE)
