"""
מודול עזר קריפטוגרפי (crypto_utils.py) עבור צד השרת.

מודול זה מרכז את כל פעולות ההצפנה, הפענוח וייצור המפתחות של השרת באמצעות ספריית PyCryptodome:
1. ייצור מפתח סימטרי AES באורך 256 ביט (32 בתים).
2. אימות תקינות מפתח ציבורי RSA-1024 (באורך 160 בתים בפורמט X.509 / DER) שהתקבל מהלקוח.
3. הצפנת מפתח ה-AES באמצעות המפתח הציבורי (RSA-OAEP) של הלקוח לשליחה בתשובות 1602 ו-1605.
4. פענוח תוכן קובץ שהוצפן ב-AES-CBC (עם וקטור אתחול IV מאופס של 16 בתים וריפוד PKCS#7) בבקשה 828.

מי קורא למודול זה:
- הקובץ `server.py` מייבא וקורא לפונקציות במודול זה מתוך:
  * `_handle_send_public_key` (קוד 826) - אימות מפתח RSA, יצירת מפתח AES והצפנתו.
  * `_handle_reconnect` (קוד 827) - יצירת מפתח AES חדש והצפנתו במפתח ה-RSA השמור של הלקוח.
  * `_handle_send_file` (קוד 828) - פענוח תוכן הקובץ המוצפן לאחר קבלת כל החבילות.
"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

# ==============================================================================
# קבועים קריפטוגרפיים לפי מפרט הפרוטוקול
# ==============================================================================
AES_KEY_SIZE = 32          # גודל מפתח AES-256 בבתים (256 ביט = 32 בתים)
AES_BLOCK_SIZE = 16        # גודל בלוק של AES בבתים (128 ביט = 16 בתים)
ZERO_IV = b"\x00" * 16     # וקטור אתחול (Initialization Vector) קבוע של 16 בתים מאופסים כנדרש במטלה


def generate_aes_key() -> bytes:
    """
    ייצור מפתח AES אקראי ובטוח קריפטוגרפית באורך 32 בתים (256 ביט).

    מי קורא לפונקציה:
    - `Server._handle_send_public_key` (קוד 826) בעת רישום מפתח ציבורי ראשוני.
    - `Server._handle_reconnect` (קוד 827) בעת התחברות חוזרת של לקוח קיים.

    ערך מוחזר:
    - bytes: מפתח AES באורך 32 בתים.
    """
    return get_random_bytes(AES_KEY_SIZE)


def validate_rsa_public_key(public_key_bytes: bytes) -> bool:
    """
    בדיקת תקינות של מפתח ציבורי RSA שהתקבל מהלקוח (160 בתים בפורמט X.509 SubjectPublicKeyInfo).

    מי קורא לפונקציה:
    - `Server._handle_send_public_key` (קוד 826) לפני שמירת המפתח ב-RAM והצפנת מפתח ה-AES.

    פרמטרים:
    - public_key_bytes (bytes): מערך הבתים של המפתח הציבורי שהתקבל ב-Payload של בקשה 826.

    ערך מוחזר:
    - bool: מחזיר True אם המפתח תקין וניתן לטעינה כמפתח RSA, אחרת False.
    """
    try:
        RSA.import_key(public_key_bytes)
        return True
    except (ValueError, IndexError, TypeError):
        return False


def encrypt_aes_key_with_rsa(public_key_bytes: bytes, aes_key: bytes) -> bytes:
    """
    הצפנת מפתח ה-AES הסימטרי באמצעות המפתח הציבורי (RSA) של הלקוח לפי תקן PKCS#1 OAEP.
    תואם לפענוח בצד הלקוח (C++ Crypto++ `RSAES_OAEP_SHA_Decryptor`).

    מי קורא לפונקציה:
    - `Server._handle_send_public_key` (עבור תשובה 1602).
    - `Server._handle_reconnect` (עבור תשובה 1605).

    פרמטרים:
    - public_key_bytes (bytes): המפתח הציבורי של הלקוח (160 בתים).
    - aes_key (bytes): מפתח ה-AES הסימטרי להצפנה (32 בתים).

    ערך מוחזר:
    - bytes: מפתח ה-AES המוצפן ב-RSA (128 בתים עבור מפתח RSA של 1024 ביט).
    """
    rsa_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(aes_key)


def decrypt_file_aes_cbc(encrypted_data: bytes, aes_key: bytes) -> bytes:
    """
    פענוח תוכן קובץ שהוצפן באלגוריתם AES במצב CBC עם IV של 16 בתים מאופסים (ZERO_IV)
    והסרת ריפוד (Padding) מסוג PKCS#7.

    מי קורא לפונקציה:
    - `Server._handle_send_file` (קוד 828) ב-`server.py` לאחר שכל חבילות הקובץ התקבלו ונצברו ב-RAM.

    פרמטרים:
    - encrypted_data (bytes): תוכן הקובץ המוצפן המלא שנצבר מכל החבילות.
    - aes_key (bytes): מפתח ה-AES של הלקוח (32 בתים) השמור ב-RAM של השרת.

    ערך מוחזר:
    - bytes: תוכן הקובץ המקורי המפוענח (ללא הריפוד).
    """
    if not encrypted_data or len(encrypted_data) % AES_BLOCK_SIZE != 0:
        raise ValueError(
            f"Invalid encrypted file size ({len(encrypted_data)} bytes); "
            f"must be a non-empty multiple of {AES_BLOCK_SIZE}."
        )
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=ZERO_IV)
    decrypted_padded = cipher_aes.decrypt(encrypted_data)
    return unpad(decrypted_padded, AES_BLOCK_SIZE)

