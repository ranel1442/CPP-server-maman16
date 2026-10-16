"""
מודול פרוטוקול תקשורת בינארי (protocol.py) עבור צד השרת.

מודול זה מגדיר את כל הקבועים, גדלי השדות, קודי הבקשות והתשובות,
ומספק פונקציות עזר לאריזה ופריקה (Packing/Unpacking) של כותרות ומחרוזות
בפורמט Little-Endian, וכן חישוב Checksum לפי תקן POSIX 1003.2 (זהה לפקודת cksum בלינוקס).

מי קורא למודול זה:
- הקובץ `server.py` מייבא מודול זה לצורך פענוח כותרות הבקשות המגיעות מהלקוח (RequestHeader),
  בניית תשובות השרת (pack_response), חילוץ ואריזת שמות משתמשים וקבצים (extract_null_terminated_string, pack_fixed_string),
  וחישוב ערך ה-CRC של קבצים שהתקבלו ופוענחו (calculate_cksum).
"""

import struct
from dataclasses import dataclass
from enum import IntEnum

# ==============================================================================
# קבועי מערכת השרת לפי מפרט הפרוטוקול
# ==============================================================================
SERVER_VERSION = 3               # גרסת השרת הנוכחית (1 בית, unsigned char)
DEFAULT_PORT = 1369              # פורט ברירת מחדל במקרה שקובץ port.info אינו קיים או לא תקין
PORT_INFO_FILE = "port.info"     # שם הקובץ שממנו השרת קורא את מספר הפורט להאזנה
CLIENT_TIMEOUT_SECONDS = 300     # זמן המתנה מקסימלי (בשניות) ללקוח לא פעיל (5 דקות)

# ==============================================================================
# גדלי שדות קבועים (בבתים) לפי טבלאות הפרוטוקול
# ==============================================================================
CLIENT_ID_SIZE = 16              # גודל מזהה לקוח ייחודי (UUID - 16 בתים)
NAME_SIZE = 255                  # גודל שדה שם לקוח או שם קובץ (מחרוזת ASCII מרופדת ב-null)
PUBLIC_KEY_SIZE = 160            # גודל מפתח ציבורי RSA-1024 בפורמט X.509 SubjectPublicKeyInfo
CONTENT_SIZE_FIELD = 4           # גודל שדה Content Size (גודל הקובץ המוצפן בבתים - unsigned int)
ORIG_FILE_SIZE_FIELD = 4         # גודל שדה Orig File Size (גודל הקובץ המקורי לפני הצפנה - unsigned int)
PACKET_NUMBER_SIZE = 2           # גודל שדה Packet Number (מספר החבילה הנוכחית - unsigned short)
TOTAL_PACKETS_SIZE = 2           # גודל שדה Total Packets (סה"כ חבילות בקובץ - unsigned short)
CKSUM_SIZE = 4                   # גודל שדה ה-CRC / Checksum בתשובה 1603 (unsigned int)

# ==============================================================================
# תבניות struct לפריקה ואריזה בפורמט Little-Endian (<) וללא סימן (Unsigned)
# ==============================================================================
# מבנה כותרת בקשה (Request Header):
# Client ID (16s: 16 בתים), Version (B: בית 1), Code (H: 2 בתים), Payload Size (I: 4 בתים)
REQUEST_HEADER_FORMAT = "<16sBHI"
REQUEST_HEADER_SIZE = struct.calcsize(REQUEST_HEADER_FORMAT)  # סה"כ 23 בתים

# מבנה כותרת תשובה (Response Header):
# Version (B: בית 1), Code (H: 2 בתים), Payload Size (I: 4 בתים)
RESPONSE_HEADER_FORMAT = "<BHI"
RESPONSE_HEADER_SIZE = struct.calcsize(RESPONSE_HEADER_FORMAT)  # סה"כ 7 בתים


class RequestCode(IntEnum):
    """
    קודי הבקשות (Request Codes) שהלקוח שולח לשרת בכותרת הבקשה (2 בתים, Little-Endian).
    נקראים על ידי `Server._process_request` ב-`server.py` לניתוב הבקשה לפונקציה המתאימה.
    """

    REGISTER = 825            # בקשת רישום לקוח חדש (Payload: שם לקוח - 255 בתים)
    SEND_PUBLIC_KEY = 826     # שליחת מפתח ציבורי RSA (Payload: שם לקוח 255 בתים + מפתח ציבורי 160 בתים)
    RECONNECT = 827           # בקשת התחברות חוזרת של לקוח רשום (Payload: שם לקוח - 255 בתים)
    SEND_FILE = 828           # שליחת חבילה של קובץ מוצפן ב-AES
    CRC_OK = 900              # אישור מהלקוח שחישוב ה-CRC תואם ותקין (Payload: שם קובץ - 255 בתים)
    CRC_INVALID_RETRY = 901   # הודעה מהלקוח שה-CRC שגוי והוא שולח את הקובץ מחדש (Payload: שם קובץ - 255 בתים)
    CRC_INVALID_ABORT = 902   # הודעה מהלקוח על כישלון CRC בפעם הרביעית וביטול העברת הקובץ (Payload: שם קובץ - 255 בתים)


class ResponseCode(IntEnum):
    """
    קודי התשובות (Response Codes) שהשרת מחזיר ללקוח בכותרת התשובה (2 בתים, Little-Endian).
    נארזים על ידי הפונקציה `pack_response` ומוחזרים מפונקציות הטיפול ב-`server.py`.
    """

    REGISTER_SUCCESS = 1600               # רישום הצליח (Payload: Client ID - 16 בתים)
    REGISTER_FAILED = 1601                # רישום נכשל (ללא Payload)
    PUBLIC_KEY_RECEIVED_SEND_AES = 1602   # מפתח ציבורי התקבל, נשלח מפתח AES מוצפן ב-RSA (Payload: Client ID + Encrypted AES)
    FILE_RECEIVED_WITH_CRC = 1603         # קובץ התקבל במלואו ופוענח, מצורף CRC (Payload: Client ID + Content Size + File Name + Cksum)
    MESSAGE_RECEIVED_THANKS = 1604        # אישור קבלת הודעה סופית עבור 900 או 902 (Payload: Client ID - 16 בתים)
    RECONNECT_APPROVED_SEND_AES = 1605    # התחברות חוזרת אושרה, נשלח מפתח AES חדש מוצפן (Payload: Client ID + Encrypted AES)
    RECONNECT_REJECTED = 1606             # התחברות חוזרת נדחתה - הלקוח לא קיים או אין לו מפתח ציבורי (Payload: Client ID - 16 בתים)
    GENERAL_ERROR = 1607                  # שגיאה כללית בשרת (ללא Payload)


@dataclass
class RequestHeader:
    """
    מחלקה המייצגת את כותרת הבקשה הבינארית (23 בתים) שמתקבלת מהלקוח.

    שדות המחלקה:
    - client_id (bytes): מזהה הלקוח הייחודי (16 בתים).
    - version (int): גרסת תוכנת הלקוח (1 בית, unsigned).
    - code (int): קוד הבקשה לפי `RequestCode` (2 בתים, unsigned short).
    - payload_size (int): גודל גוף ההודעה (Payload) בבתים שמגיע מיד אחרי הכותרת (4 בתים, unsigned int).
    """

    client_id: bytes
    version: int
    code: int
    payload_size: int

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> "RequestHeader":
        """
        פריקת 23 בתים גולמיים שהתקבלו מהסוקט למוופע של `RequestHeader`.
        נקראת מתוך `Server._handle_client_connection` ב-`server.py`.
        """
        if len(raw_bytes) != REQUEST_HEADER_SIZE:
            raise ValueError(f"Expected {REQUEST_HEADER_SIZE} bytes, got {len(raw_bytes)}")
        client_id, version, code, payload_size = struct.unpack(
            REQUEST_HEADER_FORMAT, raw_bytes
        )
        return cls(client_id, version, code, payload_size)


def pack_response(code: int, payload: bytes = b"") -> bytes:
    """
    אריזת תשובת שרת מלאה (כותרת בת 7 בתים + Payload) בפורמט Little-Endian.

    פרמטרים:
    - code (int): קוד התשובה מתוך `ResponseCode`.
    - payload (bytes): תוכן התשובה הבינארי (ברירת מחדל: ריק).

    ערך מוחזר:
    - bytes: מערך בתים המוכן לשליחה ישירה לסוקט הלקוח (`sendall`).
    """
    header = struct.pack(
        RESPONSE_HEADER_FORMAT,
        SERVER_VERSION,
        int(code),
        len(payload),
    )
    return header + payload


def extract_null_terminated_string(raw_bytes: bytes) -> str:
    """
    חילוץ מחרוזת ASCII מתוך שדה בגודל קבוע (255 בתים) המרופד בתווי null ('\\x00').
    קוראת את כל הבתים עד לתו ה-null הראשון ומפענחת אותם כ-ASCII.
    נקראת ב-`server.py` לחילוץ שם לקוח (בקשות 825, 826, 827) או שם קובץ (בקשות 828, 900, 901, 902).
    """
    null_index = raw_bytes.find(b"\x00")
    if null_index == -1:
        raise ValueError("Null terminator not found in fixed-size string field")
    return raw_bytes[:null_index].decode("ascii", errors="strict")


def pack_fixed_string(text: str, size: int = NAME_SIZE) -> bytes:
    """
    קידוד מחרוזת ASCII לשדה בינארי בגודל קבוע (255 בתים) מרופד בתווי null ('\\x00') בסופו.
    נקראת ב-`server.py` בעת בניית תשובה 1603 (החזרת שם הקובץ ללקוח).
    """
    encoded = text.encode("ascii", errors="strict")
    if len(encoded) >= size:
        raise ValueError(f"String exceeds maximum allowed length of {size - 1} bytes")
    return encoded.ljust(size, b"\x00")


def _generate_posix_crc_table() -> list[int]:
    """
    פונקציית עזר פנימית המייצרת את טבלת החיפוש (256 איברים) עבור חישוב CRC-32 לפי תקן POSIX 1003.2.
    משתמשת בפולינום הגנרטור 0x04C11DB7. נקראת פעם אחת בלבד בעת טעינת המודול.
    """
    poly = 0x04C11DB7
    table = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ poly) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
        table.append(crc)
    return table


# טבלת ה-CRC הקבועה בזיכרון לחישוב מהיר של calculate_cksum
_CRC_TABLE = _generate_posix_crc_table()


def calculate_cksum(data: bytes) -> int:
    """
    חישוב Checksum (32-bit unsigned int) הזהה לחלוטין לפלט פקודת `cksum` בלינוקס (POSIX 1003.2).
    האלגוריתם מעבד את כל בתי הקובץ, מוסיף לחישוב את אורך הקובץ באוקטטות, ובסוף מבצע היפוך סיביות (bitwise NOT).
    נקראת ב-`Server._handle_send_file` על תוכן הקובץ המפוענח לפני שליחת תשובה 1603.
    """
    crc = 0
    for byte in data:
        idx = ((crc >> 24) ^ byte) & 0xFF
        crc = ((crc << 8) ^ _CRC_TABLE[idx]) & 0xFFFFFFFF

    length = len(data)
    while length > 0:
        idx = ((crc >> 24) ^ (length & 0xFF)) & 0xFF
        crc = ((crc << 8) ^ _CRC_TABLE[idx]) & 0xFFFFFFFF
        length >>= 8

    return (~crc) & 0xFFFFFFFF