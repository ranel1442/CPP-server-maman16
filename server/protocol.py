"""
קובץ: protocol.py
מימוש פרוטוקול התקשורת הבינארי בצד השרת (בהתאם לעמודים 5-8 בחוברת המטלה).

הקובץ מרכז את הקבועים של הפרוטוקול, קודי הבקשות והתשובות,
ופונקציות עזר לאריזה ופריקה של הודעות בינאריות בפורמט Little-Endian (ללא סימן - unsigned).
בנוסף, הקובץ מממש את חישוב ה-CRC הזהה לפקודת cksum בלינוקס (לפי דרישת עמוד 2 סעיף 4.ג).
"""

import struct
from dataclasses import dataclass
from enum import IntEnum

# גרסת השרת היא 3, פורט ברירת המחדל הוא 1369 אם port.info לא קיים, וניתוק לקוח לאחר 5 דקות חוסר פעילות.


SERVER_VERSION = 3
DEFAULT_PORT = 1369
PORT_INFO_FILE = "port.info"
CLIENT_TIMEOUT_SECONDS = 300

# גדלי השדות הקבועים (בבתים) לפי טבלאות הפרוטוקול בעמודים 6-8 במטלה:
CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
CONTENT_SIZE_FIELD = 4
ORIG_FILE_SIZE_FIELD = 4
PACKET_NUMBER_SIZE = 2
TOTAL_PACKETS_SIZE = 2
CKSUM_SIZE = 4

# מימוש מבנה הכותרות הבינאריות לפי עמודים 5-7 במטלה:
# כל השדות המספריים הם unsigned ומיוצגים ב-Little-Endian (<).
# כותרת בקשה מהלקוח (23 בתים): Client ID (16s), Version (B - בית 1), Code (H - 2 בתים), Payload size (I - 4 בתים)
REQUEST_HEADER_FORMAT = "<16sBHI"
REQUEST_HEADER_SIZE = struct.calcsize(REQUEST_HEADER_FORMAT)

# כותרת תשובה מהשרת (7 בתים): Version (B - בית 1), Code (H - 2 בתים), Payload size (I - 4 בתים)
RESPONSE_HEADER_FORMAT = "<BHI"
RESPONSE_HEADER_SIZE = struct.calcsize(RESPONSE_HEADER_FORMAT)


# מימוש קודי הבקשות מהלקוח לשרת לפי הטבלאות בעמודים 6-7 במטלה
class RequestCode(IntEnum):
    REGISTER = 825            # רישום לקוח חדש
    SEND_PUBLIC_KEY = 826     # שליחת מפתח ציבורי RSA של הלקוח
    RECONNECT = 827           # התחברות חוזרת של לקוח רשום
    SEND_FILE = 828           # שליחת קובץ מוצפן (בחבילה אחת או יותר)
    CRC_OK = 900              # הלקוח מאשר שה-CRC תקין
    CRC_INVALID_RETRY = 901   # CRC לא תקין, הלקוח ישלח שוב את הקובץ (בקשה 828)
    CRC_INVALID_ABORT = 902   # CRC לא תקין בפעם הרביעית, סיום וביטול העברת הקובץ


# מימוש קודי התשובות מהשרת ללקוח לפי הטבלאות בעמודים 7-8 במטלה
class ResponseCode(IntEnum):
    REGISTER_SUCCESS = 1600               # רישום הצליח
    REGISTER_FAILED = 1601                # רישום נכשל
    PUBLIC_KEY_RECEIVED_SEND_AES = 1602   # התקבל מפתח ציבורי ושולח מפתח AES מוצפן
    FILE_RECEIVED_WITH_CRC = 1603         # קובץ התקבל תקין עם CRC
    MESSAGE_RECEIVED_THANKS = 1604        # מאשר קבלת הודע תודה תגובה ל900 או 902
    RECONNECT_APPROVED_SEND_AES = 1605    # מאשר בקשה להתחברות חוזרת, שולח מפתח AES מוצפן
    RECONNECT_REJECTED = 1606              # בקשה להתחברות חוזרת נדחתה הלקוח יירשם מחדש
    GENERAL_ERROR = 1607                  # שגיאה כללית בשרת


# מחלקה המייצגת את כותרת הבקשה בת 23 הבתים שמתקבלת מהלקוח (לפי הטבלה בעמוד 6)
@dataclass
class RequestHeader:
    client_id: bytes
    version: int
    code: int
    payload_size: int

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> "RequestHeader":
        """פירוק 23 הבתים של כותרת הבקשה באמצעות מודול struct לפי דגשי השרת בעמוד 11."""
        if len(raw_bytes) != REQUEST_HEADER_SIZE:
            raise ValueError(f"Expected {REQUEST_HEADER_SIZE} header bytes, got {len(raw_bytes)}")
        client_id, version, code, payload_size = struct.unpack(REQUEST_HEADER_FORMAT, raw_bytes)
        return cls(client_id, version, code, payload_size)


# מימוש בניית תשובת שרת (כותרת בת 7 בתים + תוכן ה-Payload) בפורמט Little-Endian לפי עמוד 7 במטלה
def pack_response(code: int, payload: bytes = b"") -> bytes:
    header = struct.pack(RESPONSE_HEADER_FORMAT, SERVER_VERSION, int(code), len(payload))
    return header + payload


# חילוץ מחרוזת ASCII מתוך שדה בגודל קבוע (255 בתים) הכולל תו מסיים null ('\x00'), לפי עמודים 6-7 במטלה
def extract_null_terminated_string(raw_bytes: bytes) -> str:
    null_index = raw_bytes.find(b"\x00")
    if null_index == -1:
        raise ValueError("Null terminator not found in fixed-size string field")
    return raw_bytes[:null_index].decode("ascii", errors="strict")


# אריזת מחרוזת ASCII לשדה בגודל קבוע של 255 בתים מרופד באפסים (null-terminated), עבור תשובה 1603 בעמוד 8
def pack_fixed_string(text: str, size: int = NAME_SIZE) -> bytes:
    encoded = text.encode("ascii", errors="strict")
    if len(encoded) >= size:
        raise ValueError(f"String exceeds maximum allowed length of {size - 1} bytes")
    return encoded.ljust(size, b"\x00")


# בניית טבלת ה-CRC של תקן POSIX 1003.2 לצורך חישוב זהה לפקודת cksum בלינוקס (לפי דרישת עמוד 2 סעיף 4.ג)
def _generate_posix_crc_table() -> list[int]:
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


_CRC_TABLE = _generate_posix_crc_table()


# חישוב ה-CRC של קובץ באופן זהה לפקודת cksum בלינוקס (לפי עמוד 2 סעיף 4.ג במטלה)
def calculate_cksum(data: bytes) -> int:
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
