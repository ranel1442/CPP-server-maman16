import struct
from dataclasses import dataclass

# קבועי שרת ורשת
SERVER_VERSION = 3
DEFAULT_PORT = 1369
PORT_INFO_FILE = "port.info"
CLIENT_TIMEOUT_SECONDS = 300  # 5 דקות חוסר פעילות

# גדלי שדות קבועים בפרוטוקול (בבתים)
CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
CONTENT_SIZE_FIELD = 4
ORIG_FILE_SIZE_FIELD = 4
PACKET_INFO_SIZE = 4
CKSUM_SIZE = 4

# פורמטים של כותרות ב-Little Endian (<)
# כותרת בקשה: Client ID (16s), Version (B - 1 byte), Code (H - 2 bytes), Payload Size (I - 4 bytes)
REQUEST_HEADER_FORMAT = "<16sBHI"
REQUEST_HEADER_SIZE = struct.calcsize(REQUEST_HEADER_FORMAT)  # 23 בתים

# כותרת תשובה: Version (B - 1 byte), Code (H - 2 bytes), Payload Size (I - 4 bytes)
RESPONSE_HEADER_FORMAT = "<BHI" """מייצג """קודי # - 7 @classmethod @dataclass CRC_INVALID_ABORT="902" CRC_INVALID_RETRY="901" CRC_OK="900" FILE_RECEIVED_WITH_CRC="1603" GENERAL_ERROR="1607" MESSAGE_RECEIVED_THANKS="1604" PUBLIC_KEY_RECEIVED_SEND_AES="1602" RECONNECT="827" RECONNECT_APPROVED_SEND_AES="1605" RECONNECT_REJECTED="1606" REGISTER="825" REGISTER_FAILED="1601" REGISTER_SUCCESS="1600" RESPONSE_HEADER_SIZE="struct.calcsize(RESPONSE_HEADER_FORMAT)" RequestCode: RequestHeader: ResponseCode: SEND_FILE="828" SEND_PUBLIC_KEY="826" bytes bytes) class client_id: code: def int payload_size: raw_bytes: unpack(cls, version: בקשה בקשות בתים כותרת ללקוח""" לשרת""" מהלקוח מהלקוח""" מהשרת שהתקבלה תשובות> "RequestHeader":
        if len(raw_bytes) != REQUEST_HEADER_SIZE:
            raise ValueError(f"Invalid request header size: {len(raw_bytes)}")
        client_id, version, code, payload_size = struct.unpack(
            REQUEST_HEADER_FORMAT, raw_bytes
        )
        return cls(client_id, version, code, payload_size)


def pack_response(code: int, payload: bytes = b"") -> bytes:
    """אורז כותרת תשובה יחד עם תוכן התשובה (Payload) בפורמט Little Endian"""
    header = struct.pack(
        RESPONSE_HEADER_FORMAT,
        SERVER_VERSION,
        code,
        len(payload),
    )
    return header + payload


def extract_null_terminated_string(raw_bytes: bytes) -> str:
    """מחלץ מחרוזת ASCII מתוך שדה בגודל קבוע המרופד בתווי null"""
    null_index = raw_bytes.find(b"\x00")
    if null_index == -1:
        raise ValueError("String field is not null-terminated")
    return raw_bytes[:null_index].decode("ascii", errors="strict")


def _generate_posix_crc_table() -> list[int]:
    """מייצר את טבלת ה-CRC-32 לפי תקן POSIX של פקודת cksum בלינוקס"""
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


def calculate_cksum(data: bytes) -> int:
    """מחשב Checksum באופן זהה לפקודת cksum בלינוקס"""
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