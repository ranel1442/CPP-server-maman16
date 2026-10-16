"""Protocol constants, binary headers packing/unpacking, and POSIX cksum calculation."""

import struct
from dataclasses import dataclass
from enum import IntEnum

# Server constants per specification
SERVER_VERSION = 3
DEFAULT_PORT = 1369
PORT_INFO_FILE = "port.info"
CLIENT_TIMEOUT_SECONDS = 300  # 5 minutes timeout

# Fixed field sizes (in bytes) per protocol tables
CLIENT_ID_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
CONTENT_SIZE_FIELD = 4
ORIG_FILE_SIZE_FIELD = 4
PACKET_NUMBER_SIZE = 2
TOTAL_PACKETS_SIZE = 2
CKSUM_SIZE = 4

# Little-endian (<) unsigned struct formats
# Request header: Client ID (16s), Version (B: 1B), Code (H: 2B), Payload size (I: 4B)
REQUEST_HEADER_FORMAT = "<16sBHI"
REQUEST_HEADER_SIZE = struct.calcsize(REQUEST_HEADER_FORMAT)  # 23 bytes

# Response header: Version (B: 1B), Code (H: 2B), Payload size (I: 4B)
RESPONSE_HEADER_FORMAT = "<BHI"
RESPONSE_HEADER_SIZE = struct.calcsize(RESPONSE_HEADER_FORMAT)  # 7 bytes


class RequestCode(IntEnum):
    """Client request codes."""

    REGISTER = 825
    SEND_PUBLIC_KEY = 826
    RECONNECT = 827
    SEND_FILE = 828
    CRC_OK = 900
    CRC_INVALID_RETRY = 901
    CRC_INVALID_ABORT = 902


class ResponseCode(IntEnum):
    """Server response codes."""

    REGISTER_SUCCESS = 1600
    REGISTER_FAILED = 1601
    PUBLIC_KEY_RECEIVED_SEND_AES = 1602
    FILE_RECEIVED_WITH_CRC = 1603
    MESSAGE_RECEIVED_THANKS = 1604
    RECONNECT_APPROVED_SEND_AES = 1605
    RECONNECT_REJECTED = 1606
    GENERAL_ERROR = 1607


@dataclass
class RequestHeader:
    """Represents the 23-byte binary request header sent by a client."""

    client_id: bytes
    version: int
    code: int
    payload_size: int

    @classmethod
    def unpack(cls, raw_bytes: bytes) -> "RequestHeader":
        """Unpack 23 raw bytes into a RequestHeader instance."""
        if len(raw_bytes) != REQUEST_HEADER_SIZE:
            raise ValueError(f"Expected {REQUEST_HEADER_SIZE} bytes, got {len(raw_bytes)}")
        client_id, version, code, payload_size = struct.unpack(
            REQUEST_HEADER_FORMAT, raw_bytes
        )
        return cls(client_id, version, code, payload_size)


def pack_response(code: int, payload: bytes = b"") -> bytes:
    """Pack a server response header and payload in little-endian format."""
    header = struct.pack(
        RESPONSE_HEADER_FORMAT,
        SERVER_VERSION,
         int(code),
        len(payload),
    )
    return header + payload


def extract_null_terminated_string(raw_bytes: bytes) -> str:
    """Extract an ASCII null-terminated string from a fixed-size byte buffer."""
    null_index = raw_bytes.find(b"\x00")
    if null_index == -1:
        raise ValueError("Null terminator not found in fixed-size string field")
    return raw_bytes[:null_index].decode("ascii", errors="strict")


def pack_fixed_string(text: str, size: int = NAME_SIZE) -> bytes:
    """Encode an ASCII string into a fixed-size null-padded byte buffer."""
    encoded = text.encode("ascii", errors="strict")
    if len(encoded) >= size:
        raise ValueError(f"String exceeds maximum allowed length of {size - 1} bytes")
    return encoded.ljust(size, b"\x00")


def _generate_posix_crc_table() -> list[int]:
    """Generate the 256-entry lookup table for POSIX 1003.2 cksum."""
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
    """Calculate unsigned 32-bit checksum identical to Linux cksum command."""
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