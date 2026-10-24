"""
קובץ: server.py
מימוש תוכנת השרת הראשית בפייתון 3 (בהתאם לדרישות המטלה בעמודים 1-3, 5-13).

השרת מממש את כל דרישות המטלה:
1. קריאת הפורט מהקובץ port.info שבתיקיית השרת, או מעבר לפורט ברירת מחדל 1369 עם אזהרה וללא קריסה (עמודים 1-2).
2. שמירת נתוני הלקוחות והקבצים בזיכרון (RAM) בפורמט התואם לטבלאות clients ו-files, לצד תיקייה מקומית לשמירת הקבצים (עמודים 2 ו-13).
3. תמיכה בריבוי לקוחות במקביל באמצעות תהליכונים (threads) וניתוק לקוח לאחר 5 דקות חוסר פעילות (עמודים 1-2).
4. טיפול מלא בכל בקשות הפרוטוקול: 825 (רישום), 826 (מפתח ציבורי), 827 (התחברות חוזרת),
   828 (קבלת קובץ מוצפן בחבילות, פענוח וחישוב cksum), ו-900/901/902 (אימות ה-CRC).
"""

import os
import socket
import struct
import threading
import time
import uuid

# תמיכה בייבוא בין-קובצי גם בהרצה מתוך תיקיית server/ וגם מתיקיית האב
try:
    from protocol import (
        CLIENT_TIMEOUT_SECONDS,
        CONTENT_SIZE_FIELD,
        DEFAULT_PORT,
        NAME_SIZE,
        ORIG_FILE_SIZE_FIELD,
        PACKET_NUMBER_SIZE,
        PORT_INFO_FILE,
        PUBLIC_KEY_SIZE,
        REQUEST_HEADER_SIZE,
        TOTAL_PACKETS_SIZE,
        RequestCode,
        RequestHeader,
        ResponseCode,
        calculate_cksum,
        extract_null_terminated_string,
        pack_fixed_string,
        pack_response,
    )
    from crypto_utils import (
        decrypt_file_aes_cbc,
        encrypt_aes_key_with_rsa,
        generate_aes_key,
        validate_rsa_public_key,
    )
except ImportError:
    from server.protocol import (
        CLIENT_TIMEOUT_SECONDS,
        CONTENT_SIZE_FIELD,
        DEFAULT_PORT,
        NAME_SIZE,
        ORIG_FILE_SIZE_FIELD,
        PACKET_NUMBER_SIZE,
        PORT_INFO_FILE,
        PUBLIC_KEY_SIZE,
        REQUEST_HEADER_SIZE,
        TOTAL_PACKETS_SIZE,
        RequestCode,
        RequestHeader,
        ResponseCode,
        calculate_cksum,
        extract_null_terminated_string,
        pack_fixed_string,
        pack_response,
    )
    from server.crypto_utils import (
        decrypt_file_aes_cbc,
        encrypt_aes_key_with_rsa,
        generate_aes_key,
        validate_rsa_public_key,
    )


# מימוש מחלקת השרת הראשית המנהלת את החיבורים, מבני הנתונים ב-RAM ולוגיקת הפרוטוקול (לפי עמודים 1-2 במטלה)
class Server:
    def __init__(self, host: str = "0.0.0.0"):
        self.host = host
        self.port = self._read_port_from_file()

        # מימוש דרישת המטלה לשמירת נתוני הלקוחות והקבצים בזיכרון ה-RAM (עמוד 2 ועמוד 13):
        # המפתח במילון הוא מזהה הלקוח (16 בתים), והערך כולל את השם, המפתח הציבורי, מפתח ה-AES, זמן נראה לאחרונה והקבצים.
        self.clients_db: dict[bytes, dict] = {}
        self.db_lock = threading.Lock()

        # מימוש דרישת המטלה להחזקת תיקייה מקומית שתכלול את הקבצים שיתקבלו מלקוחות (עמוד 2)
        self.received_files_dir = "received_files"
        os.makedirs(self.received_files_dir, exist_ok=True)

    # מימוש דרישת המטלה לקריאת הפורט מקובץ port.info תוך הוצאת אזהרה וחזרה לפורט ברירת מחדל 1369
    # ללא נפילה עם Traceback במידה והקובץ לא זמין או לא תקין (לפי עמוד 1 ועמוד 2 סעיף 1).
    def _read_port_from_file(self) -> int:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        port_path = PORT_INFO_FILE if os.path.exists(PORT_INFO_FILE) else os.path.join(script_dir, PORT_INFO_FILE)

        if not os.path.exists(port_path):
            print(f"[Warning] '{PORT_INFO_FILE}' not found. Using default port {DEFAULT_PORT}.")
            return DEFAULT_PORT

        try:
            with open(port_path, "r", encoding="ascii") as f:
                port = int(f.read().strip())
                if 1 <= port <= 65535:
                    print(f"[Server] Loaded port {port} from '{PORT_INFO_FILE}'.")
                    return port
                print(f"[Warning] Port {port} in '{PORT_INFO_FILE}' is out of range. Using default port {DEFAULT_PORT}.")
                return DEFAULT_PORT
        except (ValueError, OSError) as err:
            print(f"[Warning] Could not read valid port from '{PORT_INFO_FILE}' ({err}). Using default port {DEFAULT_PORT}.")
            return DEFAULT_PORT

    # מימוש דרישת המטלה להמתנה לבקשות מלקוחות בלולאה אינסופית ותמיכה בריבוי משתמשים ע"י תהליכונים (עמוד 1 סעיף ב' ועמוד 2 סעיף 3)
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(128)
            print(f"[Server] Listening on {self.host}:{self.port} (version 3)...")

            while True:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client_connection,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[Server] Shutting down server.")
        except Exception as err:
            print(f"[Server Error] {err}")
        finally:
            server_socket.close()

    # מימוש הטיפול בחיבור של לקוח בודד, כולל הגדרת timeout של 5 דקות לחוסר פעילות (לפי עמוד 2 סעיף 4.ה)
    def _handle_client_connection(self, client_socket: socket.socket, client_address: tuple):
        print(f"[Connection] Client connected from {client_address}")
        client_socket.settimeout(CLIENT_TIMEOUT_SECONDS)

        try:
            while True:
                # קריאת כותרת הבקשה בת 23 הבתים (לפי טבלת Request Header בעמוד 6)
                header_bytes = client_socket.recv(REQUEST_HEADER_SIZE)
                if not header_bytes:
                    break  # הלקוח סגר את החיבור

                if len(header_bytes) < REQUEST_HEADER_SIZE:
                    header_bytes += self._recv_exact(client_socket, REQUEST_HEADER_SIZE - len(header_bytes))

                header = RequestHeader.unpack(header_bytes)

                # קריאת תוכן הבקשה (payload) לפי הגודל שהתקבל בכותרת
                payload_bytes = b""
                if header.payload_size > 0:
                    payload_bytes = self._recv_exact(client_socket, header.payload_size)

                # פענוח הבקשה והפעלת הלוגיקה המתאימה לפי הפרוטוקול
                response_data = self._process_request(header, payload_bytes, client_socket)
                if response_data is not None:
                    client_socket.sendall(response_data)

        except socket.timeout:
            print(f"[Timeout] Client {client_address} inactive for {CLIENT_TIMEOUT_SECONDS} seconds. Closing connection.")
        except ConnectionError:
            pass
        except Exception as err:
            print(f"[Error] Error handling client {client_address}: {err}")
            # במקרה של תקלה כללית בשרת שלא טופלה, מחזירים קוד 1607 לפי עמוד 8 במטלה
            try:
                client_socket.sendall(pack_response(ResponseCode.GENERAL_ERROR))
            except Exception:
                pass
        finally:
            client_socket.close()
            print(f"[Disconnection] Connection closed for {client_address}")

    # פונקציית עזר לקריאה מלאה של מספר בתים מדויק מהסוקט (לטיפול בהודעות גדולות לפי דגש 4.ה בעמוד 11)
    def _recv_exact(self, sock: socket.socket, num_bytes: int) -> bytes:
        data = bytearray()
        while len(data) < num_bytes:
            chunk = sock.recv(num_bytes - len(data))
            if not chunk:
                raise ConnectionError("Client disconnected while receiving payload.")
            data.extend(chunk)
        return bytes(data)

    # מימוש פענוח הבקשה וניתובה לפי קוד הבקשה (לפי סעיף 4 בעמוד 2 וטבלאות הבקשות בעמודים 6-7)
    def _process_request(
        self, header: RequestHeader, payload: bytes, client_socket: socket.socket
    ) -> bytes | None:
        code = header.code

        # עדכון שדה LastSeen בזיכרון עבור לקוח מוכר (בהתאם למבנה נתוני הלקוחות בעמוד 13)
        with self.db_lock:
            if header.client_id in self.clients_db:
                self.clients_db[header.client_id]["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")

        if code == RequestCode.REGISTER:
            return self._handle_register(header, payload)

        elif code == RequestCode.SEND_PUBLIC_KEY:
            return self._handle_send_public_key(header, payload)

        elif code == RequestCode.RECONNECT:
            return self._handle_reconnect(header, payload)

        elif code == RequestCode.SEND_FILE:
            return self._handle_send_file(header, payload)

        # מימוש קוד בקשה 900 (CRC תקין) לפי עמוד 2 סעיף 4.ד, עמוד 7 ועמוד 8 (תשובה 1604):
        # הלקוח מאשר שה-CRC תואם; השרת מעדכן ב-RAM שהקובץ אומת (Verified = True) ומחזיר תשובה 1604 עם ה-Client ID.
        elif code == RequestCode.CRC_OK:
            if len(payload) < NAME_SIZE:
                return pack_response(ResponseCode.GENERAL_ERROR)

            file_name = extract_null_terminated_string(payload[:NAME_SIZE])
            client_id = header.client_id

            with self.db_lock:
                client = self.clients_db.get(client_id)
                if not client:
                    return pack_response(ResponseCode.GENERAL_ERROR)
                if file_name in client["files"]:
                    client["files"][file_name]["verified"] = True

            print(f"[CRC OK] Client {client_id.hex()} verified CRC for '{file_name}'. Sending 1604.")
            return pack_response(ResponseCode.MESSAGE_RECEIVED_THANKS, client_id)

        # מימוש קוד בקשה 901 (CRC לא תקין, שולח שוב) לפי עמוד 7 במטלה:
        # הלקוח מודיע שה-CRC לא תואם ושהוא ישלח מיד שוב בקשה 828 עם הקובץ, לכן השרת לא מחזיר תשובה (None).
        elif code == RequestCode.CRC_INVALID_RETRY:
            if len(payload) < NAME_SIZE:
                return pack_response(ResponseCode.GENERAL_ERROR)

            file_name = extract_null_terminated_string(payload[:NAME_SIZE])
            client_id = header.client_id

            with self.db_lock:
                client = self.clients_db.get(client_id)
                if client and "incoming_files" in client:
                    client["incoming_files"].pop(file_name, None)

            print(f"[CRC Retry] Client {client_id.hex()} reported invalid CRC for '{file_name}'. Waiting for retry (828)...")
            return None

        # מימוש קוד בקשה 902 (CRC לא תקין בפעם הרביעית, סיימתי) לפי תרשים הזרימה בעמוד 3 ועמודים 7-8:
        # הלקוח מבטל את העברת הקובץ לאחר כישלון רביעי; השרת מוחק את הקובץ הפגום ומחזיר תשובה 1604 (מאשר קבלת הודעה, תודה).
        elif code == RequestCode.CRC_INVALID_ABORT:
            if len(payload) < NAME_SIZE:
                return pack_response(ResponseCode.GENERAL_ERROR)

            file_name = extract_null_terminated_string(payload[:NAME_SIZE])
            client_id = header.client_id
            file_path_to_remove = os.path.join(self.received_files_dir, client_id.hex(), file_name)

            with self.db_lock:
                client = self.clients_db.get(client_id)
                if client:
                    if "incoming_files" in client:
                        client["incoming_files"].pop(file_name, None)
                    if file_name in client["files"]:
                        saved_path = client["files"][file_name].get("file_path")
                        if saved_path:
                            file_path_to_remove = saved_path
                        del client["files"][file_name]

            if os.path.exists(file_path_to_remove):
                try:
                    os.remove(file_path_to_remove)
                except OSError:
                    pass

            print(f"[CRC Abort] Client {client_id.hex()} aborted transfer of '{file_name}' after 4th failure. Sending 1604.")
            return pack_response(ResponseCode.MESSAGE_RECEIVED_THANKS, client_id)

        else:
            print(f"[Protocol Error] Unknown request code: {code}")
            return pack_response(ResponseCode.GENERAL_ERROR)

    # מימוש בקשה 825 (רישום לקוח חדש) לפי עמוד 2 סעיף 4.א ועמודים 6-8 במטלה:
    # השרת מתעלם משדה ה-Client ID בכותרת, בודק אם שם המשתמש כבר קיים (ואם כן מחזיר 1601),
    # אחרת מייצר UUID חדש של 16 בתים, שומר ב-RAM ומחזיר תשובה 1600 עם ה-Client ID.
    def _handle_register(self, header: RequestHeader, payload: bytes) -> bytes:
        try:
            if len(payload) < NAME_SIZE:
                return pack_response(ResponseCode.REGISTER_FAILED)

            username = extract_null_terminated_string(payload[:NAME_SIZE])
            if not username:
                return pack_response(ResponseCode.REGISTER_FAILED)

            with self.db_lock:
                for client_data in self.clients_db.values():
                    if client_data["name"] == username:
                        print(f"[Register] Username '{username}' already exists. Returning 1601.")
                        return pack_response(ResponseCode.REGISTER_FAILED)

                client_id = uuid.uuid4().bytes
                self.clients_db[client_id] = {
                    "name": username,
                    "public_key": None,
                    "aes_key": None,
                    "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "files": {},
                    "incoming_files": {},
                }

            print(f"[Register] Registered '{username}' with ID {client_id.hex()}. Returning 1600.")
            return pack_response(ResponseCode.REGISTER_SUCCESS, client_id)

        except Exception as err:
            print(f"[Register Error] {err}")
            return pack_response(ResponseCode.REGISTER_FAILED)

    # מימוש בקשה 826 (שליחת מפתח ציבורי) לפי עמוד 2 סעיף 4.ב ועמודים 6 ו-8 במטלה:
    # קליטת המפתח הציבורי RSA (160 בתים), עדכונו ב-RAM, יצירת מפתח AES של 256 ביט,
    # הצפנתו בעזרת המפתח הציבורי של הלקוח ושליחת תשובה 1602 (Client ID + Encrypted AES Key).
    def _handle_send_public_key(self, header: RequestHeader, payload: bytes) -> bytes:
        try:
            client_id = header.client_id
            if len(payload) < NAME_SIZE + PUBLIC_KEY_SIZE:
                return pack_response(ResponseCode.GENERAL_ERROR)

            username = extract_null_terminated_string(payload[:NAME_SIZE])
            public_key_bytes = payload[NAME_SIZE : NAME_SIZE + PUBLIC_KEY_SIZE]

            if not validate_rsa_public_key(public_key_bytes):
                print(f"[PublicKey Error] Invalid RSA public key from client {client_id.hex()}.")
                return pack_response(ResponseCode.GENERAL_ERROR)

            aes_key = generate_aes_key()

            with self.db_lock:
                client = self.clients_db.get(client_id)
                if not client or client["name"] != username:
                    print(f"[PublicKey Error] Client {client_id.hex()} ('{username}') not found.")
                    return pack_response(ResponseCode.GENERAL_ERROR)

                client["public_key"] = public_key_bytes
                client["aes_key"] = aes_key

            encrypted_aes_key = encrypt_aes_key_with_rsa(public_key_bytes, aes_key)
            print(f"[PublicKey] Saved RSA key and sent encrypted AES key to '{username}' (1602).")

            return pack_response(ResponseCode.PUBLIC_KEY_RECEIVED_SEND_AES, client_id + encrypted_aes_key)

        except Exception as err:
            print(f"[PublicKey Error] {err}")
            return pack_response(ResponseCode.GENERAL_ERROR)

    # מימוש בקשה 827 (התחברות חוזרת) לפי תרשים ההתאוששות בעמוד 10 וטבלאות 1605/1606 בעמוד 8:
    # בדיקה האם הלקוח רשום ב-RAM ויש לו מפתח ציבורי RSA תקין.
    # אם לא - מחזירים תשובה 1606 (Client ID של 16 בתים) כדי שהלקוח יירשם מחדש כלקוח חדש.
    # אם כן - מייצרים מפתח AES חדש, מצפינים במפתח הציבורי השמור ומחזירים תשובה 1605.
    def _handle_reconnect(self, header: RequestHeader, payload: bytes) -> bytes:
        try:
            client_id = header.client_id
            if len(payload) < NAME_SIZE:
                return pack_response(ResponseCode.RECONNECT_REJECTED, client_id)

            username = extract_null_terminated_string(payload[:NAME_SIZE])

            with self.db_lock:
                client = self.clients_db.get(client_id)
                if not client or client["name"] != username or not client["public_key"]:
                    print(f"[Reconnect] Rejected for '{username}' ({client_id.hex()}). Returning 1606.")
                    return pack_response(ResponseCode.RECONNECT_REJECTED, client_id)

                aes_key = generate_aes_key()
                client["aes_key"] = aes_key
                public_key_bytes = client["public_key"]

            encrypted_aes_key = encrypt_aes_key_with_rsa(public_key_bytes, aes_key)
            print(f"[Reconnect] Approved for '{username}' ({client_id.hex()}). Sent new AES key (1605).")

            return pack_response(ResponseCode.RECONNECT_APPROVED_SEND_AES, client_id + encrypted_aes_key)

        except Exception as err:
            print(f"[Reconnect Error] {err}")
            return pack_response(ResponseCode.GENERAL_ERROR)

    # מימוש בקשה 828 (שליחת קובץ מוצפן) לפי עמוד 2 סעיף 4.ג ועמודים 7-8 במטלה:
    # קליטת חבילות הקובץ המוצפן ב-RAM לפי packet_number ו-total_packets.
    # עם קבלת החבילה האחרונה: וידוא גודל Content Size, פענוח ב-AES-CBC, שמירת הקובץ בתיקייה המקומית
    # ורישומו ב-RAM, חישוב ה-CRC (calculate_cksum) והחזרת תשובה 1603 ללקוח.
    def _handle_send_file(self, header: RequestHeader, payload: bytes) -> bytes | None:
        try:
            client_id = header.client_id
            with self.db_lock:
                client = self.clients_db.get(client_id)
                if not client or not client["aes_key"]:
                    print(f"[File Error] Client {client_id.hex()} has no active AES key.")
                    return pack_response(ResponseCode.GENERAL_ERROR)
                aes_key = client["aes_key"]

            # גודל השדות הקבועים ב-Payload של בקשה 828: 4 + 4 + 2 + 2 + 255 = 267 בתים
            file_header_size = (
                CONTENT_SIZE_FIELD
                + ORIG_FILE_SIZE_FIELD
                + PACKET_NUMBER_SIZE
                + TOTAL_PACKETS_SIZE
                + NAME_SIZE
            )
            if len(payload) < file_header_size:
                return pack_response(ResponseCode.GENERAL_ERROR)

            # פירוק שדות בקשה 828 ב-Little-Endian לפי הטבלה בעמוד 7 במטלה
            content_size, orig_file_size, packet_number, total_packets = struct.unpack_from("<IIHH", payload, 0)
            file_name_bytes = payload[12 : 12 + NAME_SIZE]
            file_name = extract_null_terminated_string(file_name_bytes)
            # מניעת גלישת נתיב (Path Traversal) לפי דגשי אבטחת המידע בעמוד 11 סעיף 4.ו
            file_name = os.path.basename(file_name)
            message_content = payload[file_header_size:]

            if total_packets == 0 or packet_number == 0 or packet_number > total_packets or not file_name:
                return pack_response(ResponseCode.GENERAL_ERROR)

            with self.db_lock:
                incoming = client["incoming_files"]
                if packet_number == 1 or file_name not in incoming:
                    incoming[file_name] = {
                        "content_size": content_size,
                        "orig_file_size": orig_file_size,
                        "total_packets": total_packets,
                        "packets": {},
                    }
                incoming[file_name]["packets"][packet_number] = message_content

            print(
                f"[File] Packet {packet_number}/{total_packets} for '{file_name}' "
                f"({len(message_content)} bytes) from {client_id.hex()}"
            )

            # אם עדיין לא הגיעה החבילה האחרונה, ממתינים לחבילה הבאה ללא שליחת תשובה
            if packet_number < total_packets:
                return None

            with self.db_lock:
                transfer_data = client["incoming_files"].pop(file_name, None)

            if not transfer_data or len(transfer_data["packets"]) != total_packets:
                return pack_response(ResponseCode.GENERAL_ERROR)

            encrypted_file_content = b"".join(
                transfer_data["packets"][i] for i in range(1, total_packets + 1)
            )

            if len(encrypted_file_content) != content_size:
                print(
                    f"[File Error] Size mismatch for '{file_name}': "
                    f"expected {content_size}, got {len(encrypted_file_content)}."
                )
                return pack_response(ResponseCode.GENERAL_ERROR)

            # פענוח הקובץ בעזרת מפתח ה-AES של הלקוח
            decrypted_content = decrypt_file_aes_cbc(encrypted_file_content, aes_key)

            # שמירת הקובץ המפוענח בתיקייה המקומית של השרת
            client_dir = os.path.join(self.received_files_dir, client_id.hex())
            os.makedirs(client_dir, exist_ok=True)
            file_path = os.path.join(client_dir, file_name)

            with open(file_path, "wb") as f:
                f.write(decrypted_content)

            # שמירת פרטי הקובץ בזיכרון ה-RAM של השרת (בהתאם לטבלת files בעמוד 13: ID, File Name, Path Name, Verified)
            with self.db_lock:
                client["files"][file_name] = {
                    "id": client_id,
                    "file_name": file_name,
                    "file_path": file_path,
                    "verified": False,
                }

            # חישוב ה-CRC של הקובץ המפוענח (זהה לפקודת cksum בלינוקס)
            cksum_value = calculate_cksum(decrypted_content)
            print(f"[File Saved] '{file_name}' ({len(decrypted_content)} bytes) saved. CRC={cksum_value}. Sending 1603.")

            # בניית תשובה 1603 לפי הטבלה בעמוד 8: Client ID (16) + Content Size (4) + File Name (255) + Cksum (4)
            response_payload = (
                client_id
                + struct.pack("<I", content_size)
                + pack_fixed_string(file_name, NAME_SIZE)
                + struct.pack("<I", cksum_value)
            )
            return pack_response(ResponseCode.FILE_RECEIVED_WITH_CRC, response_payload)

        except Exception as err:
            print(f"[File Error] Failed processing file: {err}")
            return pack_response(ResponseCode.GENERAL_ERROR)


# מימוש דרישת ההגשה בעמוד 12 סעיף 2: פונקציה ראשית בשם main() והפעלתה תחת if __name__ == "__main__"
def main():
    server = Server()
    server.start()


if __name__ == "__main__":
    main()
