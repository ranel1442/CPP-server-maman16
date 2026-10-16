"""
מערכת שרת (server.py) לפרויקט אבטחת מידע ותקשורת מחשבים (ממ"ן 16).

קובץ זה הוא נקודת הכניסה הראשית של צד השרת ומנהל את כל מחזור החיים של התקשורת מול הלקוחות:
1. האזנה לחיבורי TCP מלקוחות בפורט המוגדר בקובץ `port.info` (או בפורט ברירת המחדל 1369).
2. ניהול נתוני הלקוחות והקבצים בזיכרון (RAM) באופן מסונכרן ובטוח לתהליכונים (Thread-safe).
3. תמיכה בריבוי לקוחות במקביל באמצעות תהליכונים (`threading.Thread`).
4. פענוח וטיפול מלא בפרוטוקול הבינארי בפורמט Little-Endian:
   - קוד 825 (רישום לקוח חדש) -> תשובה 1600 / 1601.
   - קוד 826 (שליחת מפתח ציבורי RSA וקבלת מפתח AES מוצפן) -> תשובה 1602.
   - קוד 827 (התחברות חוזרת וקבלת מפתח AES חדש) -> תשובה 1605 / 1606.
   - קוד 828 (קבלה וצבירת חבילות קובץ מוצפן ב-AES-CBC, פענוח, שמירה וחישוב cksum) -> תשובה 1603.
   - קוד 900 (אישור CRC תקין מהלקוח) -> תשובה 1604.
   - קוד 901 (דיווח על CRC שגוי וניסיון שליחה חוזר) -> ללא תשובה (המתנה לבקשה 828 חדשה).
   - קוד 902 (דיווח על כישלון CRC בפעם הרביעית וביטול ההעברה) -> תשובה 1604.

מי קורא למודול זה:
- מופעל ישירות משורת הפקודה (`python server.py` מתוך תיקיית `server/` או `python server/server.py` מחוצה לה).
- משתמש במודולים `protocol.py` (מבני נתונים, קבועים וחישוב cksum) ו-`crypto_utils.py` (הצפנת RSA ופענוח AES).
"""

import os
import socket
import struct
import threading
import traceback
import uuid

# התאמת ייבואים כך שיעבדו גם בהרצה מתוך תיקיית server/ וגם בהרצה מתיקיית האב
try:
    from protocol import (
        CLIENT_ID_SIZE,
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
        CLIENT_ID_SIZE,
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


class Server:
    """
    מחלקת השרת הראשית המנהלת את האזנת הרשת, חיבורי הלקוחות, מסד הנתונים ב-RAM, ולוגיקת הפרוטוקול.

    משתנים מרכזיים במחלקה:
    - host (str): כתובת ה-IP להאזנה (ברירת מחדל "0.0.0.0" להאזנה לכל ממשקי הרשת).
    - port (int): מספר הפורט שעליו השרת מאזין (נטען מ-`port.info` או 1369 כברירת מחדל).
    - clients_db (dict[bytes, dict]): מבנה נתונים בזיכרון (RAM) המאחסן את כל הלקוחות הרשומים.
      המפתח הוא `client_id` (16 בתים), והערך הוא מילון המכיל:
        * "name" (str): שם הלקוח.
        * "public_key" (bytes | None): מפתח ה-RSA הציבורי של הלקוח (160 בתים).
        * "aes_key" (bytes | None): מפתח ה-AES הסימטרי הנוכחי של הלקוח (32 בתים).
        * "files" (dict[str, dict]): מילון הקבצים של הלקוח לפי שם קובץ (נתיב שמירה, גודל, והאם ה-CRC אומת: Verified).
        * "incoming_files" (dict[str, dict]): אוגר זמני ב-RAM לצבירת חבילות (Packets) של קבצים בתהליך קבלה (בקשה 828).
    - db_lock (threading.Lock): מנעול לסנכרון גישה מקבילית ל-`clients_db` בין תהליכוני הלקוחות השונים.
    - received_files_dir (str): נתיב התיקייה המקומית שבה נשמרים הקבצים המפוענחים שהתקבלו מהלקוחות.
    """

    def __init__(self, host: str = "0.0.0.0"):
        """אתחול מופע השרת, קריאת הפורט מקובץ ההגדרות, והכנת מבני הנתונים ב-RAM ותיקיית הקבצים."""
        self.host = host
        self.port = self._read_port_from_file()

        # מבנה נתונים בזיכרון (RAM) לניהול הלקוחות והקבצים שלהם
        self.clients_db: dict[bytes, dict] = {}
        self.db_lock = threading.Lock()  # מנעול לסנכרון גישה מקבילית ל-RAM מריבוי תהליכונים

        # יצירת תיקייה מקומית לשמירת הקבצים שיתקבלו מהלקוחות
        self.received_files_dir = "received_files"
        os.makedirs(self.received_files_dir, exist_ok=True)

    def _read_port_from_file(self) -> int:
        """
        קריאת מספר הפורט מקובץ `port.info` (מחפש בתיקיית הריצה הנוכחית או בתיקיית הקובץ `server.py`).
        אם הקובץ לא קיים או אינו תקין, השרת מדפיס אזהרה ומשתמש בפורט ברירת המחדל (1369) ללא קריסה.
        נקראת מתוך `__init__` בעת אתחול השרת.
        """
        port_file_path = PORT_INFO_FILE
        if not os.path.exists(port_file_path):
            alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), PORT_INFO_FILE)
            if os.path.exists(alt_path):
                port_file_path = alt_path
            else:
                print(f"[Warning] '{PORT_INFO_FILE}' not found. Using default port: {DEFAULT_PORT}")
                return DEFAULT_PORT

        try:
            with open(port_file_path, "r", encoding="ascii") as f:
                content = f.read().strip()
                port = int(content)
                if 1 <= port <= 65535:
                    print(f"[Info] Successfully loaded port {port} from '{port_file_path}'.")
                    return port
                else:
                    print(f"[Warning] Port {port} out of range. Falling back to default: {DEFAULT_PORT}")
                    return DEFAULT_PORT
        except Exception as e:
            print(f"[Error] Failed to read '{port_file_path}': {e}. Traceback:")
            traceback.print_exc()
            print(f"[Info] Falling back to default port: {DEFAULT_PORT}")
            return DEFAULT_PORT

    def start(self):
        """
        הפעלת השרת הראשית: פתיחת סוקט TCP, קשירה (bind) לפורט, וכניסה ללולאה אינסופית לקבלת לקוחות.
        עבור כל לקוח שמתחבר נפתח תהליכון (`Thread`) ייעודי שמריץ את `_handle_client_connection`.
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(128)
            print(f"[Server] Listening on {self.host}:{self.port}...")

            while True:
                client_socket, client_address = server_socket.accept()
                # הפעלת תהליכון נפרד (Thread) עבור כל לקוח מתחבר כדי לאפשר עבודה מרובת לקוחות במקביל
                client_thread = threading.Thread(
                    target=self._handle_client_connection,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                client_thread.start()
        except Exception as e:
            print(f"[Server Error] Fatal error in main server loop: {e}")
            traceback.print_exc()
        finally:
            server_socket.close()

    def _handle_client_connection(self, client_socket: socket.socket, client_address: tuple):
        """
        ניהול תקשורת מול לקוח בודד בתוך תהליכון ייעודי לאורך מחזור החיים של החיבור.
        קורא בכל סיבוב את כותרת הבקשה (23 בתים), קורא את ה-Payload, מעביר ל-`_process_request`,
        ושולח חזרה ללקוח את תשובת השרת (אלא אם כן הפונקציה החזירה `None`, כגון בחבילות ביניים או בקוד 901).
        """
        print(f"[Connection] New connection established from {client_address}")
        client_socket.settimeout(CLIENT_TIMEOUT_SECONDS)

        try:
            while True:
                # קריאת כותרת הבקשה (תמיד באורך קבוע של 23 בתים לפי REQUEST_HEADER_SIZE)
                header_bytes = client_socket.recv(REQUEST_HEADER_SIZE)
                if not header_bytes:
                    break  # הלקוח סגר את החיבור בצורה מסודרת

                if len(header_bytes) < REQUEST_HEADER_SIZE:
                    remaining = self._recv_exact(client_socket, REQUEST_HEADER_SIZE - len(header_bytes))
                    header_bytes += remaining

                header = RequestHeader.unpack(header_bytes)

                # קריאת ה-Payload בהתאם לגודל שצוין בכותרת (payload_size)
                payload_bytes = b""
                if header.payload_size > 0:
                    payload_bytes = self._recv_exact(client_socket, header.payload_size)

                # ניתוב הבקשה לפונקציית הטיפול המתאימה לפי קוד הבקשה (Code)
                response_data = self._process_request(header, payload_bytes, client_socket)
                if response_data:
                    client_socket.sendall(response_data)

        except socket.timeout:
            print(f"[Timeout] Client {client_address} inactive for {CLIENT_TIMEOUT_SECONDS}s. Disconnecting.")
        except Exception as e:
            print(f"[Error] Exception while handling client {client_address}: {e}")
            traceback.print_exc()
            # במקרה תקלה לא מטופלת, נשלח ללקוח תשובת שגיאה כללית (1607)
            try:
                client_socket.sendall(pack_response(ResponseCode.GENERAL_ERROR))
            except Exception:
                pass
        finally:
            client_socket.close()
            print(f"[Disconnection] Connection closed for {client_address}")

    def _recv_exact(self, sock: socket.socket, num_bytes: int) -> bytes:
        """
        פונקציית עזר לקריאה מדויקת של `num_bytes` בתים מתוך סוקט ה-TCP.
        מונעת מצב של קריאה חלקית (Partial Read) כאשר מידע מפוצל על פני מספר חבילות TCP ברשת.
        נקראת מתוך `_handle_client_connection`.
        """
        data = bytearray()
        while len(data) < num_bytes:
            packet = sock.recv(num_bytes - len(data))
            if not packet:
                raise ConnectionError("Socket connection broken while receiving payload.")
            data.extend(packet)
        return bytes(data)

    def _process_request(
        self, header: RequestHeader, payload: bytes, client_socket: socket.socket
    ) -> bytes | None:
        """
        נתב מרכזי המפענח את סוג הבקשה (`header.code`) ומפעיל את הלוגיקה המתאימה:
        - קודים 825, 826, 827, 828 מועברים לפונקציות הטיפול הייעודיות שלהם.
        - קודים 900, 901, 902 (אימות CRC של קובץ) מטופלים ומעדכנים את מצב הקובץ ב-RAM של השרת.
        מחזיר את מערך הבתים של תשובת השרת לשליחה, או `None` אם אין לשלוח תשובה כעת.
        """
        code = header.code

        # קוד 825: בקשת רישום ראשוני של לקוח חדש
        if code == RequestCode.REGISTER:
            return self._handle_register(header, payload)

        # קוד 826: שליחת מפתח ציבורי (RSA) מהלקוח לשרת
        elif code == RequestCode.SEND_PUBLIC_KEY:
            return self._handle_send_public_key(header, payload)

        # קוד 827: בקשת התחברות חוזרת (Reconnect) של לקוח שכבר רשום
        elif code == RequestCode.RECONNECT:
            return self._handle_reconnect(header, payload)

        # קוד 828: שליחת קובץ מוצפן (AES) מהלקוח לשרת (תומך בריבוי חבילות)
        elif code == RequestCode.SEND_FILE:
            return self._handle_send_file(header, payload)

        # קוד 900: הלקוח מאשר שה-CRC תקין (CRC_OK)
        elif code == RequestCode.CRC_OK:
            try:
                client_id = header.client_id
                if len(payload) < NAME_SIZE:
                    return pack_response(ResponseCode.GENERAL_ERROR)

                file_name = extract_null_terminated_string(payload[:NAME_SIZE])
                with self.db_lock:
                    client = self.clients_db.get(client_id)
                    if not client:
                        print(f"[CRC Error] Client ID {client_id.hex()} not found for CRC_OK.")
                        return pack_response(ResponseCode.GENERAL_ERROR)
                    if file_name in client["files"]:
                        client["files"][file_name]["verified"] = True
                    else:
                        client["files"][file_name] = {
                            "file_name": file_name,
                            "file_path": os.path.join(self.received_files_dir, client_id.hex(), file_name),
                            "verified": True,
                        }

                print(
                    f"[CRC OK] Client {client_id.hex()} confirmed valid CRC for file '{file_name}' "
                    f"(Verified = True)."
                )
                return pack_response(ResponseCode.MESSAGE_RECEIVED_THANKS, client_id)
            except Exception as e:
                print(f"[CRC OK Error] {e}")
                traceback.print_exc()
                return pack_response(ResponseCode.GENERAL_ERROR)

        # קוד 901: הלקוח מדווח שה-CRC אינו תקין ומבקש לשלוח את הקובץ שוב (CRC_INVALID_RETRY)
        elif code == RequestCode.CRC_INVALID_RETRY:
            try:
                client_id = header.client_id
                if len(payload) < NAME_SIZE:
                    return pack_response(ResponseCode.GENERAL_ERROR)

                file_name = extract_null_terminated_string(payload[:NAME_SIZE])
                with self.db_lock:
                    client = self.clients_db.get(client_id)
                    if client and "incoming_files" in client:
                        client["incoming_files"].pop(file_name, None)

                print(
                    f"[CRC Retry] Client {client_id.hex()} reported invalid CRC for file '{file_name}'. "
                    f"Waiting for client to resend file (request 828)..."
                )
                # לא שולחים תשובה ללקוח בקוד 901 - הלקוח ישלח מיד בקשה 828 חדשה
                return None
            except Exception as e:
                print(f"[CRC Retry Error] {e}")
                traceback.print_exc()
                return pack_response(ResponseCode.GENERAL_ERROR)

        # קוד 902: הלקוח מדווח על כישלון CRC בפעם הרביעית ומבטל את ההעברה (CRC_INVALID_ABORT)
        elif code == RequestCode.CRC_INVALID_ABORT:
            try:
                client_id = header.client_id
                if len(payload) < NAME_SIZE:
                    return pack_response(ResponseCode.GENERAL_ERROR)

                file_name = extract_null_terminated_string(payload[:NAME_SIZE])
                file_path_to_delete = os.path.join(self.received_files_dir, client_id.hex(), file_name)

                with self.db_lock:
                    client = self.clients_db.get(client_id)
                    if client:
                        if "incoming_files" in client:
                            client["incoming_files"].pop(file_name, None)
                        if file_name in client["files"]:
                            saved_path = client["files"][file_name].get("file_path")
                            if saved_path:
                                file_path_to_delete = saved_path
                            del client["files"][file_name]

                # מחיקת הקובץ הלא-תקין מהדיסק אם נשמר
                if os.path.exists(file_path_to_delete):
                    try:
                        os.remove(file_path_to_delete)
                    except OSError as os_err:
                        print(f"[File Cleanup Warning] Could not remove '{file_path_to_delete}': {os_err}")

                print(
                    f"[CRC Abort] Client {client_id.hex()} reported 4th CRC failure for file '{file_name}' "
                    f"and aborted transfer. Corrupted file removed."
                )
                return pack_response(ResponseCode.MESSAGE_RECEIVED_THANKS, client_id)
            except Exception as e:
                print(f"[CRC Abort Error] {e}")
                traceback.print_exc()
                return pack_response(ResponseCode.GENERAL_ERROR)

        else:
            print(f"[Protocol Error] Unknown request code received: {code}")
            return pack_response(ResponseCode.GENERAL_ERROR)

    def _handle_register(self, header: RequestHeader, payload: bytes) -> bytes:
        """
        טיפול בבקשת רישום לקוח חדש (קוד 825):
        - מחלץ את שם המשתמש מה-Payload (255 בתים מרופדים ב-null).
        - בודק ב-RAM האם השם כבר תפוס; אם כן, מחזיר תשובת כישלון 1601 (`REGISTER_FAILED`).
        - אם השם פנוי, מייצר UUID חדש (16 בתים), שומר את הלקוח ב-`clients_db` ומחזיר תשובה 1600 (`REGISTER_SUCCESS`).
        נקראת מתוך `_process_request`.
        """
        try:
            # בשדה Name ישנם 255 בתים המכילים מחרוזת מרופדת ב-null
            if len(payload) < NAME_SIZE:
                return pack_response(ResponseCode.REGISTER_FAILED)

            username = extract_null_terminated_string(payload[:NAME_SIZE])

            with self.db_lock:
                # בדיקה האם השם כבר קיים בבסיס הנתונים בזיכרון
                for client_data in self.clients_db.values():
                    if client_data["name"] == username:
                        print(f"[Register] Failed: Username '{username}' already exists.")
                        return pack_response(ResponseCode.REGISTER_FAILED)

                # ייצור מזהה ייחודי חדש ללקוח (16 בתים - UUID אקראי)
                client_id = uuid.uuid4().bytes

                # שמירת הלקוח ב-RAM עם מבני נתונים לקבצים שהושלמו ולקבצים בתהליך העברה
                self.clients_db[client_id] = {
                    "name": username,
                    "public_key": None,
                    "aes_key": None,
                    "files": {},
                    "incoming_files": {},
                }

            print(f"[Register] Success: Registered new user '{username}' with ID {client_id.hex()}")
            # תשובה 1600 (רישום הצליח) כוללת ב-Payload את ה-Client ID באורך 16 בתים
            return pack_response(ResponseCode.REGISTER_SUCCESS, client_id)

        except Exception as e:
            print(f"[Register Error] {e}")
            return pack_response(ResponseCode.REGISTER_FAILED)

    def _handle_send_public_key(self, header: RequestHeader, payload: bytes) -> bytes:
        """
        טיפול בשליחת מפתח ציבורי מהלקוח (קוד 826):
        - מוודא שהלקוח רשום ב-RAM לפי `header.client_id`.
        - מחלץ את המפתח הציבורי RSA (160 בתים) ומוודא את תקינותו בעזרת `validate_rsa_public_key`.
        - מייצר מפתח AES-256 חדש (`generate_aes_key`), שומר את שני המפתחות ב-RAM,
          מצפין את מפתח ה-AES באמצעות מפתח ה-RSA (`encrypt_aes_key_with_rsa`), ומחזיר תשובה 1602.
        נקראת מתוך `_process_request`.
        """
        try:
            client_id = header.client_id
            with self.db_lock:
                if client_id not in self.clients_db:
                    print(f"[Auth Error] Client ID {client_id.hex()} not found in database.")
                    return pack_response(ResponseCode.GENERAL_ERROR)

            # ה-Payload מורכב מ-255 בתים שם משתמש + 160 בתים מפתח ציבורי RSA (X.509)
            if len(payload) < NAME_SIZE + PUBLIC_KEY_SIZE:
                return pack_response(ResponseCode.GENERAL_ERROR)

            public_key_bytes = payload[NAME_SIZE : NAME_SIZE + PUBLIC_KEY_SIZE]

            # אימות תקינות מפתח ה-RSA
            if not validate_rsa_public_key(public_key_bytes):
                print(f"[Crypto Error] Invalid RSA public key received from client {client_id.hex()}")
                return pack_response(ResponseCode.GENERAL_ERROR)

            # יצירת מפתח AES סימטרי חדש (256 ביט / 32 בתים) ללקוח
            aes_key = generate_aes_key()

            with self.db_lock:
                self.clients_db[client_id]["public_key"] = public_key_bytes
                self.clients_db[client_id]["aes_key"] = aes_key

            # הצפנת מפתח ה-AES באמצעות המפתח הציבורי (RSA) של הלקוח
            encrypted_aes_key = encrypt_aes_key_with_rsa(public_key_bytes, aes_key)

            print(f"[Crypto] Generated and encrypted AES key for client {client_id.hex()}")

            # תשובה 1602: Client ID (16 בתים) + מפתח AES מוצפן (128 בתים)
            response_payload = client_id + encrypted_aes_key
            return pack_response(ResponseCode.PUBLIC_KEY_RECEIVED_SEND_AES, response_payload)

        except Exception as e:
            print(f"[Send Public Key Error] {e}")
            traceback.print_exc()
            return pack_response(ResponseCode.GENERAL_ERROR)

    def _handle_reconnect(self, header: RequestHeader, payload: bytes) -> bytes:
        """
        טיפול בבקשת התחברות חוזרת של לקוח (קוד 827):
        - בודק האם `client_id` קיים ב-RAM, האם שם המשתמש ב-Payload תואם, והאם שמור לו מפתח ציבורי RSA.
        - אם לא, מחזיר תשובת דחייה 1606 (`RECONNECT_REJECTED`) עם `client_id`.
        - אם כן, מייצר מפתח AES חדש, מצפין אותו במפתח ה-RSA השמור של הלקוח, ומחזיר תשובה 1605 (`RECONNECT_APPROVED_SEND_AES`).
        נקראת מתוך `_process_request`.
        """
        try:
            client_id = header.client_id
            if len(payload) < NAME_SIZE:
                return pack_response(ResponseCode.RECONNECT_REJECTED, client_id)

            requested_name = extract_null_terminated_string(payload[:NAME_SIZE])

            with self.db_lock:
                client = self.clients_db.get(client_id)
                # אם הלקוח לא קיים, השם אינו תואם, או שאין לו מפתח ציבורי שמור - השרת דוחה את ההתחברות (1606)
                if not client or client["name"] != requested_name or not client["public_key"]:
                    print(
                        f"[Reconnect] Rejected: Client ID {client_id.hex()} ('{requested_name}') "
                        f"not found or missing RSA key."
                    )
                    return pack_response(ResponseCode.RECONNECT_REJECTED, client_id)

                # יצירת מפתח AES חדש להתחברות המחודשת
                aes_key = generate_aes_key()
                client["aes_key"] = aes_key
                public_key_bytes = client["public_key"]

            # הצפנת מפתח ה-AES החדש ב-RSA של הלקוח
            encrypted_aes_key = encrypt_aes_key_with_rsa(public_key_bytes, aes_key)

            print(f"[Reconnect] Approved for client {client_id.hex()} ('{requested_name}'). Sent new AES key.")
            # תשובה 1605: Client ID (16 בתים) + מפתח AES מוצפן
            response_payload = client_id + encrypted_aes_key
            return pack_response(ResponseCode.RECONNECT_APPROVED_SEND_AES, response_payload)

        except Exception as e:
            print(f"[Reconnect Error] {e}")
            return pack_response(ResponseCode.GENERAL_ERROR)

    def _handle_send_file(self, header: RequestHeader, payload: bytes) -> bytes | None:
        """
        טיפול בקבלת קובץ מוצפן בחבילה אחת או בחבילות מרובות (קוד 828):
        - מפענח את שדות ה-Payload בפורמט Little-Endian:
          * Content Size (4 בתים, unsigned int) - גודל הקובץ הכולל לאחר הצפנה.
          * Orig File Size (4 בתים, unsigned int) - גודל הקובץ המקורי לפני הצפנה.
          * Packet number (2 בתים, unsigned short) - מספר החבילה הנוכחית.
          * Total packets (2 בתים, unsigned short) - סה"כ מספר החבילות.
          * File Name (255 בתים, מחרוזת ASCII מרופדת ב-null).
          * Message Content (אורך משתנה) - תוכן החבילה המוצפן.
        - צובר את `Message Content` של כל חבילה במבנה הנתונים של הלקוח ב-RAM (`incoming_files`).
        - אם `packet_number < total_packets`, מחזיר `None` וממתין לחבילה הבאה.
        - בחבילה האחרונה (`packet_number == total_packets`), מוודא שסך הבתים המוצפנים שווה ל-`Content Size`,
          מפענח את הקובץ בעזרת `decrypt_file_aes_cbc`, שומר לתיקייה המקומית, רושם את הקובץ ב-RAM של השרת
          (`Verified = False` עד לקבלת קוד 900), מחשב `calculate_cksum`, ומחזיר תשובה 1603.
        נקראת מתוך `_process_request`.
        """
        try:
            client_id = header.client_id
            with self.db_lock:
                client = self.clients_db.get(client_id)
                if not client or not client["aes_key"]:
                    print(f"[File Error] Unauthorized file transfer attempt from client {client_id.hex()}")
                    return pack_response(ResponseCode.GENERAL_ERROR)
                aes_key = client["aes_key"]

            # גודל כותרת המשנה של ה-Payload בבקשה 828: 4 + 4 + 2 + 2 + 255 = 267 בתים
            min_payload_header = (
                CONTENT_SIZE_FIELD
                + ORIG_FILE_SIZE_FIELD
                + PACKET_NUMBER_SIZE
                + TOTAL_PACKETS_SIZE
                + NAME_SIZE
            )
            if len(payload) < min_payload_header:
                print(f"[File Error] Payload too short ({len(payload)} bytes) in request 828.")
                return pack_response(ResponseCode.GENERAL_ERROR)

            # פריקת שדות המטא-דאטה של הקובץ בפורמט Little-Endian
            offset = 0
            content_size = struct.unpack_from("<I", payload, offset)[0]
            offset += CONTENT_SIZE_FIELD

            orig_file_size = struct.unpack_from("<I", payload, offset)[0]
            offset += ORIG_FILE_SIZE_FIELD

            packet_number = struct.unpack_from("<H", payload, offset)[0]
            offset += PACKET_NUMBER_SIZE

            total_packets = struct.unpack_from("<H", payload, offset)[0]
            offset += TOTAL_PACKETS_SIZE

            file_name_bytes = payload[offset : offset + NAME_SIZE]
            file_name = extract_null_terminated_string(file_name_bytes)
            offset += NAME_SIZE

            message_content = payload[offset:]

            if total_packets == 0 or packet_number == 0 or packet_number > total_packets:
                print(
                    f"[File Error] Invalid packet numbering ({packet_number}/{total_packets}) "
                    f"for file '{file_name}'."
                )
                return pack_response(ResponseCode.GENERAL_ERROR)

            # צבירת תוכן החבילה במבנה הנתונים של הלקוח ב-RAM
            with self.db_lock:
                incoming_files = client.setdefault("incoming_files", {})
                # אם זו החבילה הראשונה של הקובץ (או שליחה מחדש החל מחבילה 1), נאתחל את האוגר עבור הקובץ
                if packet_number == 1 or file_name not in incoming_files:
                    incoming_files[file_name] = {
                        "content_size": content_size,
                        "orig_file_size": orig_file_size,
                        "total_packets": total_packets,
                        "packets": {},
                    }

                transfer_state = incoming_files[file_name]
                transfer_state["packets"][packet_number] = message_content

            print(
                f"[File] Received packet {packet_number}/{total_packets} for file '{file_name}' "
                f"({len(message_content)} bytes) from client {client_id.hex()}"
            )

            # אם טרם התקבלו כל החבילות, לא שולחים תשובה וממתינים לחבילה הבאה
            if packet_number < total_packets:
                return None

            # התקבלה החבילה האחרונה (packet_number == total_packets) - הרכבת כלל החבילות לפי הסדר
            with self.db_lock:
                transfer_state = client["incoming_files"].pop(file_name, None)

            if not transfer_state or len(transfer_state["packets"]) != total_packets:
                print(f"[File Error] Missing packets for file '{file_name}' from client {client_id.hex()}.")
                return pack_response(ResponseCode.GENERAL_ERROR)

            encrypted_file_content = b"".join(
                transfer_state["packets"][pkt_idx] for pkt_idx in range(1, total_packets + 1)
            )

            # וידוא שסך הבתים המוצפנים שהתקבלו שווה ל-Content Size שהוצהר בבקשה
            if len(encrypted_file_content) != content_size:
                print(
                    f"[File Error] Encrypted size mismatch for '{file_name}': "
                    f"expected {content_size} bytes, got {len(encrypted_file_content)} bytes."
                )
                return pack_response(ResponseCode.GENERAL_ERROR)

            # פענוח תוכן הקובץ המוצפן באמצעות מפתח ה-AES במצב CBC
            decrypted_file_content = decrypt_file_aes_cbc(encrypted_file_content, aes_key)

            # שמירת הקובץ המפוענח בתיקייה המקומית בשרת
            client_file_dir = os.path.join(self.received_files_dir, client_id.hex())
            os.makedirs(client_file_dir, exist_ok=True)
            file_path = os.path.join(client_file_dir, file_name)

            with open(file_path, "wb") as f:
                f.write(decrypted_file_content)

            # רישום פרטי הקובץ ב-RAM של השרת (שם הקובץ, נתיב שמירה, והאם ה-CRC אומת)
            with self.db_lock:
                client["files"][file_name] = {
                    "file_name": file_name,
                    "file_path": file_path,
                    "orig_file_size": orig_file_size,
                    "content_size": content_size,
                    "verified": False,
                }

            # חישוב Checksum (זהה לפקודת cksum בלינוקס) על הקובץ המפוענח
            file_cksum = calculate_cksum(decrypted_file_content)

            print(
                f"[File Success] Saved '{file_name}' ({len(decrypted_file_content)} bytes decrypted) "
                f"at '{file_path}'. Calculated cksum: {file_cksum}"
            )

            # תשובה 1603: Client ID (16 בתים) + Content Size (4 בתים) + File Name (255 בתים) + Cksum (4 בתים)
            response_payload = (
                client_id
                + struct.pack("<I", content_size)
                + pack_fixed_string(file_name, NAME_SIZE)
                + struct.pack("<I", file_cksum)
            )
            return pack_response(ResponseCode.FILE_RECEIVED_WITH_CRC, response_payload)

        except Exception as e:
            print(f"[File Error] Failed to process file transfer: {e}")
            traceback.print_exc()
            return pack_response(ResponseCode.GENERAL_ERROR)


if __name__ == "__main__":
    # נקודת הכניסה הראשית להפעלת השרת
    server_instance = Server()
    server_instance.start()