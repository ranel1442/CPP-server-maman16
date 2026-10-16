/**
 * @file Protocol.h
 * @brief הגדרת קבועי הפרוטוקול, קודי בקשות ותשובות, ומבנים בינאריים (Little-Endian) עבור צד הלקוח.
 *
 * קובץ זה מיישם את מפרט פרוטוקול התקשורת הבינארי של המטלה (גרסת לקוח 3) מעל TCP.
 * כל המבנים מוגדרים תחת `#pragma pack(push, 1)` כדי למנוע ריפוד בתים (Padding) של המהדר,
 * ומשתמשים בטיפוסים חסרי סימן בגודל קבוע (`uint8_t`, `uint16_t`, `uint32_t`).
 *
 * מי קורא למודול זה:
 * - קובץ המימוש `Protocol.cpp` (פונקציות עזר לאתחול והמרת שדות הפרוטוקול).
 * - מודול הקונפיגורציה (`Config.h` / `Config.cpp`) לעבודה עם גודל ה-Client ID (16 בתים) ושם הלקוח.
 * - מודול התקשורת והלקוח הראשי לבניית בקשות (825, 826, 827, 828, 900, 901, 902) ופענוח תשובות השרת (1600–1607).
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>

namespace Protocol {

    // =========================================================================
    // קבועי מערכת ופרוטוקול לפי מפרט המטלה
    // =========================================================================
    constexpr uint8_t  CLIENT_VERSION          = 3;    ///< גרסת תוכנת הלקוח (1 בית, unsigned)
    constexpr size_t   CLIENT_ID_SIZE          = 16;   ///< גודל מזהה לקוח ייחודי UUID בבתים (128 ביט)
    constexpr size_t   MAX_CONFIG_CLIENT_NAME  = 100;  ///< אורך מקסימלי של שם לקוח בקובץ transfer.json
    constexpr size_t   NAME_FIELD_SIZE         = 255;  ///< גודל שדה שם משתמש או שם קובץ בפרוטוקול (כולל תו null מסיים)
    constexpr size_t   PUBLIC_KEY_SIZE         = 160;  ///< גודל מפתח ציבורי RSA-1024 בפורמט X.509 בינארי
    constexpr size_t   AES_KEY_SIZE            = 32;   ///< גודל מפתח סימטרי AES-256 בבתים (256 ביט)
    constexpr size_t   AES_BLOCK_SIZE          = 16;   ///< גודל בלוק AES וגודל ה-IV בבתים (128 ביט)
    constexpr size_t   REQUEST_HEADER_SIZE     = 23;   ///< גודל כותרת בקשה מהלקוח לשרת בבתים
    constexpr size_t   RESPONSE_HEADER_SIZE    = 7;    ///< גודל כותרת תשובה מהשרת ללקוח בבתים
    constexpr size_t   FILE_PACKET_CHUNK_SIZE  = 4096; ///< גודל מקטע תוכן קובץ בחבילה בודדת (ניתן לחלוקה למספר חבילות)
    constexpr uint32_t MAX_RETRY_ATTEMPTS      = 3;    ///< מספר ניסיונות חוזרים מקסימלי בשגיאת שרת או שגיאת CRC

    /// טיפוס עזר לייצוג מזהה לקוח של 16 בתים בזיכרון
    using ClientIdArray = std::array<uint8_t, CLIENT_ID_SIZE>;

    // =========================================================================
    // קודי בקשות (Request Codes) - נשלחים מהלקוח לשרת (2 בתים, Little-Endian)
    // =========================================================================
    enum class RequestCode : uint16_t {
        REGISTER          = 825, ///< רישום לקוח חדש (Payload: שם לקוח - 255 בתים)
        SEND_PUBLIC_KEY   = 826, ///< שליחת מפתח ציבורי RSA (Payload: שם לקוח 255 בתים + מפתח ציבורי 160 בתים)
        RECONNECT         = 827, ///< בקשת התחברות חוזרת של לקוח רשום (Payload: שם לקוח - 255 בתים)
        SEND_FILE         = 828, ///< שליחת קובץ מוצפן ב-AES-CBC (בחבילה אחת או יותר)
        CRC_OK            = 900, ///< אישור שה-CRC שחושב בשרת תואם ל-CRC של הלקוח (Payload: שם קובץ - 255 בתים)
        CRC_INVALID_RETRY = 901, ///< הודעה שה-CRC אינו תקין והלקוח שולח שוב את הקובץ (Payload: שם קובץ - 255 בתים)
        CRC_INVALID_ABORT = 902  ///< הודעה שה-CRC אינו תקין בפעם הרביעית וביטול העברת הקובץ (Payload: שם קובץ - 255 בתים)
    };

    // =========================================================================
    // קודי תשובות (Response Codes) - מתקבלים מהשרת ללקוח (2 בתים, Little-Endian)
    // =========================================================================
    enum class ResponseCode : uint16_t {
        REGISTER_SUCCESS            = 1600, ///< רישום הצליח (Payload: Client ID - 16 בתים)
        REGISTER_FAILED             = 1601, ///< רישום נכשל (ללא Payload)
        PUBLIC_KEY_RECEIVED_AES     = 1602, ///< התקבל מפתח ציבורי ונשלח מפתח AES מוצפן (Payload: Client ID + Encrypted AES)
        FILE_RECEIVED_WITH_CRC      = 1603, ///< קובץ התקבל תקין עם CRC (Payload: Client ID + Content Size + File Name + Cksum)
        MESSAGE_RECEIVED_THANKS     = 1604, ///< מאשר קבלת הודעה, תודה - בתגובה ל-900 או 902 (Payload: Client ID - 16 בתים)
        RECONNECT_APPROVED_SEND_AES = 1605, ///< מאשר התחברות חוזרת ושולח מפתח AES מוצפן (Payload: Client ID + Encrypted AES)
        RECONNECT_REJECTED          = 1606, ///< בקשה להתחברות חוזרת נדחתה - יש להירשם מחדש (Payload: Client ID - 16 בתים)
        GENERAL_ERROR               = 1607  ///< שגיאה כללית בשרת (ללא Payload)
    };

    // =========================================================================
    // מבנים בינאריים צפופים (Packed Binary Structures) בפורמט Little-Endian
    // =========================================================================
#pragma pack(push, 1)

    /**
     * @struct RequestHeader
     * @brief כותרת בקשה בינארית מהלקוח לשרת (23 בתים בדיוק).
     *
     * שדות המבנה:
     * - clientId: מזהה ייחודי של הלקוח (16 בתים / 128 ביט). בבקשה 825 השרת מתעלם משדה זה.
     * - version: מספר גרסת הלקוח (1 בית, תמיד 3).
     * - code: קוד הבקשה מתוך `RequestCode` (2 בתים, unsigned short, Little-Endian).
     * - payloadSize: גודל תוכן הבקשה (Payload) בבתים שמגיע מיד לאחר הכותרת (4 בתים, unsigned int).
     */
    struct RequestHeader {
        uint8_t  clientId[CLIENT_ID_SIZE];
        uint8_t  version;
        uint16_t code;
        uint32_t payloadSize;
    };

    /**
     * @struct ResponseHeader
     * @brief כותרת תשובה בינארית מהשרת ללקוח (7 בתים בדיוק).
     *
     * שדות המבנה:
     * - version: מספר גרסת השרת (1 בית, צפוי 3).
     * - code: קוד התשובה מתוך `ResponseCode` (2 בתים, unsigned short, Little-Endian).
     * - payloadSize: גודל תוכן התשובה (Payload) בבתים שמגיע מיד לאחר הכותרת (4 בתים, unsigned int).
     */
    struct ResponseHeader {
        uint8_t  version;
        uint16_t code;
        uint32_t payloadSize;
    };

    /**
     * @struct NamePayload
     * @brief מבנה ה-Payload עבור בקשות המכילות שם בלבד (255 בתים):
     *        - בקשה 825 (רישום - שם משתמש)
     *        - בקשה 827 (התחברות חוזרת - שם משתמש)
     *        - בקשות 900, 901, 902 (אימות CRC - שם הקובץ הנשלח)
     */
    struct NamePayload {
        char name[NAME_FIELD_SIZE]; ///< מחרוזת ASCII כולל תו מסיים null ('\0') ומרופדת באפסים
    };

    /**
     * @struct PublicKeyPayload
     * @brief מבנה ה-Payload עבור בקשה 826 (שליחת מפתח ציבורי - 415 בתים):
     *        255 בתים שם משתמש + 160 בתים מפתח ציבורי RSA בפורמט X.509.
     */
    struct PublicKeyPayload {
        char    name[NAME_FIELD_SIZE];        ///< שם המשתמש (ASCII, null-terminated, 255 בתים)
        uint8_t publicKey[PUBLIC_KEY_SIZE];   ///< מפתח ציבורי RSA-1024 בפורמט X.509 (160 בתים)
    };

    /**
     * @struct SendFilePayloadHeader
     * @brief כותרת המשנה הקבועה בתחילת ה-Payload של בקשה 828 (שליחת קובץ - 267 בתים),
     *        ולאחריה מגיע תוכן החבילה המוצפן (`Message Content`) בגודל משתנה.
     */
    struct SendFilePayloadHeader {
        uint32_t contentSize;                ///< גודל הקובץ הכולל בבתים לאחר הצפנה ב-AES (4 בתים)
        uint32_t origFileSize;               ///< גודל הקובץ המקורי בבתים לפני הצפנה (4 בתים)
        uint16_t packetNumber;               ///< מספר החבילה הנוכחית, החל מ-1 (2 בתים)
        uint16_t totalPackets;               ///< סה"כ מספר החבילות המרכיבות את הקובץ (2 בתים)
        char     fileName[NAME_FIELD_SIZE];  ///< שם הקובץ הנשלח, ללא הנתיב המלא (ASCII, null-terminated, 255 בתים)
    };

    /**
     * @struct FileCrcResponsePayload
     * @brief מבנה ה-Payload של תשובה 1603 מהשרת (קובץ התקבל תקין עם CRC - 279 בתים).
     */
    struct FileCrcResponsePayload {
        uint8_t  clientId[CLIENT_ID_SIZE];   ///< מזהה הלקוח השולח (16 בתים)
        uint32_t contentSize;                ///< גודל הקובץ לאחר הצפנה (4 בתים)
        char     fileName[NAME_FIELD_SIZE];  ///< שם הקובץ הנשלח (255 בתים)
        uint32_t cksum;                      ///< ערך ה-CRC (POSIX cksum) שחושב על ידי השרת (4 בתים)
    };

#pragma pack(pop)

    // וידוא גדלי המבנים בזמן הידור (Compile-time assertions) למניעת חריגות מהפרוטוקול
    static_assert(sizeof(RequestHeader) == REQUEST_HEADER_SIZE, "RequestHeader must be exactly 23 bytes");
    static_assert(sizeof(ResponseHeader) == RESPONSE_HEADER_SIZE, "ResponseHeader must be exactly 7 bytes");
    static_assert(sizeof(NamePayload) == NAME_FIELD_SIZE, "NamePayload must be exactly 255 bytes");
    static_assert(sizeof(PublicKeyPayload) == NAME_FIELD_SIZE + PUBLIC_KEY_SIZE, "PublicKeyPayload must be 415 bytes");
    static_assert(sizeof(SendFilePayloadHeader) == 4 + 4 + 2 + 2 + NAME_FIELD_SIZE, "SendFilePayloadHeader must be 267 bytes");
    static_assert(sizeof(FileCrcResponsePayload) == CLIENT_ID_SIZE + 4 + NAME_FIELD_SIZE + 4, "FileCrcResponsePayload must be 279 bytes");

    // =========================================================================
    // פונקציות עזר לאריזה ופריקה של שדות הפרוטוקול
    // =========================================================================

    /**
     * @brief יצירת כותרת בקשה (`RequestHeader`) מוכנה לשליחה.
     * @param clientId מערך 16 הבתים של מזהה הלקוח.
     * @param code קוד הבקשה מתוך `RequestCode`.
     * @param payloadSize גודל ה-Payload בבתים.
     * @return מבנה `RequestHeader` מאותחל.
     */
    RequestHeader createRequestHeader(const ClientIdArray& clientId, RequestCode code, uint32_t payloadSize);

    /**
     * @brief העתקת מחרוזת ASCII לתוך שדה קבוע של 255 בתים מרופד באפסים (Null-terminated).
     *        זורקת חריגת `std::invalid_argument` אם אורך המחרוזת גדול או שווה ל-255.
     * @param text המחרוזת להעתקה (שם לקוח או שם קובץ).
     * @param destBuffer מצביע למערך יעד בגודל `NAME_FIELD_SIZE` (255 בתים).
     */
    void packFixedName(const std::string& text, char (&destBuffer)[NAME_FIELD_SIZE]);

    /**
     * @brief חילוץ בטוח של מחרוזת מתוך שדה קבוע בגודל 255 בתים (עוצרת בתו ה-null הראשון).
     * @param srcBuffer מערך המקור בגודל `NAME_FIELD_SIZE` (255 בתים).
     * @return מחרוזת `std::string` נקייה מתווי ריפוד.
     */
    std::string extractFixedName(const char (&srcBuffer)[NAME_FIELD_SIZE]);

    /**
     * @brief המרת מערך 16 בתים של Client ID למחרוזת הקסדצימלית (32 תווי ASCII באותיות קטנות).
     *        משמשת לשמירת המזהה בשורה השנייה של הקובץ `me.info`.
     * @param clientId מערך 16 הבתים של המזהה הייחודי.
     * @return מחרוזת הקסדצימלית באורך 32 תווים.
     */
    std::string clientIdToHex(const ClientIdArray& clientId);

    /**
     * @brief המרת מחרוזת הקסדצימלית בת 32 תווי ASCII למערך בינארי של 16 בתים (`ClientIdArray`).
     *        משמשת לטעינת המזהה הייחודי מתוך הקובץ `me.info`.
     * @param hexStr מחרוזת הקסדצימלית באורך 32 תווים.
     * @return מערך של 16 בתים המייצג את ה-UUID של הלקוח.
     */
    ClientIdArray hexToClientId(const std::string& hexStr);

} // namespace Protocol

