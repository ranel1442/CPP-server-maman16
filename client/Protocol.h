/**
 * קובץ: Protocol.h
 * מימוש מבני הנתונים, הקבועים וקודי הבקשות והתשובות של פרוטוקול התקשורת הבינארי בצד הלקוח
 * (בהתאם לעמודים 4-8 בחוברת המטלה).
 *
 * כל השדות המספריים בפרוטוקול מיוצגים כטיפוסים חסרי סימן (unsigned) בפורמט Little-Endian,
 * והמבנים ארוזים בצפיפות ללא ריפוד בתים (#pragma pack(push, 1)) כדי להתאים בדיוק לטבלאות המטלה.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace Protocol {

    // מימוש קבועי הלקוח והפרוטוקול לפי עמוד 4 סעיף ד' וטבלאות עמודים 6-8 במטלה:
    constexpr uint8_t  CLIENT_VERSION          = 3;    // גרסת הלקוח היא 3 (עמוד 4 סעיף ד')
    constexpr size_t   CLIENT_ID_SIZE          = 16;   // גודל מזהה ייחודי UUID בבתים (128 ביט - עמוד 6)
    constexpr size_t   MAX_CONFIG_CLIENT_NAME  = 100;  // אורך שם לקוח בקובץ transfer.json (עד 100 תווים - עמוד 4)
    constexpr size_t   NAME_FIELD_SIZE         = 255;  // גודל שדה Name / File Name בפרוטוקול כולל תו null מסיים (עמודים 6-7)
    constexpr size_t   PUBLIC_KEY_SIZE         = 160;  // גודל מפתח ציבורי RSA-1024 בפורמט X.509 של Crypto++ (עמודים 6 ו-11)
    constexpr size_t   AES_KEY_SIZE            = 32;   // גודל מפתח סימטרי AES-256 בבתים (256 ביט - עמוד 9)
    constexpr size_t   AES_BLOCK_SIZE          = 16;   // גודל בלוק AES וגודל ה-IV המאופס בבתים (עמוד 9)
    constexpr size_t   REQUEST_HEADER_SIZE     = 23;   // גודל כותרת בקשה לשרת: 16 + 1 + 2 + 4 = 23 בתים (עמוד 6)
    constexpr size_t   RESPONSE_HEADER_SIZE    = 7;    // גודל כותרת תשובה מהשרת: 1 + 2 + 4 = 7 בתים (עמוד 7)
    constexpr size_t   FILE_PACKET_CHUNK_SIZE  = 4096; // גודל מקטע תוכן קובץ בחבילה בודדת בבקשה 828 (עמוד 7 ועמוד 11 סעיף 4.ה)
    constexpr uint32_t MAX_RETRY_ATTEMPTS      = 3;    // עד 3 ניסיונות חוזרים בשגיאת שרת או בשגיאת CRC (עמודים 1, 3 ו-5)

    // טיפוס מערך קבוע של 16 בתים לייצוג ה-Client ID
    using ClientIdArray = std::array<uint8_t, CLIENT_ID_SIZE>;

    // מימוש קודי הבקשות מהלקוח לשרת (2 בתים, unsigned) לפי הטבלאות בעמודים 6-7 במטלה
    enum class RequestCode : uint16_t {
        REGISTER          = 825, // רישום לקוח חדש
        SEND_PUBLIC_KEY   = 826, // שליחת מפתח ציבורי
        RECONNECT         = 827, // התחברות חוזרת (במידה והלקוח נרשם כבר בעבר)
        SEND_FILE         = 828, // שליחת קובץ מוצפן
        CRC_OK            = 900, // CRC תקין
        CRC_INVALID_RETRY = 901, // CRC לא תקין, שולח שוב (לאחר מכן תגיע שוב בקשה 828)
        CRC_INVALID_ABORT = 902  // CRC לא תקין בפעם הרביעית, סיימתי
    };

    // מימוש קודי התשובות מהשרת ללקוח (2 בתים, unsigned) לפי הטבלאות בעמודים 7-8 במטלה
    enum class ResponseCode : uint16_t {
        REGISTER_SUCCESS            = 1600, // רישום הצליח
        REGISTER_FAILED             = 1601, // רישום נכשל
        PUBLIC_KEY_RECEIVED_AES     = 1602, // התקבל מפתח ציבורי ושולח מפתח AES מוצפן
        FILE_RECEIVED_WITH_CRC      = 1603, // קובץ התקבל תקין עם CRC
        MESSAGE_RECEIVED_THANKS     = 1604, // מאשר קבלת הודעה, תודה (בתגובה ל-900 או 902)
        RECONNECT_APPROVED_SEND_AES = 1605, // מאשר בקשה להתחברות חוזרת, שולח מפתח AES מוצפן
        RECONNECT_REJECTED          = 1606, // בקשה להתחברות חוזרת נדחתה (על הלקוח להירשם מחדש כמו לקוח חדש)
        GENERAL_ERROR               = 1607  // שגיאה כללית בשרת
    };

#pragma pack(push, 1)

    // מימוש מבנה כותרת בקשה לשרת (23 בתים) לפי הטבלה בעמוד 6 במטלה
    struct RequestHeader {
        uint8_t  clientId[CLIENT_ID_SIZE]; // מזהה ייחודי עבור הלקוח (16 בתים)
        uint8_t  version;                  // מספר גרסת לקוח (1 בית)
        uint16_t code;                     // קוד בקשה (2 בתים)
        uint32_t payloadSize;              // גודל תוכן הבקשה (4 בתים)
    };

    // מימוש מבנה כותרת תשובה מהשרת (7 בתים) לפי הטבלה בעמוד 7 במטלה
    struct ResponseHeader {
        uint8_t  version;     // מספר גרסת שרת (1 בית)
        uint16_t code;        // קוד התשובה (2 בתים)
        uint32_t payloadSize; // גודל תוכן התשובה (4 בתים)
    };

    // מימוש מבנה ה-Payload עבור בקשות המכילות שם באורך 255 בתים (בקשות 825, 827, 900, 901, 902 בעמודים 6-7)
    struct NamePayload {
        char name[NAME_FIELD_SIZE]; // מחרוזת ASCII המייצגת שם משתמש או שם קובץ, כולל תו null מסיים
    };

    // מימוש מבנה ה-Payload עבור בקשה 826 (שליחת מפתח ציבורי - 415 בתים) לפי הטבלה בעמוד 6 במטלה
    struct PublicKeyPayload {
        char    name[NAME_FIELD_SIZE];      // שם המשתמש (255 בתים כולל תו null מסיים)
        uint8_t publicKey[PUBLIC_KEY_SIZE]; // מפתח ציבורי של הלקוח (160 בתים)
    };

    // מימוש השדות הקבועים ב-Payload של בקשה 828 (שליחת קובץ - 267 בתים לפני תוכן ההודעה המוצפן) לפי עמוד 7 במטלה
    struct SendFilePayloadHeader {
        uint32_t contentSize;               // גודל הקובץ הכולל לאחר הצפנה (4 בתים)
        uint32_t origFileSize;              // גודל הקובץ המקורי לפני הצפנה (4 בתים)
        uint16_t packetNumber;              // מספר הודעה/חבילה נוכחית (2 בתים)
        uint16_t totalPackets;              // סה"כ מספר הודעות/חבילות (2 בתים)
        char     fileName[NAME_FIELD_SIZE]; // שם הקובץ הנשלח (255 בתים כולל תו null מסיים)
    };

    // מימוש מבנה ה-Payload של תשובה 1603 מהשרת (קובץ התקבל תקין עם CRC - 279 בתים) לפי הטבלה בעמוד 8 במטלה
    struct FileCrcResponsePayload {
        uint8_t  clientId[CLIENT_ID_SIZE];  // מזהה ייחודי של הלקוח השולח (16 בתים)
        uint32_t contentSize;               // גודל הקובץ לאחר הצפנה (4 בתים)
        char     fileName[NAME_FIELD_SIZE]; // שם הקובץ הנשלח (255 בתים)
        uint32_t cksum;                     // ערך ה-CRC שחושב בשרת (4 בתים)
    };

#pragma pack(pop)

    // בדיקות בזמן קומפילציה שגודל המבנים בזיכרון תואם בדיוק לטבלאות הפרוטוקול במטלה
    static_assert(sizeof(RequestHeader) == REQUEST_HEADER_SIZE, "RequestHeader must be 23 bytes");
    static_assert(sizeof(ResponseHeader) == RESPONSE_HEADER_SIZE, "ResponseHeader must be 7 bytes");
    static_assert(sizeof(NamePayload) == NAME_FIELD_SIZE, "NamePayload must be 255 bytes");
    static_assert(sizeof(PublicKeyPayload) == NAME_FIELD_SIZE + PUBLIC_KEY_SIZE, "PublicKeyPayload must be 415 bytes");
    static_assert(sizeof(SendFilePayloadHeader) == 267, "SendFilePayloadHeader must be 267 bytes");
    static_assert(sizeof(FileCrcResponsePayload) == 279, "FileCrcResponsePayload must be 279 bytes");

    // יצירת כותרת בקשה (RequestHeader) עם גרסת הלקוח (3), מזהה הלקוח, קוד הבקשה וגודל ה-Payload
    RequestHeader createRequestHeader(const ClientIdArray& clientId, RequestCode code, uint32_t payloadSize);

    // העתקת מחרוזת ASCII לתוך שדה בגודל קבוע של 255 בתים כולל איפוס וריפוד ב-null terminator (לפי עמודים 6-7)
    void packFixedName(const std::string& text, char (&destBuffer)[NAME_FIELD_SIZE]);

    // חילוץ מחרוזת מתוך שדה קבוע בגודל 255 בתים (עד תו ה-null הראשון)
    std::string extractFixedName(const char (&srcBuffer)[NAME_FIELD_SIZE]);

    // המרת מזהה הלקוח (16 בתים) לייצוג ASCII הקסדצימלי של 32 תווים (עבור השורה השנייה בקובץ me.info לפי עמוד 4)
    std::string clientIdToHex(const ClientIdArray& clientId);

    // המרת מחרוזת הקסדצימלית בת 32 תווים מהקובץ me.info חזרה למערך 16 בתים של Client ID (לפי עמוד 4)
    ClientIdArray hexToClientId(const std::string& hexStr);

} // namespace Protocol
