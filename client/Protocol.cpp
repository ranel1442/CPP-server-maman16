/**
 * קובץ: Protocol.cpp
 * מימוש פונקציות העזר של הפרוטוקול: בניית כותרת בקשה, טיפול בשדות מחרוזת בגודל קבוע (255 בתים),
 * והמרת ה-Client ID (16 בתים) בין ייצוג בינארי לייצוג הקסדצימלי עבור הקובץ me.info.
 */

#include "Protocol.h"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace Protocol {

    // מימוש בניית כותרת בקשה בת 23 בתים מהלקוח לשרת (לפי טבלת Request Header בעמוד 6 במטלה)
    RequestHeader createRequestHeader(const ClientIdArray& clientId, RequestCode code, uint32_t payloadSize) {
        RequestHeader header{};
        std::memcpy(header.clientId, clientId.data(), CLIENT_ID_SIZE);
        header.version = CLIENT_VERSION;
        header.code = static_cast<uint16_t>(code);
        header.payloadSize = payloadSize;
        return header;
    }

    // מימוש דרישת הפרוטוקול לשדות Name ו-File Name בגודל 255 בתים כולל תו מסיים null (עמודים 6-7 במטלה)
    void packFixedName(const std::string& text, char (&destBuffer)[NAME_FIELD_SIZE]) {
        if (text.size() >= NAME_FIELD_SIZE) {
            throw std::invalid_argument("Name exceeds maximum allowed length of 254 characters.");
        }
        std::memset(destBuffer, 0, NAME_FIELD_SIZE);
        std::memcpy(destBuffer, text.data(), text.size());
    }

    // חילוץ בטוח של שם מתוך שדה קבוע של 255 בתים (עוצר בתו ה-null הראשון)
    std::string extractFixedName(const char (&srcBuffer)[NAME_FIELD_SIZE]) {
        const char* nullPos = static_cast<const char*>(std::memchr(srcBuffer, '\0', NAME_FIELD_SIZE));
        if (nullPos == nullptr) {
            throw std::runtime_error("Invalid fixed-size string field: missing null terminator.");
        }
        return std::string(srcBuffer, static_cast<size_t>(nullPos - srcBuffer));
    }

    // מימוש המרת ה-UUID (16 בתים) למחרוזת ASCII שבה כל שני תווים מייצגים ערך hex בעל 8 סיביות (לפי עמוד 4 במטלה)
    std::string clientIdToHex(const ClientIdArray& clientId) {
        std::ostringstream oss;
        oss << std::hex << std::nouppercase << std::setfill('0');
        for (uint8_t byte : clientId) {
            oss << std::setw(2) << static_cast<unsigned int>(byte);
        }
        return oss.str();
    }

    // מימוש קריאת ה-UUID מתוך שורה 2 של הקובץ me.info (32 תווי hex -> 16 בתים בינאריים, לפי עמוד 4 במטלה)
    ClientIdArray hexToClientId(const std::string& hexStr) {
        if (hexStr.size() != CLIENT_ID_SIZE * 2) {
            throw std::invalid_argument("Invalid hex Client ID length in me.info (expected 32 hex chars).");
        }

        ClientIdArray clientId{};
        for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
            std::string byteStr = hexStr.substr(i * 2, 2);
            size_t processed = 0;
            unsigned long val = std::stoul(byteStr, &processed, 16);
            if (processed != 2 || val > 0xFF) {
                throw std::invalid_argument("Invalid hex character in Client ID.");
            }
            clientId[i] = static_cast<uint8_t>(val);
        }
        return clientId;
    }

} // namespace Protocol
