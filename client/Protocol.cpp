/**
 * @file Protocol.cpp
 * @brief מימוש פונקציות העזר של הפרוטוקול הבינארי עבור צד הלקוח (C++20).
 *
 * קובץ זה מממש את הפונקציות המוצהרות ב-`Protocol.h`:
 * - יצירת כותרת בקשה (`createRequestHeader`) בפורמט Little-Endian.
 * - אריזת וחילוץ שמות משתמשים ושמות קבצים בשדות קבועים של 255 בתים (`packFixedName`, `extractFixedName`).
 * - המרה דו-כיוונית של מזהה הלקוח הייחודי (16 בתים) בין ייצוג בינארי לייצוג הקסדצימלי (`clientIdToHex`, `hexToClientId`).
 *
 * מי קורא למודול זה:
 * - מודול הקונפיגורציה (`Config.cpp`) להמרת המזהה הייחודי בקובץ `me.info`.
 * - מודול ניהול התקשורת והלקוח בעת בניית בקשות לשרת ופענוח תשובותיו.
 */

#include "Protocol.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace Protocol {

    /**
     * @brief יצירת כותרת בקשה (`RequestHeader`) בת 23 בתים מוכנה לשליחה.
     */
    RequestHeader createRequestHeader(const ClientIdArray& clientId, RequestCode code, uint32_t payloadSize) {
        RequestHeader header{};
        std::memcpy(header.clientId, clientId.data(), CLIENT_ID_SIZE);
        header.version = CLIENT_VERSION;
        header.code = static_cast<uint16_t>(code);
        header.payloadSize = payloadSize;
        return header;
    }

    /**
     * @brief העתקת מחרוזת ASCII לשדה קבוע בן 255 בתים, כולל ריפוד באפסים ותו null מסיים.
     */
    void packFixedName(const std::string& text, char (&destBuffer)[NAME_FIELD_SIZE]) {
        if (text.size() >= NAME_FIELD_SIZE) {
            throw std::invalid_argument("Name exceeds maximum allowed length of 254 characters (must include null terminator).");
        }
        // איפוס מלא של הבאפר (255 בתים של '\0') והעתקת תווי המחרוזת
        std::memset(destBuffer, 0, NAME_FIELD_SIZE);
        std::memcpy(destBuffer, text.data(), text.size());
    }

    /**
     * @brief חילוץ בטוח של מחרוזת מתוך שדה קבוע בגודל 255 בתים (עד תו ה-null הראשון).
     */
    std::string extractFixedName(const char (&srcBuffer)[NAME_FIELD_SIZE]) {
        const char* nullPos = static_cast<const char*>(std::memchr(srcBuffer, '\0', NAME_FIELD_SIZE));
        if (nullPos == nullptr) {
            throw std::runtime_error("Invalid fixed-size string field: missing null terminator.");
        }
        return std::string(srcBuffer, static_cast<size_t>(nullPos - srcBuffer));
    }

    /**
     * @brief המרת מערך 16 בתים של Client ID למחרוזת הקסדצימלית בת 32 תווי ASCII.
     */
    std::string clientIdToHex(const ClientIdArray& clientId) {
        std::ostringstream oss;
        oss << std::hex << std::nouppercase << std::setfill('0');
        for (uint8_t byte : clientId) {
            oss << std::setw(2) << static_cast<unsigned int>(byte);
        }
        return oss.str();
    }

    /**
     * @brief המרת מחרוזת הקסדצימלית בת 32 תווי ASCII למערך בינארי של 16 בתים (`ClientIdArray`).
     */
    ClientIdArray hexToClientId(const std::string& hexStr) {
        if (hexStr.size() != CLIENT_ID_SIZE * 2) {
            throw std::invalid_argument("Invalid hex Client ID length: expected 32 hex characters (16 bytes).");
        }

        ClientIdArray clientId{};
        for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
            std::string byteStr = hexStr.substr(i * 2, 2);
            size_t processed = 0;
            unsigned long val = std::stoul(byteStr, &processed, 16);
            if (processed != 2 || val > 0xFF) {
                throw std::invalid_argument("Invalid hex character encountered in Client ID.");
            }
            clientId[i] = static_cast<uint8_t>(val);
        }
        return clientId;
    }

} // namespace Protocol

