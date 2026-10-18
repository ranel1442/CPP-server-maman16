/**
 * קובץ: Config.h
 * ניהול קובצי ההנחיות והמפתחות של הלקוח לפי עמודים 4-5 במטלה:
 * 1. transfer.json - קובץ ההנחיות ללקוח (כתובת IP, פורט, שם הלקוח עד 100 תווים, ורשימת מסלולי הקבצים להעברה).
 * 2. me.info - קובץ טקסט לשמירת השם (שורה 1), המזהה הייחודי ב-hex (שורה 2), והמפתח הפרטי ב-Base64 (שורה 3).
 * 3. priv.key - קובץ לשמירת המפתח הפרטי של ה-RSA לשימוש חוזר בהתחברות חוזרת.
 */

#pragma once

#include "Protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Config {

    // שמות הקבצים בתיקייה של קובץ ההרצה (.exe) לפי עמודים 4-5 במטלה
    constexpr const char* TRANSFER_JSON_FILENAME = "transfer.json";
    constexpr const char* ME_INFO_FILENAME       = "me.info";
    constexpr const char* PRIV_KEY_FILENAME      = "priv.key";

    // מבנה נתונים המחזיק את ההגדרות שנקראו מתוך הקובץ transfer.json (לפי עמוד 4 במטלה)
    struct TransferConfig {
        std::string              serverIp;
        uint16_t                 serverPort = 0;
        std::string              clientName;
        std::vector<std::string> files;
    };

    // מבנה נתונים המחזיק את תוכן הקובץ me.info (לפי עמוד 4 במטלה)
    struct MeInfo {
        std::string             clientName;       // שורה ראשונה: שם הלקוח
        Protocol::ClientIdArray clientId{};       // שורה שנייה: מזהה ייחודי (16 בתים / 32 תווי hex)
        std::string             privateKeyBase64; // שורה שלישית: מפתח פרטי בפורמט Base64
    };

    // קריאה ופענוח של הקובץ transfer.json מתיקיית ההרצה (עמוד 4)
    TransferConfig loadTransferConfig(const std::string& filePath = TRANSFER_JSON_FILENAME);

    // בדיקה האם הקובץ me.info קיים (לפי עמוד 5: קובע האם לבצע רישום 825 או התחברות חוזרת 827)
    bool meInfoExists(const std::string& filePath = ME_INFO_FILENAME);

    // קריאת השם, המזהה הייחודי והמפתח הפרטי מתוך הקובץ me.info (עמוד 4)
    MeInfo loadMeInfo(const std::string& filePath = ME_INFO_FILENAME);

    // שמירת השם, המזהה הייחודי והמפתח הפרטי לקובץ me.info (עמודים 4-5)
    void saveMeInfo(const MeInfo& info, const std::string& filePath = ME_INFO_FILENAME);

    // בדיקה האם הקובץ priv.key קיים בדיסק (עמוד 5)
    bool privKeyExists(const std::string& filePath = PRIV_KEY_FILENAME);

    // שמירת המפתח הפרטי של ה-RSA לקובץ priv.key (עמוד 5)
    void savePrivateKeyFile(const std::string& privateKeyData, const std::string& filePath = PRIV_KEY_FILENAME);

    // קריאת המפתח הפרטי של ה-RSA מהקובץ priv.key בעת התחברות חוזרת (עמוד 5)
    std::string loadPrivateKeyFile(const std::string& filePath = PRIV_KEY_FILENAME);

} // namespace Config
