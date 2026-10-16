/**
 * @file Config.h
 * @brief הצהרת מבני נתונים ופונקציות לניהול קובצי התצורה והמפתחות של הלקוח (`transfer.json`, `me.info`, `priv.key`).
 *
 * מודול זה אחראי על:
 * 1. קריאה ופענוח של קובץ ההנחיות `transfer.json` מתיקיית קובץ ההרצה:
 *    - אובייקט `server` הכולל: `ip` (כתובת השרת), `port` (פורט תקשורת), ו-`client` (שם הלקוח - עד 100 תווים).
 *    - מערך `files` הכולל את רשימת נתיבי הקבצים שיש להעביר לשרת.
 * 2. קריאה וכתיבה של הקובץ `me.info`:
 *    - שורה ראשונה: שם הלקוח.
 *    - שורה שנייה: מזהה ייחודי (UUID של 16 בתים) בייצוג ASCII הקסדצימלי בן 32 תווים.
 *    - שורה שלישית והלאה: המפתח הפרטי של הלקוח בפורמט Base64.
 * 3. קריאה וכתיבה של הקובץ `priv.key` (שמירת וטעינת המפתח הפרטי של RSA).
 *
 * מי קורא למודול זה:
 * - תוכנית הלקוח הראשית בעת העלייה (טעינת `transfer.json`, בדיקה האם `me.info` קיים לצורך בחירה בין רישום 825 להתחברות חוזרת 827,
 *   ושמירה/טעינה של `me.info` ו-`priv.key`).
 */

#pragma once

#include "Protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Config {

    // =========================================================================
    // שמות קובצי התצורה הקבועים לפי מפרט המטלה (בתיקיית קובץ ההרצה)
    // =========================================================================
    constexpr const char* TRANSFER_JSON_FILENAME = "transfer.json"; ///< קובץ הנחיות ללקוח (פרטי שרת, שם לקוח ורשימת קבצים)
    constexpr const char* ME_INFO_FILENAME       = "me.info";       ///< קובץ פרטי לקוח רשום (שם, UUID ב-Hex, ומפתח פרטי ב-Base64)
    constexpr const char* PRIV_KEY_FILENAME      = "priv.key";      ///< קובץ המפתח הפרטי של הלקוח (RSA Private Key)

    /**
     * @struct TransferConfig
     * @brief מבנה נתונים המייצג את תוכן הקובץ `transfer.json`.
     *
     * שדות המבנה:
     * - serverIp: כתובת ה-IP של השרת (לדוגמה "127.0.0.1" או "192.168.1.5").
     * - serverPort: פורט ה-TCP של השרת (1–65535).
     * - clientName: שם הלקוח מתוך קובץ ההנחיות (מחרוזת עד 100 תווים).
     * - files: וקטור מחרוזות המכיל את מסלולי הקבצים המיועדים להעברה לשרת.
     */
    struct TransferConfig {
        std::string              serverIp;
        uint16_t                 serverPort = 0;
        std::string              clientName;
        std::vector<std::string> files;
    };

    /**
     * @struct MeInfo
     * @brief מבנה נתונים המייצג את תוכן הקובץ `me.info`.
     *
     * שדות המבנה:
     * - clientName: שורה 1 - שם הלקוח.
     * - clientId: שורה 2 - המזהה הייחודי של הלקוח (16 בתים בינאריים, נשמר בקובץ כ-32 תווי Hex).
     * - privateKeyBase64: שורה 3 והלאה - המפתח הפרטי של הלקוח בפורמט Base64.
     */
    struct MeInfo {
        std::string             clientName;
        Protocol::ClientIdArray clientId{};
        std::string             privateKeyBase64;
    };

    // =========================================================================
    // פונקציות ניהול קובצי תצורה ומפתחות
    // =========================================================================

    /**
     * @brief קריאה ופענוח של הקובץ `transfer.json`.
     *        תומכת גם בנתיבי חלונות בקובץ ה-JSON שבהם מופיע לוכסן יחיד (כמו בדוגמת המטלה `"c:\doc\file02.docx"`).
     *        זורקת חריגת `std::runtime_error` אם הקובץ חסר, פגום, או ששדות החובה אינם תקינים.
     *
     * @param filePath נתיב הקובץ (ברירת מחדל: `"transfer.json"`).
     * @return מבנה `TransferConfig` מאוכלס בפרטי השרת, שם הלקוח ורשימת הקבצים.
     */
    TransferConfig loadTransferConfig(const std::string& filePath = TRANSFER_JSON_FILENAME);

    /**
     * @brief בדיקה האם הקובץ `me.info` קיים בתיקיית ההרצה.
     *        לפי מפרט המטלה: אם הקובץ לא קיים - הלקוח מבצע רישום (825); אם קיים - הלקוח מבצע התחברות חוזרת (827).
     *
     * @param filePath נתיב הקובץ (ברירת מחדל: `"me.info"`).
     * @return `true` אם הקובץ קיים וניתן לפתיחה, אחרת `false`.
     */
    bool meInfoExists(const std::string& filePath = ME_INFO_FILENAME);

    /**
     * @brief קריאת פרטי הלקוח מתוך הקובץ `me.info`.
     *        זורקת חריגת `std::runtime_error` אם הקובץ אינו קיים או שהמבנה שלו שגוי.
     *
     * @param filePath נתיב הקובץ (ברירת מחדל: `"me.info"`).
     * @return מבנה `MeInfo` המכיל את שם הלקוח, ה-UUID (16 בתים), והמפתח הפרטי ב-Base64.
     */
    MeInfo loadMeInfo(const std::string& filePath = ME_INFO_FILENAME);

    /**
     * @brief שמירת פרטי הלקוח לקובץ `me.info` לפי הפורמט המחייב במטלה:
     *        שורה 1: שם הלקוח
     *        שורה 2: מזהה ייחודי ב-Hex (32 תווים)
     *        שורה 3: מפתח פרטי בפורמט Base64
     *
     * @param info מבנה `MeInfo` לשמירה.
     * @param filePath נתיב הקובץ (ברירת מחדל: `"me.info"`).
     */
    void saveMeInfo(const MeInfo& info, const std::string& filePath = ME_INFO_FILENAME);

    /**
     * @brief בדיקה האם הקובץ `priv.key` קיים בדיסק.
     *
     * @param filePath נתיב הקובץ (ברירת מחדל: `"priv.key"`).
     * @return `true` אם הקובץ קיים, אחרת `false`.
     */
    bool privKeyExists(const std::string& filePath = PRIV_KEY_FILENAME);

    /**
     * @brief שמירת המפתח הפרטי של RSA לקובץ `priv.key`.
     *
     * @param privateKeyData תוכן המפתח הפרטי (בפורמט Base64 או DER/בינארי כמחרוזת בתים).
     * @param filePath נתיב הקובץ (ברירת מחדל: `"priv.key"`).
     */
    void savePrivateKeyFile(const std::string& privateKeyData, const std::string& filePath = PRIV_KEY_FILENAME);

    /**
     * @brief טעינת המפתח הפרטי של RSA מתוך הקובץ `priv.key`.
     *        זורקת חריגת `std::runtime_error` אם הקובץ אינו קיים או ריק.
     *
     * @param filePath נתיב הקובץ (ברירת מחדל: `"priv.key"`).
     * @return תוכן הקובץ `priv.key` כמחרוזת (`std::string`).
     */
    std::string loadPrivateKeyFile(const std::string& filePath = PRIV_KEY_FILENAME);

} // namespace Config

