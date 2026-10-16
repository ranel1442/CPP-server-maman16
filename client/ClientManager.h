/**
 * @file ClientManager.h
 * @brief הצהרת המחלקה הראשית (`ClientManager`) המנהלת את לוגיקת הלקוח במצב Batch Mode.
 *
 * מחלקה זו מחברת בין מודול הקונפיגורציה (`Config`), מודול הרשת (`Network::SocketClient`),
 * מודול ההצפנה (`Crypto::CryptoWrapper`), ומודול חישוב ה-CRC (`Cksum`), ומממשת את כל תרשים הזרימה
 * של הפרוטוקול לפי מפרט המטלה:
 * 1. קריאת הקובץ `transfer.json` (פרטי שרת, שם לקוח ורשימת קבצים להעברה).
 * 2. פתיחת חיבור TCP מול השרת.
 * 3. בדיקה האם הקובץ `me.info` קיים:
 *    - אם אינו קיים: ביצוע רישום לקוח חדש (בקשה 825 -> תשובה 1600), יצירת זוג מפתחות RSA-1024,
 *      שמירת המפתח הפרטי ל-`priv.key` ושמירת פרטי הלקוח ל-`me.info`, שליחת המפתח הציבורי לשרת
 *      (בקשה 826 -> תשובה 1602), ופענוח מפתח ה-AES המוצפן.
 *    - אם קיים: טעינת פרטי הלקוח מ-`me.info` והמפתח הפרטי מ-`priv.key`, שליחת בקשת התחברות חוזרת
 *      (בקשה 827). אם התקבלה תשובה 1605 - פענוח מפתח ה-AES; אם התקבלה תשובה 1606 (נדחה) -
 *      ביצוע רישום מחדש כלקוח חדש (825 + 826).
 * 4. מעבר בלולאה על כל הקבצים ברשימה מתוך `transfer.json`:
 *    - קריאת תוכן הקובץ וחישוב ה-CRC המקומי שלו (`Cksum::calculate_cksum`).
 *    - הצפנת תוכן הקובץ באמצעות `AES-CBC` ושליחתו בבקשה 828 (תמיכה בחלוקה לחבילות `packetNumber` מתוך `totalPackets`).
 *    - קבלת תשובה 1603 והשוואת ה-CRC שחושב בשרת ל-CRC המקומי:
 *      * אם תואם: שליחת בקשה 900 (`CRC_OK`) וקבלת אישור 1604.
 *      * אם שגוי: שליחת בקשה 901 (`CRC_INVALID_RETRY`) ושליחה חוזרת של הקובץ (עד 3 פעמים).
 *      * בכישלון רביעי: שליחת בקשה 902 (`CRC_INVALID_ABORT`), קבלת אישור 1604, ומעבר לקובץ הבא.
 * 5. טיפול בשגיאות שרת: בכל מקרה של שגיאת שרת מודפסת ההודעה `"server responded with an error"`
 *    ומתבצע ניסיון חוזר עד 3 פעמים לפני יציאה עם הודעת Fatal מפורטת.
 *
 * מי קורא למודול זה:
 * - הפונקציה הראשית `main()` בקובץ `main.cpp` שיוצרת מופע של `ClientManager` וקוראת ל-`start()`.
 */

#pragma once

#include "Config.h"
#include "CryptoWrapper.h"
#include "Protocol.h"
#include "SocketClient.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ClientApp {

    /**
     * @class ClientManager
     * @brief המחלקה המרכזית המנהלת את זרימת הפעולות הקבועה של הלקוח (Batch Mode).
     *
     * שדות פרטיים מרכזיים:
     * - `m_transferConfig`: נתוני השרת, שם הלקוח ורשימת הקבצים שנטענו מ-`transfer.json`.
     * - `m_socket`: אובייקט תקשורת ה-TCP מול השרת (`Network::SocketClient`).
     * - `m_crypto`: אובייקט ההצפנה והמפתחות RSA/AES (`Crypto::CryptoWrapper`).
     * - `m_clientId`: המזהה הייחודי של הלקוח (16 בתים - `Protocol::ClientIdArray`).
     * - `m_clientName`: שם הלקוח הפעיל מול השרת.
     */
    class ClientManager {
    public:
        /**
         * @brief בנאי ברירת מחדל - מאתחל את שדות הלקוח והמזהה הייחודי.
         */
        ClientManager();

        /**
         * @brief הפעלת תהליך הלקוח הראשי במצב Batch Mode:
         *        טעינת הגדרות, התחברות לשרת, רישום/התחברות חוזרת והחלפת מפתחות, ושליחת כל הקבצים.
         *        זורקת חריגת `std::runtime_error` במקרה של שגיאה פטאלית לאחר מיצוי ניסיונות חוזרים.
         */
        void start();

    private:
        /**
         * @brief ביצוע שלב האימות והחלפת המפתחות מול השרת:
         *        בודקת אם `me.info` קיים ומחליטה האם לבצע התחברות חוזרת (827) או רישום חדש (825 + 826).
         */
        void authenticateAndExchangeKeys();

        /**
         * @brief ביצוע תהליך רישום מלא של לקוח חדש:
         *        1. שליחת בקשה 825 וקבלת תשובה 1600 עם ה-`Client ID` (16 בתים).
         *        2. יצירת זוג מפתחות RSA-1024 ושמירתם לקבצים `priv.key` ו-`me.info`.
         *        3. שליחת המפתח הציבורי בבקשה 826, קבלת תשובה 1602, ופענוח מפתח ה-AES.
         */
        void performNewRegistrationFlow();

        /**
         * @brief שליחת בקשת רישום (825) וקבלת `Client ID` בתשובה 1600 (עם עד 3 ניסיונות חוזרים בשגיאת שרת).
         */
        void sendRegisterRequest();

        /**
         * @brief שליחת המפתח הציבורי של ה-RSA (בקשה 826) וקבלת מפתח ה-AES המוצפן בתשובה 1602 (עם עד 3 ניסיונות חוזרים).
         */
        void sendPublicKeyRequest();

        /**
         * @brief ניסיון התחברות חוזרת (בקשה 827) עבור לקוח שכבר רשום ב-`me.info`.
         * @return `true` אם ההתחברות החוזרת אושרה (תשובה 1605) ומפתח ה-AES פוענח בהצלחה;
         *         `false` אם השרת דחה את ההתחברות החוזרת (תשובה 1606) ויש להירשם מחדש כלקוח חדש.
         */
        bool tryReconnectFlow();

        /**
         * @brief טיפול מלא בהעברת קובץ בודד מתוך רשימת הקבצים (כולל אימות CRC ועד 3 ניסיונות שליחה חוזרים).
         * @param filePath נתיב הקובץ המקומי לשליחה.
         */
        void processSingleFile(const std::string& filePath);

        /**
         * @brief שליחת הקובץ המוצפן בבקשה 828 (בחבילה אחת או בחלוקה למספר חבילות אם הקובץ גדול)
         *        וקבלת תשובה 1603 מהשרת עם ה-CRC שחושב בצד השרת.
         *
         * @param fileName שם הקובץ בלבד (ללא נתיב תיקיות, עד 254 תווים + null).
         * @param origFileSize גודל הקובץ המקורי בבתים לפני הצפנה.
         * @param encryptedContent תוכן הקובץ לאחר הצפנה ב-AES-CBC.
         * @param outServerCksum משתנה פלט שיקבל את ערך ה-`cksum` שהחזיר השרת בתשובה 1603.
         */
        void sendEncryptedFileAndGetCrc(
            const std::string& fileName,
            uint32_t origFileSize,
            const std::vector<uint8_t>& encryptedContent,
            uint32_t& outServerCksum
        );

        /**
         * @brief שליחת הודעת סטטוס CRC לשרת (900 = תקין, 901 = לא תקין ושולח שוב, 902 = לא תקין בפעם הרביעית וביטול).
         *        עבור קודים 900 ו-902 הפונקציה ממתינה לתשובת אישור 1604 (`MESSAGE_RECEIVED_THANKS`) מהשרת.
         *        עבור קוד 901 הפונקציה אינה ממתינה לתשובה כי מיד לאחריה נשלחת בקשה 828 חדשה.
         *
         * @param code קוד הבקשה (`CRC_OK`, `CRC_INVALID_RETRY`, או `CRC_INVALID_ABORT`).
         * @param fileName שם הקובץ שעליו מדווחים.
         */
        void sendCrcStatus(Protocol::RequestCode code, const std::string& fileName);

        /**
         * @brief הדפסת הודעת השגיאה המחייבת לפי עמוד 5 במטלה: `"server responded with an error"`.
         */
        static void printServerError();

        /**
         * @brief חילוץ שם הקובץ הבסיסי (Basename) מתוך נתיב מלא (תומך ב-`\` וב-`/`).
         */
        static std::string extractBaseFileName(const std::string& fullPath);

        /**
         * @brief קריאת תוכן בינארי מלא של קובץ מהדיסק לתוך וקטור בתים.
         */
        static std::vector<uint8_t> readBinaryFile(const std::string& filePath);

    private:
        Config::TransferConfig  m_transferConfig; ///< הגדרות השרת, הלקוח והקבצים מתוך transfer.json
        Network::SocketClient   m_socket;         ///< סוקט ה-TCP הפעיל מול השרת
        Crypto::CryptoWrapper   m_crypto;         ///< מנוע ההצפנה (RSA-1024 + AES-256-CBC)
        Protocol::ClientIdArray m_clientId;       ///< מזהה הלקוח הייחודי (16 בתים)
        std::string             m_clientName;     ///< שם הלקוח הנוכחי
    };

} // namespace ClientApp

