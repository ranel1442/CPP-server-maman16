/**
 * קובץ: ClientManager.h
 * הצהרת המחלקה ClientManager המנהלת את סדר הפעולות הקבוע של הלקוח (Batch Mode)
 * לפי תרשימי הזרימה והדרישות בעמודים 3-10 במטלה.
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

    // המחלקה הראשית בצד הלקוח המנהלת את הרישום/התחברות חוזרת, החלפת המפתחות והעברת הקבצים
    class ClientManager {
    public:
        ClientManager();

        // הפעלת סדר הפעולות של הלקוח מההתחלה ועד סיום העברת כל הקבצים (Batch Mode - עמוד 4 סעיף ב')
        void start();

    private:
        // בדיקה אם me.info קיים ובחירה בין רישום לקוח חדש (825 + 826) לבין התחברות חוזרת (827) לפי עמוד 5
        void authenticateAndExchangeKeys();

        // תהליך רישום לקוח חדש: בקשה 825 -> יצירת מפתחות RSA ושמירה ל-me.info ו-priv.key -> בקשה 826
        void performNewRegistrationFlow();

        // שליחת בקשת רישום (825) וקבלת המזהה הייחודי בתשובה 1600 (עם עד 3 ניסיונות חוזרים בשגיאה)
        void sendRegisterRequest();

        // שליחת המפתח הציבורי (826) וקבלת מפתח ה-AES המוצפן בתשובה 1602 (עם עד 3 ניסיונות חוזרים בשגיאה)
        void sendPublicKeyRequest();

        // ניסיון התחברות חוזרת (827): מחזיר true אם אושר (1605), או false אם נדחה (1606) ויש להירשם מחדש
        bool tryReconnectFlow();

        // טיפול מלא בהעברת קובץ בודד: הצפנה ב-AES, שליחה ב-828, השוואת CRC מול 1603 ושליחת 900/901/902
        void processSingleFile(const std::string& filePath);

        // שליחת חבילות הקובץ המוצפן בבקשה 828 וקבלת ערך ה-CRC שחושב בשרת בתשובה 1603
        void sendEncryptedFileAndGetCrc(
            const std::string& fileName,
            uint32_t origFileSize,
            const std::vector<uint8_t>& encryptedContent,
            uint32_t& outServerCksum
        );

        // שליחת הודעת סטטוס CRC לשרת (900, 901 או 902) וקבלת אישור 1604 עבור 900 ו-902
        void sendCrcStatus(Protocol::RequestCode code, const std::string& fileName);

        // הדפסת ההודעה "server responded with an error" בכל מקרה של שגיאה מצד השרת (לפי עמוד 5 במטלה)
        static void printServerError();

        // חילוץ שם הקובץ מתוך מסלול מלא
        static std::string extractBaseFileName(const std::string& fullPath);

        // קריאת קובץ בינארי מהדיסק לתוך וקטור בתים
        static std::vector<uint8_t> readBinaryFile(const std::string& filePath);

    private:
        Config::TransferConfig  m_transferConfig;
        Network::SocketClient   m_socket;
        Crypto::CryptoWrapper   m_crypto;
        Protocol::ClientIdArray m_clientId;
        std::string             m_clientName;
    };

} // namespace ClientApp
