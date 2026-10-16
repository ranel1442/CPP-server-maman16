/**
 * @file SocketClient.h
 * @brief הצהרת מחלקת העטיפה (`SocketClient`) לתקשורת TCP בינארית מעל Winsock (`ws2_32.lib`).
 *
 * מחלקה זו אחראית על כל שכבת הרשת (Transport Layer) בצד הלקוח:
 * - אתחול וניקוי ספריית Winsock2 של מערכת ההפעלה חלונות (`WSAStartup` / `WSACleanup`).
 * - פתיחת סוקט TCP והתחברות לשרת לפי כתובת IP ופורט.
 * - שליחה מלאה של באפרים בינאריים (`sendAll`) בלופ עד להעברת כל הבתים (תמיכה בקבצים והודעות גדולות).
 * - קריאה מדויקת של מספר בתים מבוקש (`recvExact`) למניעת קריאה חלקית בזרם ה-TCP.
 * - שליחת בקשות פרוטוקול מלאות (כותרת 23 בתים + Payload) וקריאת תשובות השרת (כותרת 7 בתים + Payload).
 *
 * מי קורא למודול זה:
 * - מחלקת הלקוח הראשית (`Client`) לצורך ביצוע כל חילופי ההודעות מול השרת (בקשות 825–902 ותשובות 1600–1607).
 */

#pragma once

// מניעת הכללת כותרות מיושנות של winsock.h מתוך windows.h ומניעת מאקרואי min/max שמתנגשים עם ה-STL
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Protocol.h"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// הנחיה אוטומטית ללינקר של Visual Studio לקשר את ספריית Winsock2
#pragma comment(lib, "ws2_32.lib")

namespace Network {

    /**
     * @class SocketClient
     * @brief מחלקה לניהול חיבור TCP מול השרת באופן בטוח (RAII).
     *
     * שדות פרטיים מרכזיים:
     * - `m_socket`: מתאר הסוקט הפעיל (`SOCKET`) מול השרת (או `INVALID_SOCKET` כאשר מנותק).
     * - `m_wsaInitialized`: דגל בוליאני המציין האם `WSAStartup` הופעל בהצלחה במופע זה.
     */
    class SocketClient {
    public:
        /**
         * @brief בנאי המחלקה - מאתחל את ספריית Winsock2 (`WSAStartup`).
         *        זורק חריגת `std::runtime_error` אם אתחול Winsock נכשל.
         */
        SocketClient();

        /**
         * @brief מפרק המחלקה (Destructor) - סוגר את הסוקט הפתוח ומנקה את משאבי Winsock (`WSACleanup`).
         */
        ~SocketClient();

        // מניעת העתקה של אובייקט הסוקט (RAII - משאב רשת ייחודי)
        SocketClient(const SocketClient&) = delete;
        SocketClient& operator=(const SocketClient&) = delete;

        /**
         * @brief יצירת חיבור TCP לשרת המרוחק לפי כתובת IP ופורט.
         *        זורקת חריגת `std::runtime_error` אם החיבור נכשל.
         *
         * @param serverIp כתובת ה-IP של השרת (למשל `"127.0.0.1"`).
         * @param serverPort פורט ה-TCP של השרת (למשל `1369`).
         */
        void connectToServer(const std::string& serverIp, uint16_t serverPort);

        /**
         * @brief סגירת חיבור ה-TCP הנוכחי מול השרת (אם פתוח).
         */
        void closeConnection() noexcept;

        /**
         * @brief בדיקה האם קיים כרגע חיבור סוקט פתוח ותקין.
         * @return `true` אם הסוקט מחובר ופתוח, אחרת `false`.
         */
        bool isConnected() const noexcept;

        /**
         * @brief שליחה מלאה של מערך בתים דרך הסוקט (`send` בלולאה עד לשליחת כל `size` הבתים).
         *        זורקת חריגת `std::runtime_error` במקרה של ניתוק או שגיאת רשת.
         *
         * @param data מצביע לתחילת מערך הבתים לשליחה.
         * @param size מספר הבתים המדויק שיש לשלוח.
         */
        void sendAll(const uint8_t* data, size_t size);

        /**
         * @brief מעטפת נוחה לשליחה מלאה של וקטור בתים (`std::vector<uint8_t>`).
         *
         * @param buffer וקטור הבתים לשליחה.
         */
        void sendAll(const std::vector<uint8_t>& buffer);

        /**
         * @brief קריאה מדויקת של `size` בתים מתוך הסוקט לתוך באפר יעד (`recv` בלולאה).
         *        מבטיחה שלא תתרחש קריאה חלקית גם כאשר הודעה או תשובה מפוצלת על פני מספר חבילות TCP.
         *        זורקת חריגת `std::runtime_error` אם השרת סגר את החיבור לפני שהתקבלו כל הבתים או בשגיאת רשת.
         *
         * @param destBuffer מצביע לבאפר היעד שבו יישמרו הבתים שנקראו.
         * @param size מספר הבתים המדויק שיש לקרוא.
         */
        void recvExact(uint8_t* destBuffer, size_t size);

        /**
         * @brief קריאה מדויקת של `size` בתים מתוך הסוקט והחזרתם כווקטור (`std::vector<uint8_t>`).
         *
         * @param size מספר הבתים המדויק שיש לקרוא.
         * @return וקטור המכיל בדיוק `size` בתים שנקראו מהסוקט.
         */
        std::vector<uint8_t> recvExact(size_t size);

        /**
         * @brief שליחת בקשה בינארית שלמה לשרת (כותרת `RequestHeader` בת 23 בתים + תוכן ה-Payload).
         *
         * @param header כותרת הבקשה המוכנה.
         * @param payload מצביע לתוכן ה-Payload (יכול להיות `nullptr` אם `header.payloadSize == 0`).
         */
        void sendRequest(const Protocol::RequestHeader& header, const uint8_t* payload = nullptr);

        /**
         * @brief קריאת תשובה שלמה מהשרת: קוראת תחילה את כותרת התשובה (7 בתים - `ResponseHeader`),
         *        ולאחר מכן קוראת את מלוא ה-Payload לפי השדה `header.payloadSize`.
         *
         * @param outHeader משתנה פלט שיקבל את כותרת התשובה שנקראה מהשרת.
         * @param outPayload וקטור פלט שיקבל את בתי ה-Payload של התשובה.
         */
        void receiveResponse(Protocol::ResponseHeader& outHeader, std::vector<uint8_t>& outPayload);

    private:
        SOCKET m_socket;          ///< מתאר הסוקט של Winsock2
        bool   m_wsaInitialized;  ///< האם WSAStartup אותחל בהצלחה
    };

} // namespace Network

