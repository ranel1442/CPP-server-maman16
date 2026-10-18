/**
 * קובץ: SocketClient.h
 * מימוש שכבת התקשורת של הלקוח מעל TCP באמצעות ספריית Winsock (לפי עמוד 5 ועמוד 12 דגש 3 במטלה).
 *
 * המחלקה מנהלת את החיבור לשרת, שליחת בקשות בינאריות (כותרת + Payload) וקריאת תשובות מהשרת,
 * תוך תמיכה בהעברת וקליטת הודעות גדולות בלולאה (לפי דגש 4.ה בעמוד 11).
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Protocol.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace Network {

    // מחלקה לניהול חיבור ה-TCP של הלקוח מול השרת באמצעות Winsock2
    class SocketClient {
    public:
        SocketClient();
        ~SocketClient();

        // מניעת העתקה של אובייקט הסוקט הפעיל
        SocketClient(const SocketClient&) = delete;
        SocketClient& operator=(const SocketClient&) = delete;

        // התחברות לשרת לפי כתובת IP ופורט שנקראו מ-transfer.json
        void connectToServer(const std::string& serverIp, uint16_t serverPort);

        // סגירה מסודרת של החיבור מול השרת
        void closeConnection() noexcept;

        // בדיקה האם הסוקט מחובר
        bool isConnected() const noexcept;

        // שליחה מלאה של מערך בתים דרך ה-TCP (בלולאה עד שכל הבתים נשלחים)
        void sendAll(const uint8_t* data, size_t size);
        void sendAll(const std::vector<uint8_t>& buffer);

        // קריאה מדויקת של מספר בתים מבוקש מהסוקט (למניעת קריאה חלקית בהודעות גדולות)
        void recvExact(uint8_t* destBuffer, size_t size);
        std::vector<uint8_t> recvExact(size_t size);

        // שליחת בקשה מלאה לשרת: כותרת RequestHeader (23 בתים) ואחריה תוכן ה-Payload
        void sendRequest(const Protocol::RequestHeader& header, const uint8_t* payload = nullptr);

        // קריאת תשובה מלאה מהשרת: כותרת ResponseHeader (7 בתים) ואחריה תוכן ה-Payload לפי payloadSize
        void receiveResponse(Protocol::ResponseHeader& outHeader, std::vector<uint8_t>& outPayload);

    private:
        SOCKET m_socket;
        bool   m_wsaInitialized;
    };

} // namespace Network
