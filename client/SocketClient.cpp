/**
 * @file SocketClient.cpp
 * @brief מימוש מחלקת העטיפה (`SocketClient`) לתקשורת TCP בינארית מעל Winsock (`ws2_32.lib`).
 *
 * קובץ זה מממש:
 * - אתחול ספריית Winsock בגרסה 2.2 (`WSAStartup`) ושחרורה ב-Destructor (`WSACleanup`).
 * - חיבור לשרת (`connectToServer`) באמצעות `getaddrinfo` ו-`connect`.
 * - שליחת באפרים מלאה (`sendAll`) בלולאה כדי להבטיח שגם הודעות וקבצים גדולים נשלחים במלואם.
 * - קריאה מדויקת (`recvExact`) בלולאה כדי להבטיח קבלת כל הבתים של הכותרת וה-Payload מעל זרם ה-TCP.
 *
 * מי קורא למודול זה:
 * - מחלקת הלקוח הראשית בעת שליחת בקשות (825–902) וקבלת תשובות השרת (1600–1607).
 */

#include "SocketClient.h"

#include <limits>
#include <stdexcept>
#include <string>

namespace Network {

    /**
     * @brief בנאי המחלקה - מאתחל את מערכת ה-Winsock2 בחלונות.
     */
    SocketClient::SocketClient()
        : m_socket(INVALID_SOCKET), m_wsaInitialized(false) {
        WSADATA wsaData{};
        int result = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed with error code: " + std::to_string(result));
        }
        m_wsaInitialized = true;
    }

    /**
     * @brief מפרק המחלקה - סוגר את הסוקט הפתוח ומנקה את Winsock2.
     */
    SocketClient::~SocketClient() {
        closeConnection();
        if (m_wsaInitialized) {
            ::WSACleanup();
            m_wsaInitialized = false;
        }
    }

    /**
     * @brief פתיחת סוקט TCP והתחברות לשרת לפי כתובת IP ופורט.
     */
    void SocketClient::connectToServer(const std::string& serverIp, uint16_t serverPort) {
        closeConnection();

        addrinfo hints{};
        hints.ai_family   = AF_INET;       // IPv4 בהתאם להגדרת השרת
        hints.ai_socktype = SOCK_STREAM;   // חיבור TCP אמין
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* addrResult = nullptr;
        const std::string portStr = std::to_string(serverPort);

        int res = ::getaddrinfo(serverIp.c_str(), portStr.c_str(), &hints, &addrResult);
        if (res != 0 || addrResult == nullptr) {
            throw std::runtime_error(
                "Failed to resolve server address (" + serverIp + ":" + portStr +
                "), Winsock error: " + std::to_string(res)
            );
        }

        m_socket = ::socket(addrResult->ai_family, addrResult->ai_socktype, addrResult->ai_protocol);
        if (m_socket == INVALID_SOCKET) {
            int err = ::WSAGetLastError();
            ::freeaddrinfo(addrResult);
            throw std::runtime_error("Failed to create TCP socket, WSA error: " + std::to_string(err));
        }

        if (::connect(m_socket, addrResult->ai_addr, static_cast<int>(addrResult->ai_addrlen)) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            ::freeaddrinfo(addrResult);
            closeConnection();
            throw std::runtime_error(
                "Failed to connect to server (" + serverIp + ":" + portStr +
                "), WSA error: " + std::to_string(err)
            );
        }

        ::freeaddrinfo(addrResult);
    }

    /**
     * @brief סגירת חיבור ה-TCP מול השרת באופן בטוח.
     */
    void SocketClient::closeConnection() noexcept {
        if (m_socket != INVALID_SOCKET) {
            ::closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }

    /**
     * @brief בדיקה האם הסוקט מחובר כרגע.
     */
    bool SocketClient::isConnected() const noexcept {
        return m_socket != INVALID_SOCKET;
    }

    /**
     * @brief שליחה מלאה של `size` בתים דרך סוקט ה-TCP בלולאה.
     */
    void SocketClient::sendAll(const uint8_t* data, size_t size) {
        if (!isConnected()) {
            throw std::runtime_error("Cannot send data: socket is not connected.");
        }
        if (size == 0) {
            return;
        }
        if (data == nullptr) {
            throw std::invalid_argument("Cannot send null data buffer with non-zero size.");
        }

        size_t totalSent = 0;
        while (totalSent < size) {
            size_t remaining = size - totalSent;
            // הגבלת גודל מקטע שליחה בודד לטווח של int ב-Winsock
            int chunkToSend = (remaining > static_cast<size_t>(std::numeric_limits<int>::max()))
                ? std::numeric_limits<int>::max()
                : static_cast<int>(remaining);

            int bytesSent = ::send(
                m_socket,
                reinterpret_cast<const char*>(data + totalSent),
                chunkToSend,
                0
            );

            if (bytesSent == SOCKET_ERROR || bytesSent <= 0) {
                int err = ::WSAGetLastError();
                throw std::runtime_error("Socket send failed, WSA error: " + std::to_string(err));
            }

            totalSent += static_cast<size_t>(bytesSent);
        }
    }

    /**
     * @brief מעטפת לשליחת וקטור בתים שלם (`std::vector<uint8_t>`).
     */
    void SocketClient::sendAll(const std::vector<uint8_t>& buffer) {
        sendAll(buffer.data(), buffer.size());
    }

    /**
     * @brief קריאה מדויקת של `size` בתים מתוך סוקט ה-TCP לתוך `destBuffer`.
     */
    void SocketClient::recvExact(uint8_t* destBuffer, size_t size) {
        if (!isConnected()) {
            throw std::runtime_error("Cannot receive data: socket is not connected.");
        }
        if (size == 0) {
            return;
        }
        if (destBuffer == nullptr) {
            throw std::invalid_argument("Destination buffer cannot be null when receiving data.");
        }

        size_t totalReceived = 0;
        while (totalReceived < size) {
            size_t remaining = size - totalReceived;
            int chunkToRead = (remaining > static_cast<size_t>(std::numeric_limits<int>::max()))
                ? std::numeric_limits<int>::max()
                : static_cast<int>(remaining);

            int bytesRead = ::recv(
                m_socket,
                reinterpret_cast<char*>(destBuffer + totalReceived),
                chunkToRead,
                0
            );

            if (bytesRead == 0) {
                throw std::runtime_error("Server closed the TCP connection unexpectedly before all bytes were received.");
            }
            if (bytesRead == SOCKET_ERROR || bytesRead < 0) {
                int err = ::WSAGetLastError();
                throw std::runtime_error("Socket recv failed, WSA error: " + std::to_string(err));
            }

            totalReceived += static_cast<size_t>(bytesRead);
        }
    }

    /**
     * @brief קריאה מדויקת של `size` בתים והחזרתם כ-`std::vector<uint8_t>`.
     */
    std::vector<uint8_t> SocketClient::recvExact(size_t size) {
        std::vector<uint8_t> buffer(size);
        if (size > 0) {
            recvExact(buffer.data(), size);
        }
        return buffer;
    }

    /**
     * @brief שליחת בקשה בינארית שלמה לשרת (כותרת 23 בתים + Payload).
     */
    void SocketClient::sendRequest(const Protocol::RequestHeader& header, const uint8_t* payload) {
        // שליחת כותרת הבקשה (23 בתים בפורמט Little-Endian)
        sendAll(reinterpret_cast<const uint8_t*>(&header), sizeof(Protocol::RequestHeader));

        // שליחת ה-Payload אם קיים
        if (header.payloadSize > 0) {
            if (payload == nullptr) {
                throw std::invalid_argument("Payload pointer is null although header.payloadSize > 0.");
            }
            sendAll(payload, header.payloadSize);
        }
    }

    /**
     * @brief קריאת תשובה בינארית שלמה מהשרת (כותרת 7 בתים + Payload לפי השדה payloadSize).
     */
    void SocketClient::receiveResponse(Protocol::ResponseHeader& outHeader, std::vector<uint8_t>& outPayload) {
        // קריאת כותרת התשובה מהשרת (7 בתים)
        recvExact(reinterpret_cast<uint8_t*>(&outHeader), sizeof(Protocol::ResponseHeader));

        // קריאת תוכן התשובה (Payload) בהתאם לגודל שצוין בכותרת
        outPayload.clear();
        if (outHeader.payloadSize > 0) {
            outPayload.resize(outHeader.payloadSize);
            recvExact(outPayload.data(), outHeader.payloadSize);
        }
    }

} // namespace Network

