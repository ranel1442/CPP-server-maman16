/**
 * קובץ: SocketClient.cpp
 * מימוש תקשורת ה-TCP של הלקוח באמצעות Winsock2 (לפי עמוד 5 ועמוד 12 דגש 3 במטלה).
 */

#include "SocketClient.h"

#include <limits>
#include <stdexcept>
#include <string>

namespace Network {

    // אתחול ספריית Winsock2 בעת יצירת אובייקט התקשורת
    SocketClient::SocketClient()
        : m_socket(INVALID_SOCKET), m_wsaInitialized(false) {
        WSADATA wsaData{};
        int res = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (res != 0) {
            throw std::runtime_error("WSAStartup failed with error code: " + std::to_string(res));
        }
        m_wsaInitialized = true;
    }

    // סגירת הסוקט ושחרור משאבי Winsock2 בסיום חיי האובייקט
    SocketClient::~SocketClient() {
        closeConnection();
        if (m_wsaInitialized) {
            ::WSACleanup();
            m_wsaInitialized = false;
        }
    }

    // מימוש יצירת הקשר מיוזמת הלקוח מול השרת מעל TCP (לפי עמוד 1 ועמוד 5 במטלה)
    void SocketClient::connectToServer(const std::string& serverIp, uint16_t serverPort) {
        closeConnection();

        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* result = nullptr;
        std::string portStr = std::to_string(serverPort);

        int res = ::getaddrinfo(serverIp.c_str(), portStr.c_str(), &hints, &result);
        if (res != 0 || result == nullptr) {
            throw std::runtime_error("Failed to resolve server address: " + serverIp + ":" + portStr);
        }

        m_socket = ::socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (m_socket == INVALID_SOCKET) {
            int err = ::WSAGetLastError();
            ::freeaddrinfo(result);
            throw std::runtime_error("Failed to create TCP socket, WSA error: " + std::to_string(err));
        }

        if (::connect(m_socket, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR) {
            int err = ::WSAGetLastError();
            ::freeaddrinfo(result);
            closeConnection();
            throw std::runtime_error(
                "Could not connect to server " + serverIp + ":" + portStr + " (WSA error " + std::to_string(err) + ")"
            );
        }

        ::freeaddrinfo(result);
    }

    void SocketClient::closeConnection() noexcept {
        if (m_socket != INVALID_SOCKET) {
            ::closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }

    bool SocketClient::isConnected() const noexcept {
        return m_socket != INVALID_SOCKET;
    }

    // מימוש שליחת כמות מידע דינמית/גדולה בלולאה עד לשליחת כל הבתים (לפי דגש 4.ה בעמוד 11 במטלה)
    void SocketClient::sendAll(const uint8_t* data, size_t size) {
        if (!isConnected()) {
            throw std::runtime_error("Socket is not connected.");
        }
        if (size == 0) {
            return;
        }

        size_t totalSent = 0;
        while (totalSent < size) {
            size_t remaining = size - totalSent;
            int chunk = (remaining > static_cast<size_t>(std::numeric_limits<int>::max()))
                ? std::numeric_limits<int>::max()
                : static_cast<int>(remaining);

            int sent = ::send(m_socket, reinterpret_cast<const char*>(data + totalSent), chunk, 0);
            if (sent == SOCKET_ERROR || sent <= 0) {
                int err = ::WSAGetLastError();
                throw std::runtime_error("Socket send error (WSA " + std::to_string(err) + ")");
            }
            totalSent += static_cast<size_t>(sent);
        }
    }

    void SocketClient::sendAll(const std::vector<uint8_t>& buffer) {
        sendAll(buffer.data(), buffer.size());
    }

    // מימוש קליטת כמות מידע מדויקת בלולאה מהסוקט (לפי דגש 4.ה בעמוד 11 במטלה)
    void SocketClient::recvExact(uint8_t* destBuffer, size_t size) {
        if (!isConnected()) {
            throw std::runtime_error("Socket is not connected.");
        }
        if (size == 0) {
            return;
        }

        size_t totalRead = 0;
        while (totalRead < size) {
            size_t remaining = size - totalRead;
            int chunk = (remaining > static_cast<size_t>(std::numeric_limits<int>::max()))
                ? std::numeric_limits<int>::max()
                : static_cast<int>(remaining);

            int bytesRead = ::recv(m_socket, reinterpret_cast<char*>(destBuffer + totalRead), chunk, 0);
            if (bytesRead == 0) {
                throw std::runtime_error("Server closed the connection unexpectedly.");
            }
            if (bytesRead == SOCKET_ERROR || bytesRead < 0) {
                int err = ::WSAGetLastError();
                throw std::runtime_error("Socket recv error (WSA " + std::to_string(err) + ")");
            }
            totalRead += static_cast<size_t>(bytesRead);
        }
    }

    std::vector<uint8_t> SocketClient::recvExact(size_t size) {
        std::vector<uint8_t> buffer(size);
        if (size > 0) {
            recvExact(buffer.data(), size);
        }
        return buffer;
    }

    // שליחת בקשה לשרת לפי מבנה הבקשה בעמוד 6 במטלה (Header בן 23 בתים ואחריו ה-Payload)
    void SocketClient::sendRequest(const Protocol::RequestHeader& header, const uint8_t* payload) {
        sendAll(reinterpret_cast<const uint8_t*>(&header), sizeof(Protocol::RequestHeader));
        if (header.payloadSize > 0 && payload != nullptr) {
            sendAll(payload, header.payloadSize);
        }
    }

    // קריאת תשובה מהשרת לפי מבנה התשובה בעמוד 7 במטלה (Header בן 7 בתים ואחריו ה-Payload לפי payloadSize)
    void SocketClient::receiveResponse(Protocol::ResponseHeader& outHeader, std::vector<uint8_t>& outPayload) {
        recvExact(reinterpret_cast<uint8_t*>(&outHeader), sizeof(Protocol::ResponseHeader));

        outPayload.clear();
        if (outHeader.payloadSize > 0) {
            outPayload.resize(outHeader.payloadSize);
            recvExact(outPayload.data(), outHeader.payloadSize);
        }
    }

} // namespace Network
