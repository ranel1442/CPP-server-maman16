/**
 * קובץ: ClientManager.cpp
 * מימוש סדר הפעולות של הלקוח (Batch Mode) בהתאם לעמודים 3-10 בחוברת המטלה:
 * 1. קריאת הקובץ transfer.json והתחברות לשרת.
 * 2. רישום לקוח חדש (825 -> 1600, יצירת RSA ושמירה ל-me.info ו-priv.key, שליחת מפתח ציבורי 826 -> 1602)
 *    או התחברות חוזרת במידה ו-me.info כבר קיים (827 -> 1605, או רישום מחדש אם התקבל 1606).
 * 3. הצפנת כל קובץ ברשימה באמצעות מפתח ה-AES ושליחתו בבקשה 828 (בחבילות).
 * 4. השוואת ה-CRC המקומי ל-CRC מהשרת (תשובה 1603) ושליחת 900 (תקין), 901 (ניסיון חוזר עד 3 פעמים) או 902 (ביטול בפעם ה-4).
 */

#include "ClientManager.h"
#include "Cksum.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace ClientApp {

    ClientManager::ClientManager()
        : m_clientId{} {}

    // מימוש סדר הפעולות הקבוע של הלקוח (Batch Mode - עמוד 4 סעיף ב')
    void ClientManager::start() {
        m_transferConfig = Config::loadTransferConfig();
        m_clientName = m_transferConfig.clientName;

        std::cout << "[Client] Loaded transfer.json (Server " << m_transferConfig.serverIp
                  << ":" << m_transferConfig.serverPort
                  << ", Client '" << m_clientName << "')." << std::endl;

        m_socket.connectToServer(m_transferConfig.serverIp, m_transferConfig.serverPort);
        std::cout << "[Client] Connected to server." << std::endl;

        authenticateAndExchangeKeys();

        for (const std::string& filePath : m_transferConfig.files) {
            processSingleFile(filePath);
        }

        m_socket.closeConnection();
        std::cout << "[Client] Finished transferring all files. Disconnected." << std::endl;
    }

    // מימוש הבחירה בין רישום להתחברות חוזרת לפי קיום הקובץ me.info (עמוד 5 סעיפים 1-3 ועמוד 10)
    void ClientManager::authenticateAndExchangeKeys() {
        if (!Config::meInfoExists()) {
            std::cout << "[Client] 'me.info' does not exist. Registering as a new client..." << std::endl;
            performNewRegistrationFlow();
        } else {
            std::cout << "[Client] 'me.info' found. Sending reconnect request (827)..." << std::endl;
            if (!tryReconnectFlow()) {
                // מימוש דרישת קוד 1606 בעמוד 8 ותהליך ההתאוששות בעמוד 10:
                // אם בקשת ההתחברות החוזרת נדחתה, על הלקוח להירשם מחדש כמו לקוח חדש.
                std::cout << "[Client] Reconnect rejected (1606). Registering as a new client..." << std::endl;
                m_clientName = m_transferConfig.clientName;
                performNewRegistrationFlow();
            }
        }
    }

    // מימוש תהליך הרישום והחלפת המפתחות ללקוח חדש (לפי תרשים הזרימה בעמוד 3 ועמוד 5 במטלה)
    void ClientManager::performNewRegistrationFlow() {
        sendRegisterRequest();

        // יצירת זוג מפתחות RSA (ציבורי ופרטי) ושמירת הפרטי ב-priv.key וב-me.info (עמודים 4-5)
        m_crypto.generateRsaKeyPair();
        std::string privKeyBase64 = m_crypto.exportPrivateKeyBase64();

        Config::savePrivateKeyFile(privKeyBase64);

        Config::MeInfo meInfo{};
        meInfo.clientName       = m_clientName;
        meInfo.clientId         = m_clientId;
        meInfo.privateKeyBase64 = privKeyBase64;
        Config::saveMeInfo(meInfo);

        std::cout << "[Client] Saved client details and RSA private key to 'me.info' and 'priv.key'." << std::endl;

        sendPublicKeyRequest();
    }

    // מימוש בקשה 825 (רישום) וקבלת תשובה 1600, כולל עד 3 ניסיונות חוזרים במקרה של שגיאת שרת (עמודים 5-8)
    void ClientManager::sendRegisterRequest() {
        Protocol::NamePayload payload{};
        Protocol::packFixedName(m_clientName, payload.name);

        Protocol::ClientIdArray emptyId{};
        Protocol::RequestHeader reqHeader = Protocol::createRequestHeader(
            emptyId,
            Protocol::RequestCode::REGISTER,
            sizeof(Protocol::NamePayload)
        );

        for (uint32_t attempt = 0; attempt <= Protocol::MAX_RETRY_ATTEMPTS; ++attempt) {
            m_socket.sendRequest(reqHeader, reinterpret_cast<const uint8_t*>(&payload));

            Protocol::ResponseHeader respHeader{};
            std::vector<uint8_t> respPayload;
            m_socket.receiveResponse(respHeader, respPayload);

            auto respCode = static_cast<Protocol::ResponseCode>(respHeader.code);
            if (respCode == Protocol::ResponseCode::REGISTER_SUCCESS &&
                respPayload.size() == Protocol::CLIENT_ID_SIZE) {
                std::memcpy(m_clientId.data(), respPayload.data(), Protocol::CLIENT_ID_SIZE);
                std::cout << "[Client] Registered successfully (1600). ID: "
                          << Protocol::clientIdToHex(m_clientId) << std::endl;
                return;
            }

            printServerError();
        }

        throw std::runtime_error("Fatal: Registration (825) failed after 3 retries.");
    }

    // מימוש בקשה 826 (שליחת מפתח ציבורי) וקבלת מפתח AES מוצפן בתשובה 1602 (עמודים 5-8)
    void ClientManager::sendPublicKeyRequest() {
        Protocol::PublicKeyPayload payload{};
        Protocol::packFixedName(m_clientName, payload.name);

        Crypto::PublicKeyArray pubKeyBytes = m_crypto.getPublicKeyBytes();
        std::memcpy(payload.publicKey, pubKeyBytes.data(), Protocol::PUBLIC_KEY_SIZE);

        Protocol::RequestHeader reqHeader = Protocol::createRequestHeader(
            m_clientId,
            Protocol::RequestCode::SEND_PUBLIC_KEY,
            sizeof(Protocol::PublicKeyPayload)
        );

        for (uint32_t attempt = 0; attempt <= Protocol::MAX_RETRY_ATTEMPTS; ++attempt) {
            m_socket.sendRequest(reqHeader, reinterpret_cast<const uint8_t*>(&payload));

            Protocol::ResponseHeader respHeader{};
            std::vector<uint8_t> respPayload;
            m_socket.receiveResponse(respHeader, respPayload);

            auto respCode = static_cast<Protocol::ResponseCode>(respHeader.code);
            if (respCode == Protocol::ResponseCode::PUBLIC_KEY_RECEIVED_AES &&
                respPayload.size() > Protocol::CLIENT_ID_SIZE &&
                std::memcmp(respPayload.data(), m_clientId.data(), Protocol::CLIENT_ID_SIZE) == 0) {

                const uint8_t* encryptedAes = respPayload.data() + Protocol::CLIENT_ID_SIZE;
                size_t encryptedAesLen = respPayload.size() - Protocol::CLIENT_ID_SIZE;

                m_crypto.decryptAndStoreAesKey(encryptedAes, encryptedAesLen);
                std::cout << "[Client] Received and decrypted AES key (1602)." << std::endl;
                return;
            }

            printServerError();
        }

        throw std::runtime_error("Fatal: Public key exchange (826) failed after 3 retries.");
    }

    // מימוש בקשה 827 (התחברות חוזרת) בעזרת המפתח הקודם מהקובץ priv.key (לפי עמוד 5 סעיף 3 ועמודים 7-8)
    bool ClientManager::tryReconnectFlow() {
        Config::MeInfo meInfo = Config::loadMeInfo();
        m_clientName = meInfo.clientName;
        m_clientId   = meInfo.clientId;

        std::string privKeyBase64;
        if (Config::privKeyExists()) {
            privKeyBase64 = Config::loadPrivateKeyFile();
        } else if (!meInfo.privateKeyBase64.empty()) {
            privKeyBase64 = meInfo.privateKeyBase64;
        } else {
            return false;
        }

        m_crypto.loadPrivateKeyBase64(privKeyBase64);

        Protocol::NamePayload payload{};
        Protocol::packFixedName(m_clientName, payload.name);

        Protocol::RequestHeader reqHeader = Protocol::createRequestHeader(
            m_clientId,
            Protocol::RequestCode::RECONNECT,
            sizeof(Protocol::NamePayload)
        );

        for (uint32_t attempt = 0; attempt <= Protocol::MAX_RETRY_ATTEMPTS; ++attempt) {
            m_socket.sendRequest(reqHeader, reinterpret_cast<const uint8_t*>(&payload));

            Protocol::ResponseHeader respHeader{};
            std::vector<uint8_t> respPayload;
            m_socket.receiveResponse(respHeader, respPayload);

            auto respCode = static_cast<Protocol::ResponseCode>(respHeader.code);
            if (respCode == Protocol::ResponseCode::RECONNECT_APPROVED_SEND_AES &&
                respPayload.size() > Protocol::CLIENT_ID_SIZE &&
                std::memcmp(respPayload.data(), m_clientId.data(), Protocol::CLIENT_ID_SIZE) == 0) {

                const uint8_t* encryptedAes = respPayload.data() + Protocol::CLIENT_ID_SIZE;
                size_t encryptedAesLen = respPayload.size() - Protocol::CLIENT_ID_SIZE;

                m_crypto.decryptAndStoreAesKey(encryptedAes, encryptedAesLen);
                std::cout << "[Client] Reconnect approved (1605). Decrypted new AES key." << std::endl;
                return true;
            }

            if (respCode == Protocol::ResponseCode::RECONNECT_REJECTED) {
                return false;
            }

            printServerError();
        }

        throw std::runtime_error("Fatal: Reconnect (827) failed after 3 retries.");
    }

    // מימוש העברת קובץ בודד ואימות השליחה בעזרת CRC (לפי תרשים הזרימה בעמוד 3 ועמודים 5 ו-7):
    // אם ה-CRC תואם נשלחת הודעה 900; אם לא תואם מנסים לשלוח שוב (הודעה 901 + בקשה 828) עד 3 פעמים,
    // ובכישלון בפעם הרביעית שולחים הודעת ביטול 902.
    void ClientManager::processSingleFile(const std::string& filePath) {
        std::string fileName = extractBaseFileName(filePath);
        std::vector<uint8_t> plainData = readBinaryFile(filePath);

        uint32_t origFileSize = static_cast<uint32_t>(plainData.size());
        uint32_t localCrc     = Cksum::calculate_cksum(plainData);

        std::vector<uint8_t> encryptedData = m_crypto.encryptFileAesCbc(plainData);

        for (uint32_t crcTry = 1; crcTry <= Protocol::MAX_RETRY_ATTEMPTS + 1; ++crcTry) {
            uint32_t serverCrc = 0;
            sendEncryptedFileAndGetCrc(fileName, origFileSize, encryptedData, serverCrc);

            std::cout << "[Client] File '" << fileName << "' (try " << crcTry
                      << "): local CRC=" << localCrc << ", server CRC=" << serverCrc << std::endl;

            if (serverCrc == localCrc) {
                std::cout << "[Client] CRC matched! Sending 900 (CRC_OK)." << std::endl;
                sendCrcStatus(Protocol::RequestCode::CRC_OK, fileName);
                return;
            }

            if (crcTry <= Protocol::MAX_RETRY_ATTEMPTS) {
                std::cout << "[Client] CRC mismatch. Sending 901 (retry " << crcTry << "/3)..." << std::endl;
                sendCrcStatus(Protocol::RequestCode::CRC_INVALID_RETRY, fileName);
            } else {
                std::cout << "[Client] CRC mismatch on 4th time. Sending 902 (Abort)." << std::endl;
                sendCrcStatus(Protocol::RequestCode::CRC_INVALID_ABORT, fileName);
                return;
            }
        }
    }

    // מימוש שליחת קובץ מוצפן בבקשה 828 בחבילות וקבלת תשובה 1603 עם ה-CRC מהשרת (לפי עמודים 7-8 במטלה)
    void ClientManager::sendEncryptedFileAndGetCrc(
        const std::string& fileName,
        uint32_t origFileSize,
        const std::vector<uint8_t>& encryptedContent,
        uint32_t& outServerCksum
    ) {
        uint32_t contentSize = static_cast<uint32_t>(encryptedContent.size());

        size_t numPackets = (encryptedContent.size() + Protocol::FILE_PACKET_CHUNK_SIZE - 1)
                            / Protocol::FILE_PACKET_CHUNK_SIZE;
        if (numPackets == 0) {
            numPackets = 1;
        }
        if (numPackets > 0xFFFF) {
            throw std::runtime_error("Fatal: File is too large for 16-bit totalPackets field.");
        }
        uint16_t totalPackets = static_cast<uint16_t>(numPackets);

        for (uint32_t attempt = 0; attempt <= Protocol::MAX_RETRY_ATTEMPTS; ++attempt) {
            for (uint16_t pktNum = 1; pktNum <= totalPackets; ++pktNum) {
                size_t offset = static_cast<size_t>(pktNum - 1) * Protocol::FILE_PACKET_CHUNK_SIZE;
                size_t chunkLen = std::min(Protocol::FILE_PACKET_CHUNK_SIZE, encryptedContent.size() - offset);

                Protocol::SendFilePayloadHeader fileHeader{};
                fileHeader.contentSize  = contentSize;
                fileHeader.origFileSize = origFileSize;
                fileHeader.packetNumber = pktNum;
                fileHeader.totalPackets = totalPackets;
                Protocol::packFixedName(fileName, fileHeader.fileName);

                std::vector<uint8_t> payload(sizeof(Protocol::SendFilePayloadHeader) + chunkLen);
                std::memcpy(payload.data(), &fileHeader, sizeof(Protocol::SendFilePayloadHeader));
                if (chunkLen > 0) {
                    std::memcpy(
                        payload.data() + sizeof(Protocol::SendFilePayloadHeader),
                        encryptedContent.data() + offset,
                        chunkLen
                    );
                }

                Protocol::RequestHeader reqHeader = Protocol::createRequestHeader(
                    m_clientId,
                    Protocol::RequestCode::SEND_FILE,
                    static_cast<uint32_t>(payload.size())
                );

                m_socket.sendRequest(reqHeader, payload.data());
            }

            Protocol::ResponseHeader respHeader{};
            std::vector<uint8_t> respPayload;
            m_socket.receiveResponse(respHeader, respPayload);

            auto respCode = static_cast<Protocol::ResponseCode>(respHeader.code);
            if (respCode == Protocol::ResponseCode::FILE_RECEIVED_WITH_CRC &&
                respPayload.size() == sizeof(Protocol::FileCrcResponsePayload)) {

                Protocol::FileCrcResponsePayload crcResp{};
                std::memcpy(&crcResp, respPayload.data(), sizeof(Protocol::FileCrcResponsePayload));
                outServerCksum = crcResp.cksum;
                return;
            }

            printServerError();
        }

        throw std::runtime_error("Fatal: Sending file (828) failed after 3 server error retries.");
    }

    // מימוש שליחת הודעות 900, 901 ו-902 וקבלת תשובה 1604 (עבור 900 ו-902, לפי עמודים 7-8 במטלה)
    void ClientManager::sendCrcStatus(Protocol::RequestCode code, const std::string& fileName) {
        Protocol::NamePayload payload{};
        Protocol::packFixedName(fileName, payload.name);

        Protocol::RequestHeader reqHeader = Protocol::createRequestHeader(
            m_clientId,
            code,
            sizeof(Protocol::NamePayload)
        );

        // בבקשה 901 הלקוח שולח מיד שוב בקשה 828 ללא המתנה לתשובה מהשרת
        if (code == Protocol::RequestCode::CRC_INVALID_RETRY) {
            m_socket.sendRequest(reqHeader, reinterpret_cast<const uint8_t*>(&payload));
            return;
        }

        for (uint32_t attempt = 0; attempt <= Protocol::MAX_RETRY_ATTEMPTS; ++attempt) {
            m_socket.sendRequest(reqHeader, reinterpret_cast<const uint8_t*>(&payload));

            Protocol::ResponseHeader respHeader{};
            std::vector<uint8_t> respPayload;
            m_socket.receiveResponse(respHeader, respPayload);

            auto respCode = static_cast<Protocol::ResponseCode>(respHeader.code);
            if (respCode == Protocol::ResponseCode::MESSAGE_RECEIVED_THANKS) {
                std::cout << "[Client] Server confirmed message with 1604 (Thanks)." << std::endl;
                return;
            }

            printServerError();
        }

        throw std::runtime_error("Fatal: Finalizing CRC status (900/902) failed after 3 retries.");
    }

    // מימוש דרישת עמוד 5 ("שגיאה מצד השרת"): הדפסת ההודעה המדויקת למסך בכל מקרה של שגיאה
    void ClientManager::printServerError() {
        std::cout << "server responded with an error" << std::endl;
    }

    std::string ClientManager::extractBaseFileName(const std::string& fullPath) {
        size_t pos = fullPath.find_last_of("\\/");
        return (pos == std::string::npos) ? fullPath : fullPath.substr(pos + 1);
    }

    std::vector<uint8_t> ClientManager::readBinaryFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Fatal: Cannot open file for transfer: " + filePath);
        }

        std::streamsize size = file.tellg();
        if (size < 0) {
            throw std::runtime_error("Fatal: Cannot read size of file: " + filePath);
        }

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (size > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            throw std::runtime_error("Fatal: Failed reading content of file: " + filePath);
        }

        return buffer;
    }

} // namespace ClientApp
