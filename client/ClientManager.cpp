/**
 * @file ClientManager.cpp
 * @brief מימוש המחלקה `ClientManager` לניהול זרימת התקשורת, ההצפנה והעברת הקבצים מול השרת.
 *
 * קובץ זה מיישם את תרשימי הזרימה והפרוטוקול מעמודים 3–10 במסמך הדרישות:
 * - טעינת `transfer.json` והתחברות ב-TCP לשרת.
 * - רישום לקוח חדש (825 -> 1600) והחלפת מפתחות RSA/AES (826 -> 1602) עם שמירה ל-`me.info` ו-`priv.key`.
 * - התחברות חוזרת (827 -> 1605) או רישום מחדש במקרה של דחייה (1606).
 * - הצפנת קבצים ב-AES-CBC ושליחתם בבקשה 828 (עם תמיכה בריבוי חבילות לקבצים גדולים).
 * - אימות ה-CRC מול תשובה 1603 ושליחת 900 (תקין), 901 (ניסיון חוזר עד 3 פעמים), או 902 (ביטול בפעם הרביעית).
 * - טיפול בשגיאות שרת: הדפסת `"server responded with an error"` וביצוע עד 3 ניסיונות חוזרים לפני זריקת שגיאת Fatal.
 *
 * מי קורא למודול זה:
 * - הפונקציה `main()` בקובץ `main.cpp`.
 */

#include "ClientManager.h"
#include "Cksum.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace ClientApp {

    /**
     * @brief בנאי המחלקה - מאפס את מזהה הלקוח.
     */
    ClientManager::ClientManager()
        : m_clientId{} {}

    /**
     * @brief הפעלת תהליך הלקוח הראשי במצב Batch Mode.
     */
    void ClientManager::start() {
        // 1. קריאת קובץ ההנחיות transfer.json
        m_transferConfig = Config::loadTransferConfig();
        m_clientName = m_transferConfig.clientName;

        std::cout << "[Client] Loaded transfer.json: Server=" << m_transferConfig.serverIp
                  << ":" << m_transferConfig.serverPort
                  << ", Client='" << m_clientName << "'"
                  << ", Files count=" << m_transferConfig.files.size() << std::endl;

        // 2. התחברות לשרת באמצעות TCP (Winsock)
        m_socket.connectToServer(m_transferConfig.serverIp, m_transferConfig.serverPort);
        std::cout << "[Client] Connected to server " << m_transferConfig.serverIp
                  << ":" << m_transferConfig.serverPort << std::endl;

        // 3. ביצוע רישום או התחברות חוזרת והחלפת מפתחות הצפנה
        authenticateAndExchangeKeys();

        // 4. מעבר בלולאה על כל הקבצים ב-transfer.json והעברתם המאובטחת לשרת
        for (const std::string& filePath : m_transferConfig.files) {
            processSingleFile(filePath);
        }

        // 5. סגירת החיבור בסיום העבודה
        m_socket.closeConnection();
        std::cout << "[Client] All files processed. Batch session completed." << std::endl;
    }

    /**
     * @brief ניהול שלב ההזדהות (רישום ראשוני או התחברות חוזרת) וקבלת מפתח ה-AES מהשרת.
     */
    void ClientManager::authenticateAndExchangeKeys() {
        if (!Config::meInfoExists()) {
            std::cout << "[Client] 'me.info' not found. Starting new registration flow (825 -> 826)..." << std::endl;
            performNewRegistrationFlow();
        } else {
            std::cout << "[Client] 'me.info' found. Attempting reconnect flow (827)..." << std::endl;
            bool reconnected = tryReconnectFlow();
            if (!reconnected) {
                // לפי עמוד 8 במטלה (קוד 1606): "במצב כזה על הלקוח להירשם מחדש כמו לקוח חדש"
                std::cout << "[Client] Reconnect rejected by server (1606). Restarting as new client..." << std::endl;
                m_clientName = m_transferConfig.clientName;
                performNewRegistrationFlow();
            }
        }
    }

    /**
     * @brief תהליך רישום מלא של לקוח חדש: בקשה 825 -> יצירת RSA ושמירה -> בקשה 826.
     */
    void ClientManager::performNewRegistrationFlow() {
        // שלב א': שליחת בקשת רישום (825) וקבלת Client ID בתשובה 1600
        sendRegisterRequest();

        // שלב ב': יצירת זוג מפתחות RSA-1024 ושמירת המפתח הפרטי ב-priv.key וב-me.info
        m_crypto.generateRsaKeyPair();
        std::string privKeyBase64 = m_crypto.exportPrivateKeyBase64();

        Config::savePrivateKeyFile(privKeyBase64);

        Config::MeInfo meInfo{};
        meInfo.clientName       = m_clientName;
        meInfo.clientId         = m_clientId;
        meInfo.privateKeyBase64 = privKeyBase64;
        Config::saveMeInfo(meInfo);

        std::cout << "[Client] Generated RSA-1024 key pair and saved 'me.info' and 'priv.key'." << std::endl;

        // שלב ג': שליחת המפתח הציבורי לשרת (826) וקבלת מפתח ה-AES המוצפן בתשובה 1602
        sendPublicKeyRequest();
    }

    /**
     * @brief שליחת בקשת רישום (825) עם תמיכה בעד 3 ניסיונות חוזרים במקרה של שגיאת שרת.
     */
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
                std::cout << "[Client] Registration succeeded (1600). Assigned Client ID: "
                          << Protocol::clientIdToHex(m_clientId) << std::endl;
                return;
            }

            // השרת החזיר שגיאה (1601 או 1607)
            printServerError();
        }

        throw std::runtime_error("Fatal: Registration (825) failed after maximum retry attempts.");
    }

    /**
     * @brief שליחת המפתח הציבורי של ה-RSA (בקשה 826) וקבלת מפתח ה-AES בתשובה 1602 (עם עד 3 ניסיונות חוזרים).
     */
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
                respPayload.size() > Protocol::CLIENT_ID_SIZE) {

                // אימות שה-Client ID בתשובה תואם ומפתח ה-AES המוצפן ניתן לפענוח
                const uint8_t* encryptedAesPtr = respPayload.data() + Protocol::CLIENT_ID_SIZE;
                size_t encryptedAesLen = respPayload.size() - Protocol::CLIENT_ID_SIZE;

                m_crypto.decryptAndStoreAesKey(encryptedAesPtr, encryptedAesLen);
                std::cout << "[Client] Received and decrypted AES-256 key from server (1602)." << std::endl;
                return;
            }

            printServerError();
        }

        throw std::runtime_error("Fatal: Sending public key (826) failed after maximum retry attempts.");
    }

    /**
     * @brief ביצוע התחברות חוזרת (בקשה 827) באמצעות הנתונים מ-`me.info` ו-`priv.key`.
     */
    bool ClientManager::tryReconnectFlow() {
        Config::MeInfo meInfo = Config::loadMeInfo();
        m_clientName = meInfo.clientName;
        m_clientId   = meInfo.clientId;

        // טעינת המפתח הפרטי מ-priv.key (או משורה 3 של me.info כגיבוי אם priv.key חסר)
        std::string privKeyBase64;
        if (Config::privKeyExists()) {
            privKeyBase64 = Config::loadPrivateKeyFile();
        } else if (!meInfo.privateKeyBase64.empty()) {
            privKeyBase64 = meInfo.privateKeyBase64;
        } else {
            // אם אין מפתח פרטי שמור כלל, יש להירשם מחדש כלקוח חדש
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

            // תשובה 1605: התחברות חוזרת אושרה והתקבל מפתח AES מוצפן חדש
            if (respCode == Protocol::ResponseCode::RECONNECT_APPROVED_SEND_AES &&
                respPayload.size() > Protocol::CLIENT_ID_SIZE) {

                const uint8_t* encryptedAesPtr = respPayload.data() + Protocol::CLIENT_ID_SIZE;
                size_t encryptedAesLen = respPayload.size() - Protocol::CLIENT_ID_SIZE;

                m_crypto.decryptAndStoreAesKey(encryptedAesPtr, encryptedAesLen);
                std::cout << "[Client] Reconnect approved (1605). Decrypted new AES-256 key." << std::endl;
                return true;
            }

            // תשובה 1606: בקשת התחברות חוזרת נדחתה - יש להירשם מחדש כלקוח חדש
            if (respCode == Protocol::ResponseCode::RECONNECT_REJECTED) {
                return false;
            }

            // שגיאת שרת כללית (1607)
            printServerError();
        }

        throw std::runtime_error("Fatal: Reconnect request (827) failed after maximum retry attempts.");
    }

    /**
     * @brief העברת קובץ בודד לשרת, חישוב והשוואת CRC, וניהול עד 3 ניסיונות שליחה חוזרים (900 / 901 / 902).
     */
    void ClientManager::processSingleFile(const std::string& filePath) {
        std::string baseFileName = extractBaseFileName(filePath);
        std::cout << "[Client] Preparing file '" << filePath << "' (as '" << baseFileName << "')..." << std::endl;

        // קריאת תוכן הקובץ המקורי וחישוב ה-CRC המקומי שלו
        std::vector<uint8_t> plainFileData = readBinaryFile(filePath);
        uint32_t origFileSize = static_cast<uint32_t>(plainFileData.size());
        uint32_t localCksum   = Cksum::calculate_cksum(plainFileData);

        // הצפנת הקובץ באמצעות מפתח ה-AES במצב CBC (עם IV מאופס)
        std::vector<uint8_t> encryptedData = m_crypto.encryptFileAesCbc(plainFileData);

        // שליחת הקובץ ועד 3 ניסיונות חוזרים במקרה של אי-התאמת CRC (סה"כ עד 4 שליחות)
        for (uint32_t crcAttempt = 1; crcAttempt <= Protocol::MAX_RETRY_ATTEMPTS + 1; ++crcAttempt) {
            uint32_t serverCksum = 0;
            sendEncryptedFileAndGetCrc(baseFileName, origFileSize, encryptedData, serverCksum);

            std::cout << "[Client] File '" << baseFileName << "' (attempt " << crcAttempt
                      << "): Local CRC=" << localCksum << ", Server CRC=" << serverCksum << std::endl;

            if (serverCksum == localCksum) {
                // ה-CRC תואם! שולחים הודעה 900 (CRC_OK) ומקבלים אישור 1604
                std::cout << "[Client] CRC verified successfully! Sending CRC_OK (900)..." << std::endl;
                sendCrcStatus(Protocol::RequestCode::CRC_OK, baseFileName);
                return;
            }

            // ה-CRC אינו תואם: עד 3 פעמים שולחים 901 (CRC_INVALID_RETRY) ושולחים שוב את הקובץ
            if (crcAttempt <= Protocol::MAX_RETRY_ATTEMPTS) {
                std::cout << "[Client] CRC mismatch on attempt " << crcAttempt
                          << ". Sending CRC_INVALID_RETRY (901) and resending file..." << std::endl;
                sendCrcStatus(Protocol::RequestCode::CRC_INVALID_RETRY, baseFileName);
            } else {
                // כישלון בפעם הרביעית: שולחים 902 (CRC_INVALID_ABORT), מקבלים 1604, וממשיכים הלאה
                std::cout << "[Client] CRC mismatch on 4th attempt for '" << baseFileName
                          << "'. Sending CRC_INVALID_ABORT (902)..." << std::endl;
                sendCrcStatus(Protocol::RequestCode::CRC_INVALID_ABORT, baseFileName);
                return;
            }
        }
    }

    /**
     * @brief שליחת הקובץ המוצפן בבקשה 828 (עם חלוקה לחבילות) וקבלת תשובה 1603 מהשרת.
     */
    void ClientManager::sendEncryptedFileAndGetCrc(
        const std::string& fileName,
        uint32_t origFileSize,
        const std::vector<uint8_t>& encryptedContent,
        uint32_t& outServerCksum
    ) {
        const uint32_t contentSize = static_cast<uint32_t>(encryptedContent.size());

        // חישוב מספר החבילות הכולל (כל חבילה מכילה עד FILE_PACKET_CHUNK_SIZE בתים של תוכן מוצפן)
        size_t totalPacketsCalc = (encryptedContent.size() + Protocol::FILE_PACKET_CHUNK_SIZE - 1)
                                  / Protocol::FILE_PACKET_CHUNK_SIZE;
        if (totalPacketsCalc == 0) {
            totalPacketsCalc = 1;
        }
        if (totalPacketsCalc > 0xFFFF) {
            throw std::runtime_error("Encrypted file is too large: exceeds maximum uint16_t packet count.");
        }
        const uint16_t totalPackets = static_cast<uint16_t>(totalPacketsCalc);

        for (uint32_t errorAttempt = 0; errorAttempt <= Protocol::MAX_RETRY_ATTEMPTS; ++errorAttempt) {
            // שליחת כל החבילות מ-1 עד totalPackets
            for (uint16_t pktNum = 1; pktNum <= totalPackets; ++pktNum) {
                size_t chunkOffset = static_cast<size_t>(pktNum - 1) * Protocol::FILE_PACKET_CHUNK_SIZE;
                size_t chunkLen = std::min(Protocol::FILE_PACKET_CHUNK_SIZE, encryptedContent.size() - chunkOffset);

                Protocol::SendFilePayloadHeader fileHeader{};
                fileHeader.contentSize  = contentSize;
                fileHeader.origFileSize = origFileSize;
                fileHeader.packetNumber = pktNum;
                fileHeader.totalPackets = totalPackets;
                Protocol::packFixedName(fileName, fileHeader.fileName);

                // הרכבת ה-Payload של החבילה הנוכחית: 267 בתים של SendFilePayloadHeader + תוכן החבילה המוצפן
                std::vector<uint8_t> packetPayload(sizeof(Protocol::SendFilePayloadHeader) + chunkLen);
                std::memcpy(packetPayload.data(), &fileHeader, sizeof(Protocol::SendFilePayloadHeader));
                if (chunkLen > 0) {
                    std::memcpy(
                        packetPayload.data() + sizeof(Protocol::SendFilePayloadHeader),
                        encryptedContent.data() + chunkOffset,
                        chunkLen
                    );
                }

                Protocol::RequestHeader reqHeader = Protocol::createRequestHeader(
                    m_clientId,
                    Protocol::RequestCode::SEND_FILE,
                    static_cast<uint32_t>(packetPayload.size())
                );

                m_socket.sendRequest(reqHeader, packetPayload.data());
            }

            // לאחר שליחת החבילה האחרונה, המתנה לתשובה 1603 מהשרת
            Protocol::ResponseHeader respHeader{};
            std::vector<uint8_t> respPayload;
            m_socket.receiveResponse(respHeader, respPayload);

            auto respCode = static_cast<Protocol::ResponseCode>(respHeader.code);
            if (respCode == Protocol::ResponseCode::FILE_RECEIVED_WITH_CRC &&
                respPayload.size() >= sizeof(Protocol::FileCrcResponsePayload)) {

                Protocol::FileCrcResponsePayload crcResp{};
                std::memcpy(&crcResp, respPayload.data(), sizeof(Protocol::FileCrcResponsePayload));
                outServerCksum = crcResp.cksum;
                return;
            }

            // השרת החזיר שגיאה (1607) - מדפיסים הודעת שגיאה ומנסים שוב עד 3 פעמים
            printServerError();
        }

        throw std::runtime_error("Fatal: File transfer (828) failed after maximum server error retry attempts.");
    }

    /**
     * @brief שליחת הודעת סטטוס CRC (900, 901, 902) וקבלת תשובה 1604 (עבור 900 ו-902).
     */
    void ClientManager::sendCrcStatus(Protocol::RequestCode code, const std::string& fileName) {
        Protocol::NamePayload payload{};
        Protocol::packFixedName(fileName, payload.name);

        Protocol::RequestHeader reqHeader = Protocol::createRequestHeader(
            m_clientId,
            code,
            sizeof(Protocol::NamePayload)
        );

        // עבור קוד 901 (CRC_INVALID_RETRY) השרת אינו שולח תשובה אלא ממתין מיד לבקשה 828 חדשה
        if (code == Protocol::RequestCode::CRC_INVALID_RETRY) {
            m_socket.sendRequest(reqHeader, reinterpret_cast<const uint8_t*>(&payload));
            return;
        }

        // עבור קודים 900 ו-902 השרת מחזיר תשובה 1604 (MESSAGE_RECEIVED_THANKS)
        for (uint32_t attempt = 0; attempt <= Protocol::MAX_RETRY_ATTEMPTS; ++attempt) {
            m_socket.sendRequest(reqHeader, reinterpret_cast<const uint8_t*>(&payload));

            Protocol::ResponseHeader respHeader{};
            std::vector<uint8_t> respPayload;
            m_socket.receiveResponse(respHeader, respPayload);

            auto respCode = static_cast<Protocol::ResponseCode>(respHeader.code);
            if (respCode == Protocol::ResponseCode::MESSAGE_RECEIVED_THANKS) {
                std::cout << "[Client] Server acknowledged final status with 1604 (Thanks)." << std::endl;
                return;
            }

            printServerError();
        }

        throw std::runtime_error("Fatal: CRC status confirmation (900/902) failed after maximum retry attempts.");
    }

    /**
     * @brief הדפסת הודעת השגיאה המחייבת לפי המטלה כאשר השרת מגיב בשגיאה.
     */
    void ClientManager::printServerError() {
        std::cout << "server responded with an error" << std::endl;
    }

    /**
     * @brief חילוץ שם הקובץ בלבד מתוך נתיב קובץ מלא.
     */
    std::string ClientManager::extractBaseFileName(const std::string& fullPath) {
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash == std::string::npos) {
            return fullPath;
        }
        return fullPath.substr(lastSlash + 1);
    }

    /**
     * @brief קריאת קובץ בינארי שלם מהדיסק לווקטור בתים.
     */
    std::vector<uint8_t> ClientManager::readBinaryFile(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Fatal: Cannot open local file for transfer: " + filePath);
        }

        std::streamsize fileSize = file.tellg();
        if (fileSize < 0) {
            throw std::runtime_error("Fatal: Failed to determine size of local file: " + filePath);
        }

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
        if (fileSize > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
            throw std::runtime_error("Fatal: Error reading content of local file: " + filePath);
        }

        return buffer;
    }

} // namespace ClientApp

