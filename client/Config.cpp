/**
 * קובץ: Config.cpp
 * מימוש הקריאה והכתיבה של קובצי הלקוח: transfer.json, me.info ו-priv.key (לפי עמודים 4-5 במטלה).
 *
 * הערה לגבי transfer.json:
 * בדוגמה שבעמוד 4 במטלה, נתיבי הקבצים תחת "files" כתובים עם לוכסן יחיד של חלונות, למשל:
 * "c:\doc\file02.docx". לכן פונקציית חילוץ המחרוזות כאן בנויה כך שתשמור על הלוכסן כפי שהוא
 * ולא תיכשל על תווי escape של JSON רגיל.
 * כמו כן, כדי לעמוד בדרישת עמוד 11 סעיף 5.א (ללא תלויות בספריות חיצוניות מלבד הספריות הנדרשות),
 * הפענוח ממומש ישירות ב-C++ סטנדרטי (STL).
 */

#include "Config.h"

#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace Config {

    namespace {

        // הסרת רווחים ותווי ירידת שורה מתחילת ומסוף מחרוזת
        std::string trim(const std::string& str) {
            size_t first = str.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) {
                return "";
            }
            size_t last = str.find_last_not_of(" \t\r\n");
            return str.substr(first, (last - first + 1));
        }

        // קריאת כל תוכן הקובץ למחרוזת אחת
        std::string readEntireFile(const std::string& filePath) {
            std::ifstream file(filePath, std::ios::in | std::ios::binary);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot open file: " + filePath);
            }
            std::ostringstream ss;
            ss << file.rdbuf();
            return ss.str();
        }

        // דילוג על רווחים וירידות שורה בטקסט
        void skipWhitespace(const std::string& text, size_t& pos) {
            while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
                ++pos;
            }
        }

        // קריאת מחרוזת מתוך מירכאות בקובץ ה-JSON (כולל תמיכה בנתיבי Windows עם לוכסן יחיד או כפול לפי הדוגמה בעמוד 4)
        std::string parseQuotedString(const std::string& text, size_t& pos) {
            skipWhitespace(text, pos);
            if (pos >= text.size() || text[pos] != '"') {
                throw std::runtime_error("Expected '\"' in transfer.json.");
            }
            ++pos;

            std::string result;
            while (pos < text.size()) {
                char ch = text[pos++];
                if (ch == '"') {
                    return result;
                }
                if (ch == '\\' && pos < text.size()) {
                    char nextCh = text[pos];
                    if (nextCh == '"' || nextCh == '\\' || nextCh == '/') {
                        result.push_back(nextCh);
                        ++pos;
                    } else {
                        result.push_back('\\');
                    }
                } else {
                    result.push_back(ch);
                }
            }
            throw std::runtime_error("Unterminated string in transfer.json.");
        }

        // חיפוש שדה לפי שם בקובץ ה-JSON והחזרת האינדקס שאחרי התו ':'
        size_t findFieldValuePos(const std::string& jsonText, const std::string& key, size_t startPos = 0) {
            std::string token = "\"" + key + "\"";
            size_t keyPos = jsonText.find(token, startPos);
            if (keyPos == std::string::npos) {
                throw std::runtime_error("Missing field '" + key + "' in transfer.json.");
            }
            size_t colonPos = jsonText.find(':', keyPos + token.size());
            if (colonPos == std::string::npos) {
                throw std::runtime_error("Missing ':' after field '" + key + "' in transfer.json.");
            }
            return colonPos + 1;
        }

    } // namespace

    // מימוש קריאת קובץ ההנחיות transfer.json (לפי המבנה המוגדר בעמוד 4 במטלה)
    TransferConfig loadTransferConfig(const std::string& filePath) {
        std::string content = readEntireFile(filePath);
        TransferConfig config{};

        size_t serverPos = findFieldValuePos(content, "server");
        skipWhitespace(content, serverPos);
        if (serverPos >= content.size() || content[serverPos] != '{') {
            throw std::runtime_error("Invalid 'server' section in transfer.json.");
        }

        // קריאת כתובת ה-IP של השרת
        size_t ipPos = findFieldValuePos(content, "ip", serverPos);
        config.serverIp = trim(parseQuotedString(content, ipPos));
        if (config.serverIp.empty()) {
            throw std::runtime_error("Server IP is empty in transfer.json.");
        }

        // קריאת פורט התקשורת (port)
        size_t portPos = findFieldValuePos(content, "port", serverPos);
        skipWhitespace(content, portPos);
        unsigned long portVal = 0;
        if (portPos < content.size() && content[portPos] == '"') {
            portVal = std::stoul(parseQuotedString(content, portPos));
        } else {
            size_t endNum = portPos;
            while (endNum < content.size() && std::isdigit(static_cast<unsigned char>(content[endNum]))) {
                ++endNum;
            }
            if (endNum == portPos) {
                throw std::runtime_error("Invalid port number in transfer.json.");
            }
            portVal = std::stoul(content.substr(portPos, endNum - portPos));
        }

        if (portVal == 0 || portVal > 65535) {
            throw std::runtime_error("Port number out of range (1-65535) in transfer.json.");
        }
        config.serverPort = static_cast<uint16_t>(portVal);

        // קריאת שם הלקוח (client - מחרוזת עד 100 תווים לפי עמוד 4 במטלה)
        size_t clientPos = findFieldValuePos(content, "client", serverPos);
        config.clientName = parseQuotedString(content, clientPos);
        if (config.clientName.empty() || config.clientName.size() > Protocol::MAX_CONFIG_CLIENT_NAME) {
            throw std::runtime_error("Client name in transfer.json must be 1..100 characters.");
        }

        // קריאת רשימת הקבצים להעברה (files)
        size_t filesPos = findFieldValuePos(content, "files");
        skipWhitespace(content, filesPos);
        if (filesPos >= content.size() || content[filesPos] != '[') {
            throw std::runtime_error("Expected '[' for 'files' list in transfer.json.");
        }
        ++filesPos;

        while (filesPos < content.size()) {
            skipWhitespace(content, filesPos);
            if (filesPos < content.size() && content[filesPos] == ']') {
                break;
            }

            std::string fileEntry = parseQuotedString(content, filesPos);
            if (!fileEntry.empty()) {
                config.files.push_back(fileEntry);
            }

            skipWhitespace(content, filesPos);
            if (filesPos < content.size() && content[filesPos] == ',') {
                ++filesPos;
            } else if (filesPos < content.size() && content[filesPos] == ']') {
                break;
            } else {
                throw std::runtime_error("Invalid format in 'files' array of transfer.json.");
            }
        }

        return config;
    }

    // בדיקת קיום הקובץ me.info (לפי עמוד 5 סעיפים 1 ו-3)
    bool meInfoExists(const std::string& filePath) {
        std::ifstream file(filePath);
        return file.good();
    }

    // מימוש קריאת הקובץ me.info לפי המבנה בעמוד 4 במטלה:
    // שורה 1: שם, שורה 2: מזהה ייחודי ב-ASCII hex, שורה 3 והלאה: מפתח פרטי בפורמט Base64
    MeInfo loadMeInfo(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open me.info: " + filePath);
        }

        MeInfo info{};
        std::string line1;
        std::string line2;

        if (!std::getline(file, line1)) {
            throw std::runtime_error("me.info is missing client name (line 1).");
        }
        info.clientName = trim(line1);
        if (info.clientName.empty() || info.clientName.size() >= Protocol::NAME_FIELD_SIZE) {
            throw std::runtime_error("Invalid client name in me.info.");
        }

        if (!std::getline(file, line2)) {
            throw std::runtime_error("me.info is missing UUID hex string (line 2).");
        }
        info.clientId = Protocol::hexToClientId(trim(line2));

        std::ostringstream keyBuffer;
        std::string keyLine;
        while (std::getline(file, keyLine)) {
            std::string cleanLine = trim(keyLine);
            if (!cleanLine.empty()) {
                keyBuffer << cleanLine;
            }
        }
        info.privateKeyBase64 = keyBuffer.str();

        return info;
    }

    // מימוש שמירת הנתונים לקובץ me.info (לפי עמוד 4 ועמוד 5 סעיף 2 במטלה)
    void saveMeInfo(const MeInfo& info, const std::string& filePath) {
        std::ofstream file(filePath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open me.info for writing: " + filePath);
        }

        file << info.clientName << "\n";
        file << Protocol::clientIdToHex(info.clientId) << "\n";
        file << info.privateKeyBase64 << "\n";
    }

    bool privKeyExists(const std::string& filePath) {
        std::ifstream file(filePath);
        return file.good();
    }

    // מימוש שמירת המפתח הפרטי של ה-RSA בקובץ priv.key (לפי עמוד 5 פסקת "מפתח ציבורי")
    void savePrivateKeyFile(const std::string& privateKeyData, const std::string& filePath) {
        std::ofstream file(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open priv.key for writing: " + filePath);
        }
        file.write(privateKeyData.data(), static_cast<std::streamsize>(privateKeyData.size()));
    }

    // מימוש טעינת המפתח הפרטי מהקובץ priv.key בעת התחברות חוזרת (לפי עמוד 5 סעיף 3)
    std::string loadPrivateKeyFile(const std::string& filePath) {
        std::string keyContent = trim(readEntireFile(filePath));
        if (keyContent.empty()) {
            throw std::runtime_error("priv.key is empty.");
        }
        return keyContent;
    }

} // namespace Config
