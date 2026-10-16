/**
 * @file Config.cpp
 * @brief מימוש ניהול קובצי התצורה והמפתחות של הלקוח (`transfer.json`, `me.info`, `priv.key`).
 *
 * מודול זה כתוב ב-C++20 סטנדרטי (ללא תלות בספריות JSON חיצוניות כדי לעמוד בדרישת המטלה
 * לא להסתמך על ספריות חיצוניות למעט הספריות המותרות).
 *
 * דגשים בפענוח `transfer.json`:
 * - בדוגמה הרשמית במטלה מופיעים נתיבי Windows עם לוכסן יחיד בתוך מחרוזת JSON:
 *   `"files": [ "c:\doc\file02.docx", "c:\openu\defensive\file06-2026c.pdf" ]`
 *   מפענח JSON רגיל היה נכשל או מפרש `\f` כ-Form Feed (`0x0C`). לכן הפונקציות במודול זה
 *   תומכות הן בלוכסן כפול (`\\`) והן בלוכסן יחיד (`\`) בנתיבי קבצים של חלונות.
 *
 * מי קורא למודול זה:
 * - הלקוח הראשי (`Client` / `main`) לצורך טעינת הגדרות השרת והקבצים וניהול מצב הרישום (`me.info`, `priv.key`).
 */

#include "Config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace Config {

    namespace {

        /**
         * @brief הסרת רווחים ותווי מעבר שורה (`\r`, `\n`, `\t`, ` `) מתחילת ומסוף מחרוזת.
         */
        std::string trim(const std::string& str) {
            size_t first = str.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) {
                return "";
            }
            size_t last = str.find_last_not_of(" \t\r\n");
            return str.substr(first, (last - first + 1));
        }

        /**
         * @brief קריאת תוכן קובץ טקסט שלם למחרוזת.
         */
        std::string readEntireFile(const std::string& filePath) {
            std::ifstream file(filePath, std::ios::in | std::ios::binary);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot open file: " + filePath);
            }
            std::ostringstream ss;
            ss << file.rdbuf();
            return ss.str();
        }

        /**
         * @brief דילוג על תווי רווח לבן בתוך מחרוזת JSON החל מאינדקס `pos`.
         */
        void skipWhitespace(const std::string& text, size_t& pos) {
            while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
                ++pos;
            }
        }

        /**
         * @brief חילוץ מחרוזת תחומה במירכאות (`"..."`) מתוך טקסט ה-JSON החל מאינדקס `pos`.
         *        תומכת בלוכסן יחיד בנתיבי Windows (כגון `"c:\doc\file02.docx"`) וכן ב-Escape של `\"` ו-`\\`.
         */
        std::string parseJsonQuotedString(const std::string& text, size_t& pos) {
            skipWhitespace(text, pos);
            if (pos >= text.size() || text[pos] != '"') {
                throw std::runtime_error("Expected '\"' at start of JSON string value.");
            }
            ++pos; // דילוג על המירכאות הפותחות

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
                        // שימור הלוכסן כפי שהוא עבור נתיבי Windows עם לוכסן יחיד (למשל "c:\doc\file02.docx")
                        result.push_back('\\');
                    }
                } else {
                    result.push_back(ch);
                }
            }
            throw std::runtime_error("Unterminated string literal in transfer.json.");
        }

        /**
         * @brief איתור מפתח JSON (`"key"`) והחזרת המיקום שאחרי הנקודתיים (`:`) שלו.
         */
        size_t findJsonKeyValueStart(const std::string& jsonText, const std::string& key, size_t searchFrom = 0) {
            const std::string pattern = "\"" + key + "\"";
            size_t keyPos = jsonText.find(pattern, searchFrom);
            if (keyPos == std::string::npos) {
                throw std::runtime_error("Missing required key '" + key + "' in transfer.json.");
            }
            size_t colonPos = jsonText.find(':', keyPos + pattern.size());
            if (colonPos == std::string::npos) {
                throw std::runtime_error("Missing ':' after key '" + key + "' in transfer.json.");
            }
            return colonPos + 1;
        }

    } // namespace

    /**
     * @brief קריאה ופענוח של הקובץ `transfer.json`.
     */
    TransferConfig loadTransferConfig(const std::string& filePath) {
        std::string content = readEntireFile(filePath);
        TransferConfig config{};

        // איתור אובייקט "server"
        size_t serverStart = findJsonKeyValueStart(content, "server");
        skipWhitespace(content, serverStart);
        if (serverStart >= content.size() || content[serverStart] != '{') {
            throw std::runtime_error("Invalid 'server' object in transfer.json.");
        }

        // חילוץ שדה "ip" מתוך "server"
        size_t ipPos = findJsonKeyValueStart(content, "ip", serverStart);
        config.serverIp = trim(parseJsonQuotedString(content, ipPos));
        if (config.serverIp.empty()) {
            throw std::runtime_error("Server IP cannot be empty in transfer.json.");
        }

        // חילוץ שדה "port" מתוך "server" (יכול להיות מספר או מחרוזת)
        size_t portPos = findJsonKeyValueStart(content, "port", serverStart);
        skipWhitespace(content, portPos);
        unsigned long portVal = 0;
        if (portPos < content.size() && content[portPos] == '"') {
            std::string portStr = parseJsonQuotedString(content, portPos);
            portVal = std::stoul(portStr);
        } else {
            size_t numEnd = portPos;
            while (numEnd < content.size() && std::isdigit(static_cast<unsigned char>(content[numEnd]))) {
                ++numEnd;
            }
            if (numEnd == portPos) {
                throw std::runtime_error("Invalid 'port' value in transfer.json.");
            }
            portVal = std::stoul(content.substr(portPos, numEnd - portPos));
        }

        if (portVal == 0 || portVal > 65535) {
            throw std::runtime_error("Port number out of valid range (1-65535) in transfer.json.");
        }
        config.serverPort = static_cast<uint16_t>(portVal);

        // חילוץ שדה "client" מתוך "server" (עד 100 תווים לפי המטלה)
        size_t clientPos = findJsonKeyValueStart(content, "client", serverStart);
        config.clientName = parseJsonQuotedString(content, clientPos);
        if (config.clientName.empty() || config.clientName.size() > Protocol::MAX_CONFIG_CLIENT_NAME) {
            throw std::runtime_error("Client name in transfer.json must be between 1 and 100 characters.");
        }

        // חילוץ מערך הקבצים "files"
        size_t filesPos = findJsonKeyValueStart(content, "files");
        skipWhitespace(content, filesPos);
        if (filesPos >= content.size() || content[filesPos] != '[') {
            throw std::runtime_error("Expected '[' for 'files' array in transfer.json.");
        }
        ++filesPos; // דילוג על '['

        while (filesPos < content.size()) {
            skipWhitespace(content, filesPos);
            if (filesPos < content.size() && content[filesPos] == ']') {
                ++filesPos;
                break;
            }
            std::string fileEntry = parseJsonQuotedString(content, filesPos);
            if (!fileEntry.empty()) {
                config.files.push_back(fileEntry);
            }
            skipWhitespace(content, filesPos);
            if (filesPos < content.size() && content[filesPos] == ',') {
                ++filesPos;
            } else if (filesPos < content.size() && content[filesPos] == ']') {
                ++filesPos;
                break;
            } else {
                throw std::runtime_error("Malformed 'files' array in transfer.json.");
            }
        }

        return config;
    }

    /**
     * @brief בדיקה האם הקובץ `me.info` קיים.
     */
    bool meInfoExists(const std::string& filePath) {
        std::ifstream file(filePath);
        return file.good();
    }

    /**
     * @brief טעינת פרטי הלקוח מתוך הקובץ `me.info`.
     */
    MeInfo loadMeInfo(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open me.info file: " + filePath);
        }

        MeInfo info{};
        std::string line1;
        std::string line2;

        // שורה 1: שם הלקוח
        if (!std::getline(file, line1)) {
            throw std::runtime_error("me.info is missing line 1 (client name).");
        }
        info.clientName = trim(line1);
        if (info.clientName.empty() || info.clientName.size() >= Protocol::NAME_FIELD_SIZE) {
            throw std::runtime_error("Invalid client name in me.info.");
        }

        // שורה 2: מזהה ייחודי בייצוג הקסדצימלי (32 תווי ASCII)
        if (!std::getline(file, line2)) {
            throw std::runtime_error("me.info is missing line 2 (hex Client ID).");
        }
        info.clientId = Protocol::hexToClientId(trim(line2));

        // שורה 3 והלאה: מפתח פרטי בפורמט Base64
        std::ostringstream keyStream;
        std::string keyLine;
        while (std::getline(file, keyLine)) {
            std::string trimmedLine = trim(keyLine);
            if (!trimmedLine.empty()) {
                keyStream << trimmedLine;
            }
        }
        info.privateKeyBase64 = keyStream.str();

        return info;
    }

    /**
     * @brief שמירת פרטי הלקוח לקובץ `me.info`.
     */
    void saveMeInfo(const MeInfo& info, const std::string& filePath) {
        std::ofstream file(filePath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open me.info for writing: " + filePath);
        }

        file << info.clientName << "\n";
        file << Protocol::clientIdToHex(info.clientId) << "\n";
        file << info.privateKeyBase64 << "\n";

        if (!file.good()) {
            throw std::runtime_error("Error occurred while writing to me.info.");
        }
    }

    /**
     * @brief בדיקה האם הקובץ `priv.key` קיים.
     */
    bool privKeyExists(const std::string& filePath) {
        std::ifstream file(filePath);
        return file.good();
    }

    /**
     * @brief שמירת המפתח הפרטי של RSA לקובץ `priv.key`.
     */
    void savePrivateKeyFile(const std::string& privateKeyData, const std::string& filePath) {
        std::ofstream file(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open priv.key for writing: " + filePath);
        }
        file.write(privateKeyData.data(), static_cast<std::streamsize>(privateKeyData.size()));
        if (!file.good()) {
            throw std::runtime_error("Error occurred while writing to priv.key.");
        }
    }

    /**
     * @brief טעינת המפתח הפרטי של RSA מתוך הקובץ `priv.key`.
     */
    std::string loadPrivateKeyFile(const std::string& filePath) {
        std::string content = trim(readEntireFile(filePath));
        if (content.empty()) {
            throw std::runtime_error("Private key file (priv.key) is empty.");
        }
        return content;
    }

} // namespace Config

