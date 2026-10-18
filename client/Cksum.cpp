/**
 * קובץ: Cksum.cpp
 * מימוש חישוב ה-CRC בצד הלקוח באופן זהה לפקודת cksum בלינוקס (לפי דרישת עמוד 2 סעיף 4.ג ועמוד 5 במטלה).
 * הלקוח מחשב את ה-CRC של הקובץ המקורי ומשווה אותו לערך ה-Cksum שמתקבל מהשרת בתשובה 1603.
 */

#include "Cksum.h"

#include <array>
#include <fstream>
#include <stdexcept>

namespace Cksum {

    namespace {
        // הפולינום של POSIX 1003.2 CRC-32 המשמש את פקודת cksum בלינוקס
        constexpr uint32_t POSIX_CRC_POLY = 0x04C11DB7U;

        // בניית טבלת 256 הערכים של ה-CRC בזמן קומפילציה
        constexpr std::array<uint32_t, 256> generateCrcTable() {
            std::array<uint32_t, 256> table{};
            for (uint32_t i = 0; i < 256; ++i) {
                uint32_t crc = i << 24;
                for (int bit = 0; bit < 8; ++bit) {
                    if ((crc & 0x80000000U) != 0) {
                        crc = (crc << 1) ^ POSIX_CRC_POLY;
                    } else {
                        crc = (crc << 1);
                    }
                }
                table[i] = crc;
            }
            return table;
        }

        constexpr std::array<uint32_t, 256> CRC_TABLE = generateCrcTable();
    } // namespace

    // מימוש אלגוריתם cksum של לינוקס: מעבר על כל בתי הקובץ, שילוב אורך הקובץ, והיפוך סיביות בסוף (עמוד 2 סעיף 4.ג)
    uint32_t calculate_cksum(const uint8_t* data, size_t size) {
        uint32_t crc = 0;

        for (size_t i = 0; i < size; ++i) {
            uint8_t idx = static_cast<uint8_t>((crc >> 24) ^ data[i]);
            crc = (crc << 8) ^ CRC_TABLE[idx];
        }

        size_t length = size;
        while (length > 0) {
            uint8_t idx = static_cast<uint8_t>((crc >> 24) ^ (length & 0xFFU));
            crc = (crc << 8) ^ CRC_TABLE[idx];
            length >>= 8;
        }

        return ~crc;
    }

    uint32_t calculate_cksum(const std::vector<uint8_t>& buffer) {
        return calculate_cksum(buffer.data(), buffer.size());
    }

    // קריאת קובץ בינארי מהדיסק וחישוב ה-CRC שלו
    uint32_t calculate_file_cksum(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file for CRC calculation: " + filePath);
        }

        std::streamsize fileSize = file.tellg();
        if (fileSize < 0) {
            throw std::runtime_error("Failed to determine file size: " + filePath);
        }

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
        if (fileSize > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
            throw std::runtime_error("Failed to read file for CRC calculation: " + filePath);
        }

        return calculate_cksum(buffer);
    }

} // namespace Cksum
