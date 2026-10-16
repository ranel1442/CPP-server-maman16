/**
 * @file Cksum.cpp
 * @brief מימוש חישוב Checksum לפי תקן POSIX 1003.2 (זהה לפקודת `cksum` בלינוקס ולשרת הפייתון).
 *
 * האלגוריתם משתמש בטבלת חיפוש של 256 איברים המחושבת בזמן הידור (`constexpr`)
 * עם הפולינום הגנרטור 0x04C11DB7, עובר על כל בתי הקובץ, משלב את אורך הקובץ באוקטטות,
 * ומבצע היפוך סיביות (bitwise NOT) בסיום.
 *
 * מי קורא למודול זה:
 * - מודול העברת הקבצים בלקוח (השוואת ה-CRC המקומי ל-`cksum` שמתקבל בתשובה 1603 מהשרת).
 */

#include "Cksum.h"

#include <array>
#include <fstream>
#include <stdexcept>

namespace Cksum {

    namespace {
        /// הפולינום הגנרטור של תקן POSIX 1003.2 CRC-32
        constexpr uint32_t POSIX_CRC_POLY = 0x04C11DB7U;

        /**
         * @brief פונקציית עזר פנימית (`constexpr`) לבניית טבלת 256 הערכים של POSIX CRC בזמן הידור.
         */
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

        /// טבלת ה-CRC הקבועה בזיכרון (מחושבת בזמן קומפילציה)
        constexpr std::array<uint32_t, 256> CRC_TABLE = generateCrcTable();
    } // namespace

    /**
     * @brief חישוב ערך Checksum (32-bit unsigned) על מערך בתים בזיכרון.
     */
    uint32_t calculate_cksum(const uint8_t* data, size_t size) {
        uint32_t crc = 0;

        // מעבר על כל הבתים בתוכן הקובץ
        for (size_t i = 0; i < size; ++i) {
            uint8_t idx = static_cast<uint8_t>((crc >> 24) ^ data[i]);
            crc = (crc << 8) ^ CRC_TABLE[idx];
        }

        // שילוב אורך הקובץ (size) בחישוב ה-CRC מהבית הנמוך לגבוה, כפי שמוגדר בפקודת cksum בלינוקס
        size_t length = size;
        while (length > 0) {
            uint8_t idx = static_cast<uint8_t>((crc >> 24) ^ (length & 0xFFU));
            crc = (crc << 8) ^ CRC_TABLE[idx];
            length >>= 8;
        }

        // היפוך סיביות סופי (Bitwise complement)
        return ~crc;
    }

    /**
     * @brief מעטפת נוחה לחישוב Checksum על וקטור בתים (`std::vector<uint8_t>`).
     */
    uint32_t calculate_cksum(const std::vector<uint8_t>& buffer) {
        return calculate_cksum(buffer.data(), buffer.size());
    }

    /**
     * @brief חישוב Checksum ישירות מתוך קובץ בדיסק.
     */
    uint32_t calculate_file_cksum(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file for CRC calculation: " + filePath);
        }

        std::streamsize fileSize = file.tellg();
        if (fileSize < 0) {
            throw std::runtime_error("Failed to determine file size for CRC calculation: " + filePath);
        }

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
        if (fileSize > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
            throw std::runtime_error("Failed to read file content for CRC calculation: " + filePath);
        }

        return calculate_cksum(buffer);
    }

} // namespace Cksum

