/**
 * קובץ: Cksum.h
 * הצהרת פונקציות לחישוב ערך ה-CRC (checksum) בצד הלקוח.
 * החישוב מבוצע באופן זהה לפקודת cksum בלינוקס ולחישוב שבשרת הפייתון (לפי דרישת עמוד 2 סעיף 4.ג ועמוד 5 במטלה).
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Cksum {

    // חישוב ה-CRC (32 ביט ללא סימן) על מערך בתים בזיכרון לפי תקן POSIX cksum
    uint32_t calculate_cksum(const uint8_t* data, size_t size);

    // חישוב ה-CRC על וקטור בתים המכיל את תוכן הקובץ המקורי
    uint32_t calculate_cksum(const std::vector<uint8_t>& buffer);

    // חישוב ה-CRC ישירות מקובץ בדיסק לפי נתיבו
    uint32_t calculate_file_cksum(const std::string& filePath);

} // namespace Cksum
