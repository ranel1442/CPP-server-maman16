/**
 * @file Cksum.h
 * @brief הצהרת פונקציות לחישוב Checksum (CRC-32) לפי תקן POSIX 1003.2 (זהה לפקודת `cksum` בלינוקס).
 *
 * מודול זה מאפשר ללקוח לחשב את ערך ה-CRC של קובץ מקורי (לפני הצפנה) ולהשוות אותו לערך ה-CRC
 * שחושב על ידי השרת והוחזר בתשובה 1603 (`FILE_RECEIVED_WITH_CRC`).
 *
 * מי קורא למודול זה:
 * - לוגיקת העברת הקבצים בלקוח (לפני/בזמן שליחת קובץ בבקשה 828 ולצורך החלטה אם לשלוח 900, 901 או 902).
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace Cksum {

    /**
     * @brief חישוב ערך Checksum (32 ביט ללא סימן) על מערך בתים בזיכרון.
     *        החישוב זהה לחלוטין לפקודת `cksum` בלינוקס ולפונקציה `calculate_cksum` בשרת הפייתון.
     *
     * @param data מצביע למערך הבתים של תוכן הקובץ המקורי.
     * @param size גודל מערך הבתים (מספר הבתים בקובץ).
     * @return ערך ה-CRC כמספר שלם 32-ביט חסר סימן (`uint32_t`).
     */
    uint32_t calculate_cksum(const uint8_t* data, size_t size);

    /**
     * @brief מעטפת נוחה לחישוב Checksum על וקטור בתים (`std::vector<uint8_t>`).
     *
     * @param buffer וקטור המכיל את תוכן הקובץ.
     * @return ערך ה-CRC כמספר שלם 32-ביט חסר סימן (`uint32_t`).
     */
    uint32_t calculate_cksum(const std::vector<uint8_t>& buffer);

    /**
     * @brief חישוב Checksum ישירות מתוך קובץ בדיסק על ידי קריאתו במצב בינארי.
     *        זורקת חריגת `std::runtime_error` אם הקובץ לא ניתן לפתיחה או לקריאה.
     *
     * @param filePath נתיב הקובץ בדיסק.
     * @return ערך ה-CRC כמספר שלם 32-ביט חסר סימן (`uint32_t`).
     */
    uint32_t calculate_file_cksum(const std::string& filePath);

} // namespace Cksum

