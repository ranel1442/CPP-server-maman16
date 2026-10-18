/**
 * קובץ: main.cpp
 * נקודת הכניסה הראשית של תוכנת הלקוח ב-C++20 (לפי דרישות הלקוח בעמודים 4-5 ו-11-12 במטלה).
 *
 * התוכנית מריצה את הלקוח במצב Batch Mode על פי סדר הפעולות הקבוע ב-ClientManager,
 * ובמקרה של כשל סופי (לאחר 3 ניסיונות חוזרים מול השרת או תקלה מקומית) יוצאת עם הודעת Fatal מפורטת (עמוד 5).
 */

#include "ClientManager.h"

#include <cstdlib>
#include <exception>
#include <iostream>

int main() {
    try {
        ClientApp::ClientManager client;
        client.start();
        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        // מימוש דרישת עמוד 5 במטלה: יציאה עם הודעת Fatal מפורטת במקרה שהפעולה לא הצליחה
        std::cerr << "[Fatal] " << ex.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "[Fatal] An unexpected fatal error occurred in the client." << std::endl;
        return EXIT_FAILURE;
    }
}
