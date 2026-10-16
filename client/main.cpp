/**
 * @file main.cpp
 * @brief נקודת הכניסה הראשית (`main`) של תוכנת הלקוח (C++20) עבור פרויקט ממ"ן 16.
 *
 * קובץ זה מאתחל מופע של המחלקה `ClientApp::ClientManager` ומפעיל את פונקציית `start()`
 * שמבצעת את כל סדר הפעולות הקבוע (Batch Mode) מול השרת:
 * 1. טעינת הקובץ `transfer.json`.
 * 2. רישום לקוח חדש (825 + 826) או התחברות חוזרת (827) בהתאם לקיום הקובץ `me.info`.
 * 3. הצפנת הקבצים ב-`AES-CBC` ושליחתם לשרת (828) בחבילה אחת או יותר.
 * 4. אימות שלמות הקבצים באמצעות `cksum` (900 / 901 / 902).
 *
 * כל החריגות ואירועי הקצה נתפסים בבלוק `try / catch` מרכזי המדפיס הודעת `Fatal` מפורטת
 * ומסיים את התוכנית באופן מבוקר וללא קריסה.
 */

#include "ClientManager.h"

#include <cstdlib>
#include <exception>
#include <iostream>

/**
 * @brief הפונקציה הראשית של תוכנת הלקוח.
 * @return `EXIT_SUCCESS` (0) בסיום תקין, או `EXIT_FAILURE` (1) במקרה של שגיאה פטאלית.
 */
int main() {
    try {
        ClientApp::ClientManager clientManager;
        clientManager.start();
        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "[Fatal Error] Client terminated due to an unrecoverable error: "
                  << ex.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "[Fatal Error] Client terminated due to an unknown fatal exception." << std::endl;
        return EXIT_FAILURE;
    }
}

