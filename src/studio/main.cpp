#include <QApplication>
#include <QFont>
#include <QStringList>

#include "StudioWindow.h"

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    QApplication::setApplicationName(QStringLiteral("WmpfStudio"));
    a.setFont(QFont(QStringList{QStringLiteral("Inter"), QStringLiteral("Segoe UI"),
                                QStringLiteral("Microsoft YaHei")}));

    // Offscreen UI verification: --screenshot <png>
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--screenshot") == 0 && i + 1 < argc) {
            StudioWindow w;
            w.resize(640, 560);
            w.grab().save(QString::fromLocal8Bit(argv[i + 1]));
            return 0;
        }
    }

    StudioWindow w;
    w.show();
    return QApplication::exec();
}
