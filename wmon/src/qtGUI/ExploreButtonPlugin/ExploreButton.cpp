#include "ExploreButton.h"
#include <QFileDialog>
#include <iostream>
using namespace std;

ExploreButton::ExploreButton(QWidget* parent) : QPushButton(parent) {
    setText("Explore...");
    connect(this, SIGNAL(clicked()), this, SLOT(explore()));
}

void ExploreButton::explore() {
    QString path = QFileDialog::getSaveFileName(this, tr("Save to..."));
    if (not path.isNull()) {
        emit(selectPath(path));
    }
}
