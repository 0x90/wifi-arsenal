#ifndef EXPLOREBUTTON_H
#define EXPLOREBUTTON_H

#include <QPushButton>
#include <QtDesigner/QDesignerExportWidget>

class QDESIGNER_WIDGET_EXPORT ExploreButton : public QPushButton
{
    Q_OBJECT

    public:
    
        ExploreButton(QWidget *parent = 0);
    
    signals:
        void selectPath(const QString& path);
    
    private slots:
        void explore();    
};

#endif
