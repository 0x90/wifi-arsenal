#ifndef QTGUI_H
#define QTGUI_H

#include "ui_QtGUI.h"
#include "GUI.h"
#include "NetStatsModel.h"
#include "NetStatsSortProxyModel.h"
#include "NetManager.h"
#include <vector>
#include <string>

class QtGUI : public QWidget, public GUI {
    Q_OBJECT

public:
    QtGUI(const std::vector<std::string>& interfaces, QWidget* parent = 0);
    virtual ~QtGUI();
    
    void setNetManager(NetManager* nm);
    void updateChannel(unsigned short channel, const std::list<NetStats>& stats);
    void updateScanChannel(unsigned short channel);
    void updateRemainingChannelTime(int seconds);

public slots:
    void setChannelTime(int sec);
    void setEmptyChannelTime(int sec);
    void setInterface(const QString& iface);
    void setDisappearedAtBottom(bool enabled);
    void addChannel(uint channel);
    void removeChannel(uint channel);
    void selectChannel(uint channel);

private:
    Ui::QtGUI ui;
    NetStatsModel* model;
    NetStatsSortProxyModel* proxyModel;
    NetManager* nm;
    bool selectInterfaceEnabled;
};

#endif
