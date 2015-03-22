#include "QtGUI.h"
#include <vector>

QtGUI::QtGUI(const std::vector<std::string>& interfaces, QWidget* parent) : QWidget(parent) {
    ui.setupUi(this);
    selectInterfaceEnabled = false;
    model = new NetStatsModel(NULL); // Instantiates the model of the GUI
    proxyModel = new NetStatsSortProxyModel(NULL); // Instantiates the proxy of the model
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSourceModel(model); // Connects the proxy to the source model
    ui.modelView->setModel(proxyModel); // Connects the view to the proxy
    
    ui.modelView->sortByColumn(NetStatsModel::CHANNEL, Qt::AscendingOrder);
    
    ui.modelView->setColumnWidth(NetStatsModel::BSSID, 125);
    ui.modelView->setColumnWidth(NetStatsModel::CHANNEL, 80);
    ui.modelView->setColumnWidth(NetStatsModel::UTILIZATION, 85);
    ui.modelView->setColumnWidth(NetStatsModel::LOSS, 65);
    ui.modelView->setColumnWidth(NetStatsModel::RSSI, 75);
    ui.modelView->setColumnWidth(NetStatsModel::VALID, 55);
    ui.modelView->setColumnWidth(NetStatsModel::SECURITY, 80);
    // ui.modelView->setColumnWidth(NetStatsModel::SSID, 200);
    // ui.modelView->horizontalHeader()->setStretchLastSection(true); // For tableView
    
    for (std::vector<std::string>::const_iterator iface = interfaces.begin(); iface != interfaces.end(); ++iface) {
        ui.interfaces->addItem(iface->c_str()); // String representation + data
    }
}

QtGUI::~QtGUI() {
    delete model;
    delete proxyModel;
}

void QtGUI::setNetManager(NetManager* nm) {
    this->nm = nm;
    ui.ctime->setValue(nm->getChannelTime());
    ui.ectime->setValue(nm->getEmptyChannelTime());
    ui.ectime->setMaximum(nm->getChannelTime());
    ui.channelsList->addChannels(nm->getChannels());
    
    ui.interfaces->setCurrentIndex(ui.interfaces->findText(nm->getInterface().c_str()));
    
    selectInterfaceEnabled = true;
}

void QtGUI::updateChannel(unsigned short /*channel*/, const std::list<NetStats>& stats) {
    model->updateStats(stats);
}

void QtGUI::updateScanChannel(unsigned short channel) {
    ui.currentChannel->setNum(channel);
}

void QtGUI::updateRemainingChannelTime(int seconds) {
    if (seconds < 0) ui.timeLeft->setText("- - -");
    else ui.timeLeft->setNum(static_cast<int>(seconds));
}

void QtGUI::setChannelTime(int sec) {
    nm->setChannelTime(sec);
    ui.ectime->setMaximum(sec);
}

void QtGUI::setEmptyChannelTime(int sec) {
    nm->setEmptyChannelTime(sec);
}

void QtGUI::setInterface(const QString& iface) {
    if (selectInterfaceEnabled) nm->createMonitorInterface(iface.toStdString());
}

void QtGUI::setDisappearedAtBottom(bool enabled) {
    proxyModel->setDisappearedAtBottom(enabled);
}

void QtGUI::addChannel(uint channel) {
    nm->addChannel(channel);
}

void QtGUI::removeChannel(uint channel) {
    nm->removeChannel(channel);
}

void QtGUI::selectChannel(uint channel) {
    nm->lockChannel(channel);
}

