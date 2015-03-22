#include "ChannelsWidget.h"

ChannelsModel::ChannelsModel(QObject *parent)
    : QAbstractListModel(parent) {}

int ChannelsModel::rowCount(const QModelIndex& /*parent*/) const {
    return channels.size();
}

QVariant ChannelsModel::data(const QModelIndex &index, int role) const {
    if (channels.empty()) return QVariant();
    
    std::list<unsigned short>::const_iterator channel = channels.begin();
    advance(channel, index.row());
    
    if (role == Qt::DisplayRole) {
        return QString("%0").arg(*channel);
    }
    else if (role == Qt::UserRole) {
        return *channel;
    }
    
    return QVariant();
}

bool ChannelsModel::addChannel(unsigned short channel) {
    unsigned int pos = 0;
    std::list<unsigned short>::iterator it = channels.begin();
    while (it != channels.end() and *it < channel) {
        ++pos; ++it;
    }
    
    if (it == channels.end() or *it != channel) {
        beginInsertRows(QModelIndex(), pos, pos);
        channels.insert(it, channel);
        endInsertRows();
        return true;
    }
    return false;
}

bool ChannelsModel::removeRows (int row, int count, const QModelIndex& /*parent*/) {
    if (row < 0 or (row + count) > channels.size()) return false;
    
    std::list<unsigned short>::iterator it = channels.begin();
    advance(it, row);
    beginRemoveRows(QModelIndex(), row, row + count - 1);
    for (int i = 0; i < count; ++i) channels.erase(it);
    endRemoveRows();
    return true;
}

std::list<unsigned short> ChannelsModel::getChannels() const {
    return channels;
}

void ChannelsModel::addChannels(const std::list<unsigned short>& channels) {
    for (std::list<unsigned short>::const_iterator it = channels.begin(); it != channels.end(); ++it) {
        addChannel(*it);
    }
}

ChannelsWidget::ChannelsWidget(QWidget* parent) : QWidget(parent) {
    ui.setupUi(this);
    model = new ChannelsModel(ui.channelsList);
    ui.channelsList->setModel(model);
}

void ChannelsWidget::addChannels(const std::list<unsigned short>& channels) {
    model->addChannels(channels);
}

void ChannelsWidget::addChannel() {
    if (model->addChannel(ui.channelSpin->value())) emit(addChannel(ui.channelSpin->value()));
}

void ChannelsWidget::removeChannels() {
    QItemSelectionModel* selectionModel = ui.channelsList->selectionModel();
    QModelIndexList selectedIndexes = selectionModel->selectedIndexes();
    for (int i = 0; i < selectedIndexes.size(); ++i) {
        emit(removeChannel(model->data(selectedIndexes.at(i), Qt::UserRole).toUInt()));
        model->removeRow(selectedIndexes.at(i).row());
    }
}

void ChannelsWidget::selectChannel(const QModelIndex& index) {
    emit(selectChannel(model->data(index, Qt::UserRole).toUInt()));
}

