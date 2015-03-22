#include "NetStatsSortProxyModel.h"
#include "NetStatsModel.h"

NetStatsSortProxyModel::NetStatsSortProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent) {
    disappearedAtBottom = true;
}

void NetStatsSortProxyModel::setDisappearedAtBottom(bool enabled) {
    disappearedAtBottom = enabled;
    invalidate();
}

bool NetStatsSortProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const {
    QVariant leftData = sourceModel()->data(left, Qt::UserRole);
    QVariant rightData = sourceModel()->data(right, Qt::UserRole);
    
    if (disappearedAtBottom) {
        QVariant lossLeft = sourceModel()->data(createIndex(left.row(), NetStatsModel::LOSS), Qt::UserRole);
        QVariant lossRight = sourceModel()->data(createIndex(right.row(), NetStatsModel::LOSS), Qt::UserRole);
        
        if (lossLeft.toDouble() == 1 and lossRight.toDouble() < 1) return false;
        if (lossRight.toDouble() == 1 and lossLeft.toDouble() < 1) return true;
    }
    
    switch (leftData.type()) {
        case QVariant::ByteArray:
            if (leftData.toByteArray() != rightData.toByteArray()) return leftData.toByteArray() < rightData.toByteArray();
            return lessThan(createIndex(left.row(), NetStatsModel::CHANNEL), createIndex(right.row(), NetStatsModel::CHANNEL));
        
        case QVariant::Double:
            if (leftData.toDouble() != rightData.toDouble()) return leftData.toDouble() < rightData.toDouble();
            return lessThan(createIndex(left.row(), NetStatsModel::CHANNEL), createIndex(right.row(), NetStatsModel::CHANNEL));
        
        case QVariant::Int:
            if (leftData.toInt() != rightData.toInt()) return leftData.toInt() < rightData.toInt();
            return lessThan(createIndex(left.row(), NetStatsModel::CHANNEL), createIndex(right.row(), NetStatsModel::CHANNEL));
        
        case QVariant::UInt: // Order by channel - Only channel is UInt
            if (leftData.toUInt() != rightData.toUInt()) return leftData.toUInt() < rightData.toUInt();
            
            // Same channel, try to order by BSSID
            leftData = sourceModel()->data(createIndex(left.row(), NetStatsModel::BSSID), Qt::UserRole);
            rightData = sourceModel()->data(createIndex(right.row(), NetStatsModel::BSSID), Qt::UserRole);
            
            if (leftData.toByteArray() != rightData.toByteArray()) return leftData.toByteArray() < rightData.toByteArray();
            
            // Same BSSID, order by SSID
            leftData = sourceModel()->data(createIndex(left.row(), NetStatsModel::SSID), Qt::UserRole);
            rightData = sourceModel()->data(createIndex(right.row(), NetStatsModel::SSID), Qt::UserRole);
            return leftData.toString().compare(rightData.toString(), Qt::CaseInsensitive) < 0;
            
        case QVariant::String:
          { int res = leftData.toString().compare(rightData.toString(), Qt::CaseInsensitive);
            if (res != 0) return res < 0;
            return lessThan(createIndex(left.row(), NetStatsModel::CHANNEL), createIndex(right.row(), NetStatsModel::CHANNEL)); }
        
        case QVariant::Bool:
            if (leftData.toBool() != rightData.toBool()) return leftData.toBool() < rightData.toBool();
            return lessThan(createIndex(left.row(), NetStatsModel::CHANNEL), createIndex(right.row(), NetStatsModel::CHANNEL));
        
        default:
            return true; // Error
    }
}

