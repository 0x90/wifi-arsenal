TEMPLATE = app
TARGET = wmonGUI
CONFIG += qt thread
INCLUDEPATH += include qtGUI qtGUI/ExploreButtonPlugin qtGUI/WriteToFileCBPlugin qtGUI/ChannelsWidgetPlugin
LIBS += -ltrace -lpcap -liw -lpthread
DEFINES += QTGUI

# Input
HEADERS += include/AirmonNG.h include/CaptureStorage.h include/GUIEventDispatcher.h include/GUI.h include/NetInfo.h include/NetStats.h include/RemainingChannelTimeEvent.h include/UpdateChannelEvent.h include/BeaconInfo.h include/ChangeChannelEvent.h include/FileGUI.h include/GUIEvent.h include/NetID.h include/NetManager.h include/NetStructures.h include/Utils.h qtGUI/QtGUI.h qtGUI/NetStatsModel.h qtGUI/NetStatsSortProxyModel.h qtGUI/ExploreButtonPlugin/ExploreButton.h qtGUI/WriteToFileCBPlugin/WriteToFileCB.h qtGUI/ChannelsWidgetPlugin/ChannelsWidget.h

FORMS += qtGUI/QtGUI.ui qtGUI/ChannelsWidgetPlugin/ChannelsWidget.ui

SOURCES += AirmonNG.cpp ChangeChannelEvent.cpp FileGUI.cpp GUIEventDispatcher.cpp GUIEvent.cpp NetID.cpp NetManager.cpp Utils.cpp CaptureStorage.cpp GUI.cpp main.cpp NetInfo.cpp RemainingChannelTimeEvent.cpp UpdateChannelEvent.cpp qtGUI/QtGUI.cpp qtGUI/NetStatsModel.cpp qtGUI/NetStatsSortProxyModel.cpp qtGUI/ExploreButtonPlugin/ExploreButton.cpp qtGUI/WriteToFileCBPlugin/WriteToFileCB.cpp qtGUI/ChannelsWidgetPlugin/ChannelsWidget.cpp

