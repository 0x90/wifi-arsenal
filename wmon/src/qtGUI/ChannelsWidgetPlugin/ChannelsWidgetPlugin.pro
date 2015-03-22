CONFIG+=designer thread plugin release 
TEMPLATE=lib 
TARGET =
DEPENDPATH += .
INCLUDEPATH += .

HEADERS+=ChannelsWidget.h ChannelsWidgetPlugin.h 
FORMS += ChannelsWidget.ui
SOURCES += ChannelsWidget.cpp ChannelsWidgetPlugin.cpp 

target.path=~/.designer/plugins/designer 
INSTALLS+=target
