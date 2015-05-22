CONFIG+=designer plugin release 
TEMPLATE=lib 
TARGET =
DEPENDPATH += .
INCLUDEPATH += .

HEADERS+=ExploreButton.h ExploreButtonPlugin.h 
SOURCES += ExploreButton.cpp ExploreButtonPlugin.cpp 

target.path=~/.designer/plugins/designer 
INSTALLS+=target
