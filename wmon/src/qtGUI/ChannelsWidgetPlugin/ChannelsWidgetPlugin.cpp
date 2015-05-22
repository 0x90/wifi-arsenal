#include "ChannelsWidget.h"
#include "ChannelsWidgetPlugin.h"
#include <QtPlugin>

ChannelsWidgetPlugin :: ChannelsWidgetPlugin(QObject *parent): QObject(parent)
{
  initialized = false;
}

void ChannelsWidgetPlugin ::initialize(QDesignerFormEditorInterface * core)
{
  if (initialized) return;
  initialized = true;
}

bool ChannelsWidgetPlugin ::isInitialized() const
{
  return initialized;
}

QWidget * ChannelsWidgetPlugin ::createWidget(QWidget *parent)
{
  return new ChannelsWidget(parent);  // Construir el Widget
}

QString ChannelsWidgetPlugin ::name() const
{
  return "ChannelsWidget"; // El nom de la classe del Widget
}

QString ChannelsWidgetPlugin ::group() const
{
  return "Wmon Widgets";
}

QIcon ChannelsWidgetPlugin ::icon() const
{
  return QIcon();
}

QString ChannelsWidgetPlugin ::toolTip() const
{
  return "";
}

QString ChannelsWidgetPlugin ::whatsThis() const
{
  return "";
}

bool ChannelsWidgetPlugin ::isContainer() const
{
  return false;
}

QString ChannelsWidgetPlugin ::domXml() const
{
  return "<widget class=\"ChannelsWidget\" name=\"channelsWidget\" />\n";
}

QString ChannelsWidgetPlugin ::includeFile() const
{
  return "ChannelsWidget.h";
}

Q_EXPORT_PLUGIN2(ChannelsWidget, ChannelsWidgetPlugin)
