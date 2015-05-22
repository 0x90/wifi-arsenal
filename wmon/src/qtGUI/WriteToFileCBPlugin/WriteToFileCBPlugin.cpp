#include "WriteToFileCB.h"
#include "WriteToFileCBPlugin.h"
#include <QtPlugin>

WriteToFileCBPlugin :: WriteToFileCBPlugin(QObject *parent): QObject(parent)
{
  initialized = false;
}

void WriteToFileCBPlugin ::initialize(QDesignerFormEditorInterface * core)
{
  if (initialized) return;
  initialized = true;
}

bool WriteToFileCBPlugin ::isInitialized() const
{
  return initialized;
}

QWidget * WriteToFileCBPlugin ::createWidget(QWidget *parent)
{
  return new WriteToFileCB(parent);  // Construir el Widget
}

QString WriteToFileCBPlugin ::name() const
{
  return "WriteToFileCB"; // El nom de la classe del Widget
}

QString WriteToFileCBPlugin ::group() const
{
  return "Wmon Widgets";
}

QIcon WriteToFileCBPlugin ::icon() const
{
  return QIcon();
}

QString WriteToFileCBPlugin ::toolTip() const
{
  return "";
}

QString WriteToFileCBPlugin ::whatsThis() const
{
  return "";
}

bool WriteToFileCBPlugin ::isContainer() const
{
  return false;
}

QString WriteToFileCBPlugin ::domXml() const
{
  return "<widget class=\"WriteToFileCB\" name=\"writeToFileCB\" />\n";
}

QString WriteToFileCBPlugin ::includeFile() const
{
  return "WriteToFileCB.h";
}

Q_EXPORT_PLUGIN2(WriteToFileCB, WriteToFileCBPlugin)
