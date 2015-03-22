#include "ExploreButton.h"
#include "ExploreButtonPlugin.h"
#include <QtPlugin>

ExploreButtonPlugin :: ExploreButtonPlugin(QObject *parent): QObject(parent)
{
  initialized = false;
}

void ExploreButtonPlugin ::initialize(QDesignerFormEditorInterface * core)
{
  if (initialized) return;
  initialized = true;
}

bool ExploreButtonPlugin ::isInitialized() const
{
  return initialized;
}

QWidget * ExploreButtonPlugin ::createWidget(QWidget *parent)
{
  return new ExploreButton(parent);  // Construir el Widget
}

QString ExploreButtonPlugin ::name() const
{
  return "ExploreButton"; // El nom de la classe del Widget
}

QString ExploreButtonPlugin ::group() const
{
  return "Wmon Widgets";
}

QIcon ExploreButtonPlugin ::icon() const
{
  return QIcon();
}

QString ExploreButtonPlugin ::toolTip() const
{
  return "";
}

QString ExploreButtonPlugin ::whatsThis() const
{
  return "";
}

bool ExploreButtonPlugin ::isContainer() const
{
  return false;
}

QString ExploreButtonPlugin ::domXml() const
{
  return "<widget class=\"ExploreButton\" name=\"exploreButton\" />\n";
}

QString ExploreButtonPlugin ::includeFile() const
{
  return "ExploreButton.h";
}

Q_EXPORT_PLUGIN2(ExploreButton, ExploreButtonPlugin)
