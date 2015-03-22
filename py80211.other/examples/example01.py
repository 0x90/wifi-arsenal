import py80211.generated.defs as nl80211
import py80211.wiphy
import py80211.cli

phylist = py80211.wiphy.wiphy_list()

for phy in phylist:
	print('%s:' % phy.get_nlattr(nl80211.ATTR_WIPHY_NAME))
	for b in phy.get_nlattr(nl80211.ATTR_WIPHY_BANDS):
		print('%s' % str(py80211.cli.wiphy_band_info(b)))
