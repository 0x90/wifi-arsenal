include			../common.mak

MP_FILES        = openwips-ng.1 openwips-ng-server.1

default: all

all:
	@echo Nothing to do
	
install: uninstall
	install -d $(DESTDIR)$(mandir)
	install -m 644 $(MP_FILES) $(DESTDIR)$(mandir)

uninstall:
	@-$(foreach CUR_MP,$(MP_FILES), rm -f $(DESTDIR)$(mandir)/$(CUR_MP); echo rm -f $(DESTDIR)$(mandir)/$(CUR_MP); )