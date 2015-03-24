COMMON_HEADERS=ah_regdomain_common.h ah_regdomain.h

all: hal-reg-dump

hal-reg-dump: hal-reg-dump.c $(COMMON_HEADERS)
	gcc -o $@ hal-reg-dump.c

clean:
	rm -f hal-reg-dump

.PHONY: all
