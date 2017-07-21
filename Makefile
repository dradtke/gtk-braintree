PKGS := gtk+-3.0 libxml-2.0 libsoup-2.4 json-glib-1.0 gee-0.8
DISABLED_C_WARNINGS := deprecated-declarations pointer-sign unused-value incompatible-pointer-types incompatible-pointer-types-discards-qualifiers
CFLAGS := 

all:
	valac $(foreach pkg,$(PKGS),--pkg=$(pkg)) $(foreach w,$(DISABLED_C_WARNINGS),-X -Wno-$(w)) $(CFLAGS) app.vala

debug:
	valac $(foreach pkg,$(PKGS),--pkg=$(pkg)) $(foreach w,$(DISABLED_C_WARNINGS),-X -Wno-$(w)) $(CFLAGS) --debug app.vala
	lldb ./app

run: all
	./app
