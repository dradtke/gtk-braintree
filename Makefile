PKGS := gtk+-3.0 libxml-2.0 libsoup-2.4 json-glib-1.0 gee-0.8
DISABLED_C_WARNINGS := deprecated-declarations pointer-sign

all:
	valac $(foreach pkg,$(PKGS),--pkg=$(pkg)) $(foreach w,$(DISABLED_C_WARNINGS),-X -Wno-$(w)) app.vala

run: all
	./app
