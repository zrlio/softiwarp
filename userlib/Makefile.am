
lib_LTLIBRARIES = src/libsiw2.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE
AM_CFLAGS += -I../../common

if HAVE_LD_VERSION_SCRIPT
	siw_version_script = -Wl,--version-script=$(srcdir)/src/siw2.map
else
	siw_version_script =
endif

src_libsiw2_la_SOURCES = src/siw_verbs.c src/siw.c src/siw_uverbs.c

src_libsiw2_la_LDFLAGS = -avoid-version -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
    $(siw2_version_script)

siw2confdir = $(sysconfdir)/libibverbs.d
siw2conf_DATA = siw2.driver

EXTRA_DIST = src/siw.h src/siw_abi.h src/siw.map libsiw2.spec.in \
	siw2.driver

dist-hook: libsiw2.spec
	cp libsiw2.spec $(distdir)
