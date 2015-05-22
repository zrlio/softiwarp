
lib_LTLIBRARIES = src/libsiw.la

AM_CFLAGS = -g -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
	siw_version_script = -Wl,--version-script=$(srcdir)/src/siw.map
else
	siw_version_script =
endif

src_libsiw_la_SOURCES = src/siw_verbs.c src/siw.c src/siw_uverbs.c

src_libsiw_la_LDFLAGS = -avoid-version -release @IBV_DEVICE_LIBRARY_EXTENSION@ \
    $(siw_version_script)

siwconfdir = $(sysconfdir)/libibverbs.d
siwconf_DATA = siw.driver

EXTRA_DIST = src/siw.h src/siw_abi.h src/siw.map libsiw.spec.in \
	siw.driver

dist-hook: libsiw.spec
	cp libsiw.spec $(distdir)






