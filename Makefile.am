AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall

lib_LIBRARIES = libcasn.a

libcasn_a_SOURCES = casn/asn_app.c casn/asn.c
nobase_include_HEADERS = $(wildcard $(srcdir)/casn/*.h)

bin_PROGRAMS = asn

asn_SOURCES = asn.c tweetnacl.c
asn_LDADD = libcasn.a -luclib
