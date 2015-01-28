AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall

lib_LIBRARIES = libcasn.a

libcasn_a_SOURCES = casn/asn_app.c casn/asn.c casn/tweetnacl.c
nobase_include_HEADERS = $(wildcard $(srcdir)/casn/*.h)

bin_PROGRAMS = asntest

asntest_SOURCES = test/asn.c
asntest_LDADD = libcasn.a -luclib
