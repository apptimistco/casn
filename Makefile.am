AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall

bin_PROGRAMS = t # asn

asn_SOURCES = asn.c tweetnacl.c
asn_LDADD = -luclib

t_SOURCES = t.c casn/asn_app.c
t_LDADD = -luclib
