#
# OpenSSL/crypto/frododh/Makefile
#

DIR=	frododh
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
#TEST=dsatest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= frododh_lib.c frododh_asn1.c frododh_err.c
LIBOBJ= frododh_lib.o frododh_asn1.o frododh_err.o

SRC= $(LIBSRC)

EXHEADER= frododh.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	ranlib ../../libcrypto.a
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

frododh_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
frododh_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
frododh_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
frododh_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
frododh_asn1.o: ../../include/openssl/frododh.h ../../include/openssl/lhash.h
frododh_asn1.o: ../../include/openssl/opensslconf.h
frododh_asn1.o: ../../include/openssl/opensslv.h
frododh_asn1.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
frododh_asn1.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
frododh_asn1.o: ../../include/openssl/symhacks.h ../cryptlib.h frododh_asn1.c
frododh_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
frododh_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
frododh_err.o: ../../include/openssl/err.h ../../include/openssl/frododh.h
frododh_err.o: ../../include/openssl/lhash.h
frododh_err.o: ../../include/openssl/opensslconf.h
frododh_err.o: ../../include/openssl/opensslv.h
frododh_err.o: ../../include/openssl/ossl_typ.h
frododh_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
frododh_err.o: ../../include/openssl/symhacks.h frododh_err.c
frododh_lib.o: ../../e_os.h ../../include/openssl/asn1.h
frododh_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
frododh_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
frododh_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
frododh_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
frododh_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
frododh_lib.o: ../../include/openssl/evp.h ../../include/openssl/frododh.h
frododh_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
frododh_lib.o: ../../include/openssl/objects.h
frododh_lib.o: ../../include/openssl/opensslconf.h
frododh_lib.o: ../../include/openssl/opensslv.h
frododh_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
frododh_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
frododh_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
frododh_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
frododh_lib.o: ../cryptlib.h frododh_lib.c
