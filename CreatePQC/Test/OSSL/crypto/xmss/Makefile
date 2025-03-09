#
# OpenSSL/crypto/xmss/Makefile
#

DIR=	xmss
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
LIBSRC= xmss_lib.c xmss_asn1.c xmss_err.c
LIBOBJ= xmss_lib.o xmss_asn1.o xmss_err.o

SRC= $(LIBSRC)

EXHEADER= xmss.h
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

xmss_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
xmss_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
xmss_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
xmss_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
xmss_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
xmss_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
xmss_asn1.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
xmss_asn1.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
xmss_asn1.o: ../../include/openssl/xmss.h ../cryptlib.h xmss_asn1.c
xmss_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
xmss_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
xmss_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
xmss_err.o: ../../include/openssl/opensslconf.h
xmss_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
xmss_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
xmss_err.o: ../../include/openssl/symhacks.h ../../include/openssl/xmss.h
xmss_err.o: xmss_err.c
xmss_lib.o: ../../e_os.h ../../include/openssl/asn1.h
xmss_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
xmss_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
xmss_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
xmss_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
xmss_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
xmss_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
xmss_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
xmss_lib.o: ../../include/openssl/opensslconf.h
xmss_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
xmss_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
xmss_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
xmss_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
xmss_lib.o: ../../include/openssl/x509_vfy.h ../../include/openssl/xmss.h
xmss_lib.o: ../cryptlib.h xmss_lib.c
