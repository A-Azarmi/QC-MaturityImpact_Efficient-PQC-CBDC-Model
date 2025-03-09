#
# OpenSSL/crypto/frodokem/Makefile
#

DIR=	frodokem
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
LIBSRC= frodokem_lib.c frodokem_asn1.c frodokem_err.c
LIBOBJ= frodokem_lib.o frodokem_asn1.o frodokem_err.o

SRC= $(LIBSRC)

EXHEADER= frodokem.h
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

frodokem_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
frodokem_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
frodokem_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
frodokem_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
frodokem_asn1.o: ../../include/openssl/frodokem.h ../../include/openssl/lhash.h
frodokem_asn1.o: ../../include/openssl/opensslconf.h
frodokem_asn1.o: ../../include/openssl/opensslv.h
frodokem_asn1.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
frodokem_asn1.o: ../../include/openssl/safestack.h
frodokem_asn1.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
frodokem_asn1.o: ../cryptlib.h frodokem_asn1.c
frodokem_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
frodokem_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
frodokem_err.o: ../../include/openssl/err.h ../../include/openssl/frodokem.h
frodokem_err.o: ../../include/openssl/lhash.h
frodokem_err.o: ../../include/openssl/opensslconf.h
frodokem_err.o: ../../include/openssl/opensslv.h
frodokem_err.o: ../../include/openssl/ossl_typ.h
frodokem_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
frodokem_err.o: ../../include/openssl/symhacks.h frodokem_err.c
frodokem_lib.o: ../../e_os.h ../../include/openssl/asn1.h
frodokem_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
frodokem_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
frodokem_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
frodokem_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
frodokem_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
frodokem_lib.o: ../../include/openssl/evp.h ../../include/openssl/frodokem.h
frodokem_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
frodokem_lib.o: ../../include/openssl/objects.h
frodokem_lib.o: ../../include/openssl/opensslconf.h
frodokem_lib.o: ../../include/openssl/opensslv.h
frodokem_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
frodokem_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
frodokem_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
frodokem_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
frodokem_lib.o: ../cryptlib.h frodokem_lib.c
