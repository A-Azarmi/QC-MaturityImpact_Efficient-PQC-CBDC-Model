#
# OpenSSL/crypto/dilithium/Makefile
#

DIR=	dilithium
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
LIBSRC= dilithium_lib.c dilithium_asn1.c dilithium_err.c
LIBOBJ= dilithium_lib.o dilithium_asn1.o dilithium_err.o

SRC= $(LIBSRC)

EXHEADER= dilithium.h
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

dilithium_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
dilithium_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
dilithium_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dilithium_asn1.o: ../../include/openssl/dilithium.h
dilithium_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dilithium_asn1.o: ../../include/openssl/lhash.h
dilithium_asn1.o: ../../include/openssl/opensslconf.h
dilithium_asn1.o: ../../include/openssl/opensslv.h
dilithium_asn1.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
dilithium_asn1.o: ../../include/openssl/safestack.h
dilithium_asn1.o: ../../include/openssl/stack.h
dilithium_asn1.o: ../../include/openssl/symhacks.h ../cryptlib.h
dilithium_asn1.o: dilithium_asn1.c
dilithium_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
dilithium_err.o: ../../include/openssl/crypto.h
dilithium_err.o: ../../include/openssl/dilithium.h
dilithium_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
dilithium_err.o: ../../include/openssl/lhash.h
dilithium_err.o: ../../include/openssl/opensslconf.h
dilithium_err.o: ../../include/openssl/opensslv.h
dilithium_err.o: ../../include/openssl/ossl_typ.h
dilithium_err.o: ../../include/openssl/safestack.h
dilithium_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dilithium_err.o: dilithium_err.c
dilithium_lib.o: ../../e_os.h ../../include/openssl/asn1.h
dilithium_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
dilithium_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
dilithium_lib.o: ../../include/openssl/dilithium.h
dilithium_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
dilithium_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
dilithium_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
dilithium_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
dilithium_lib.o: ../../include/openssl/obj_mac.h
dilithium_lib.o: ../../include/openssl/objects.h
dilithium_lib.o: ../../include/openssl/opensslconf.h
dilithium_lib.o: ../../include/openssl/opensslv.h
dilithium_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
dilithium_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
dilithium_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
dilithium_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
dilithium_lib.o: ../cryptlib.h dilithium_lib.c
