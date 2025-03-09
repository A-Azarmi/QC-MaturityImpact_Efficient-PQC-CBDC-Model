#
# OpenSSL/crypto/sike/Makefile
#

DIR=	sike
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
LIBSRC= sike_lib.c sike_asn1.c sike_err.c
LIBOBJ= sike_lib.o sike_asn1.o sike_err.o

SRC= $(LIBSRC)

EXHEADER= sike.h
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

sike_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
sike_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
sike_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
sike_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
sike_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
sike_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sike_asn1.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
sike_asn1.o: ../../include/openssl/sike.h ../../include/openssl/stack.h
sike_asn1.o: ../../include/openssl/symhacks.h ../cryptlib.h sike_asn1.c
sike_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sike_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sike_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
sike_err.o: ../../include/openssl/opensslconf.h
sike_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sike_err.o: ../../include/openssl/safestack.h ../../include/openssl/sike.h
sike_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sike_err.o: sike_err.c
sike_lib.o: ../../e_os.h ../../include/openssl/asn1.h
sike_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
sike_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
sike_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
sike_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
sike_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
sike_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
sike_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
sike_lib.o: ../../include/openssl/opensslconf.h
sike_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sike_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
sike_lib.o: ../../include/openssl/sha.h ../../include/openssl/sike.h
sike_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sike_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
sike_lib.o: ../cryptlib.h sike_lib.c
