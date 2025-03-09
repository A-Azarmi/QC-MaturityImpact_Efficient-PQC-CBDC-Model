#
# OpenSSL/crypto/sphincs/Makefile
#

DIR=	sphincs
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
LIBSRC= sphincs_lib.c sphincs_asn1.c sphincs_err.c
LIBOBJ= sphincs_lib.o sphincs_asn1.o sphincs_err.o

SRC= $(LIBSRC)

EXHEADER= sphincs.h
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

sphincs_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
sphincs_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
sphincs_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
sphincs_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
sphincs_asn1.o: ../../include/openssl/lhash.h
sphincs_asn1.o: ../../include/openssl/opensslconf.h
sphincs_asn1.o: ../../include/openssl/opensslv.h
sphincs_asn1.o: ../../include/openssl/ossl_typ.h ../../include/openssl/rand.h
sphincs_asn1.o: ../../include/openssl/safestack.h
sphincs_asn1.o: ../../include/openssl/sphincs.h ../../include/openssl/stack.h
sphincs_asn1.o: ../../include/openssl/symhacks.h ../cryptlib.h sphincs_asn1.c
sphincs_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sphincs_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sphincs_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
sphincs_err.o: ../../include/openssl/opensslconf.h
sphincs_err.o: ../../include/openssl/opensslv.h
sphincs_err.o: ../../include/openssl/ossl_typ.h
sphincs_err.o: ../../include/openssl/safestack.h
sphincs_err.o: ../../include/openssl/sphincs.h ../../include/openssl/stack.h
sphincs_err.o: ../../include/openssl/symhacks.h sphincs_err.c
sphincs_lib.o: ../../e_os.h ../../include/openssl/asn1.h
sphincs_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
sphincs_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
sphincs_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
sphincs_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
sphincs_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
sphincs_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
sphincs_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
sphincs_lib.o: ../../include/openssl/opensslconf.h
sphincs_lib.o: ../../include/openssl/opensslv.h
sphincs_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
sphincs_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
sphincs_lib.o: ../../include/openssl/sphincs.h ../../include/openssl/stack.h
sphincs_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
sphincs_lib.o: ../../include/openssl/x509_vfy.h ../cryptlib.h sphincs_lib.c
