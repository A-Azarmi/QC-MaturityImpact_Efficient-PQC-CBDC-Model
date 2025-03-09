#
# OpenSSL/crypto/ntrup/Makefile
#

DIR=	ntrup
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
LIBSRC= ntrup_lib.c ntrup_asn1.c ntrup_err.c
LIBOBJ= ntrup_lib.o ntrup_asn1.o ntrup_err.o

SRC= $(LIBSRC)

EXHEADER= ntrup.h
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

ntrup_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
ntrup_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
ntrup_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
ntrup_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
ntrup_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/ntrup.h
ntrup_asn1.o: ../../include/openssl/opensslconf.h
ntrup_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ntrup_asn1.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
ntrup_asn1.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ntrup_asn1.o: ../cryptlib.h ntrup_asn1.c
ntrup_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ntrup_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ntrup_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
ntrup_err.o: ../../include/openssl/ntrup.h ../../include/openssl/opensslconf.h
ntrup_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ntrup_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
ntrup_err.o: ../../include/openssl/symhacks.h ntrup_err.c
ntrup_lib.o: ../../e_os.h ../../include/openssl/asn1.h
ntrup_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
ntrup_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
ntrup_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ntrup_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ntrup_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
ntrup_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
ntrup_lib.o: ../../include/openssl/ntrup.h ../../include/openssl/obj_mac.h
ntrup_lib.o: ../../include/openssl/objects.h
ntrup_lib.o: ../../include/openssl/opensslconf.h
ntrup_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ntrup_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ntrup_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
ntrup_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ntrup_lib.o: ../../include/openssl/x509_vfy.h ../cryptlib.h ntrup_lib.c
