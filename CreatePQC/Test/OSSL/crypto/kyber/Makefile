#
# OpenSSL/crypto/kyber/Makefile
#

DIR=	kyber
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
LIBSRC= kyber_lib.c kyber_asn1.c kyber_err.c
LIBOBJ= kyber_lib.o kyber_asn1.o kyber_err.o

SRC= $(LIBSRC)

EXHEADER= kyber.h
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

kyber_asn1.o: ../../e_os.h ../../include/openssl/asn1.h
kyber_asn1.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
kyber_asn1.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
kyber_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
kyber_asn1.o: ../../include/openssl/kyber.h ../../include/openssl/lhash.h
kyber_asn1.o: ../../include/openssl/opensslconf.h
kyber_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kyber_asn1.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
kyber_asn1.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
kyber_asn1.o: ../cryptlib.h kyber_asn1.c
kyber_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
kyber_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kyber_err.o: ../../include/openssl/err.h ../../include/openssl/kyber.h
kyber_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
kyber_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kyber_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
kyber_err.o: ../../include/openssl/symhacks.h kyber_err.c
kyber_lib.o: ../../e_os.h ../../include/openssl/asn1.h
kyber_lib.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
kyber_lib.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
kyber_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
kyber_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
kyber_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
kyber_lib.o: ../../include/openssl/evp.h ../../include/openssl/kyber.h
kyber_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
kyber_lib.o: ../../include/openssl/objects.h
kyber_lib.o: ../../include/openssl/opensslconf.h
kyber_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kyber_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
kyber_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
kyber_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
kyber_lib.o: ../../include/openssl/x509_vfy.h ../cryptlib.h kyber_lib.c
