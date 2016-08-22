#
# Make ftls-* for several configurations
#   make            -> ftls-afl     (32bit) for afl
#   make EXT=gcov   -> ftls-gcov    (32 bit) for coverage checks
#   make EXT=noafl  -> ftls-noafl   (32 bit) built normally
#   make EXT=afl64  -> ftls-afl64   with afl, built for 64bit
#
# note: make clean when changing targets!
#

OSSLSRC=../../
OSSLLIB=../../
AFL=./afl

CC=clang
CFLAGS= -pthread -Wall -I$(OSSLSRC)/include -I$(OSSLSRC) -fsanitize=address
LIBS= $(OSSLLIB)/libssl.a $(OSSLLIB)/libcrypto.a  -ldl

# note: see http://security.stackexchange.com/questions/6965/how-should-i-compile-program-for-fuzz-testing
# and http://gcc.gnu.org/wiki/Mudflap_Pointer_Debugging
CFLAGS += -g -O0
CFLAGS += -fstack-protector-all
#CFLAGS += -D_FORTIFY_SOURCE
#CFLAGS += -fmudflap
#LDFLAGS += -lmudflap

ifeq (,$(findstring noafl,$(EXT)))   # unless noafl, use AFL's compiler
CC= $(AFL)/afl-clang
endif

ifneq (,$(findstring 32,$(EXT)))   # use -m32 unless we're a 64bit build
CFLAGS += -m32
endif

ifneq (,$(findstring gcov,$(EXT))) # set gcov flags
CFLAGS += -fprofile-arcs -ftest-coverage
endif

ifneq ("$(wildcard afl/))","")
AFL_EXISTS = 1
else
AFL_EXISTS = 0
endif

check : 
ifeq ($(EXT),)
	@echo "Run 'make all'"
	exit
endif

default : ftls-$(EXT)

ftls-$(EXT) : check ftls.o
	$(CC) $(CFLAGS) -o $@ ftls.o $(LIBS)

all : 
ifneq ($(wildcard $(AFL)),)
	for e in afl afl32 gcov noafl ; do EXT=$$e make clean ftls-$$e; done
else
	@echo "Download AFL and place the compiled source in afl/"
endif


clean : # does not clean the target binary
	rm -f *.o 
cleanbin : clean
	for e in afl afl32 gcov noafl ; do rm -f ftls-$$e; done
	rm -f ftls.gcno
	rm -f ftls
	rm -f *.pem
	rm -f *.srl
	rm -f srppw*
	rm -fr inputs
