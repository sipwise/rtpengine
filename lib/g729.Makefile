ifeq (,$(filter pkg.ngcp-rtpengine.nobcg729,${DEB_BUILD_PROFILES}))
# look for bcg729
# system pkg-config
have_bcg729 := $(shell pkg-config --exists libbcg729 && echo yes)
ifeq ($(have_bcg729),yes)
bcg729_inc := $(shell pkg-config --cflags libbcg729)
bcg729_lib := $(shell pkg-config --libs libbcg729)
else
# system generic
ifneq (,$(wildcard /usr/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_lib := -lbcg729
else
# /usr/src
ifneq (,$(wildcard /usr/src/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I/usr/src/bcg729/include/
bcg729_lib := -L/usr/src/bcg729/src/ -lbcg729
else
# rfuchs dev
ifneq (,$(wildcard $(HOME)/src/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I$(HOME)/src/bcg729/include/
bcg729_lib := -L$(HOME)/src/bcg729/src/ -lbcg729
else
# home directory
ifneq (,$(wildcard $(HOME)/bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I$(HOME)/bcg729/include/
bcg729_lib := -L$(HOME)/bcg729/src/ -lbcg729
else
# included toplevel
ifneq (,$(wildcard ../bcg729/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I../bcg729/include/
bcg729_lib := -L../bcg729/src/ -lbcg729
else
# /usr/local/include when installing from git
ifneq (,$(wildcard /usr/local/include/bcg729/decoder.h))
have_bcg729 := yes
bcg729_inc := -I/usr/local/include/
bcg729_lib := -L/usr/local/lib64/ -lbcg729
endif
endif
endif
endif
endif
endif
endif
endif

ifeq ($(have_bcg729),yes)
CFLAGS+=	-DHAVE_BCG729
CFLAGS+=	$(bcg729_inc)
endif
ifeq ($(have_bcg729),yes)
LDLIBS+=	$(bcg729_lib)
endif
