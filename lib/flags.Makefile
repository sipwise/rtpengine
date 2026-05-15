with_transcoding ?= yes

ifeq ($(origin CFLAGS),undefined)
CFLAGS := -g -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter -Wstrict-prototypes -Werror=return-type \
		-Wshadow
else
CFLAGS := $(CFLAGS)
endif

CFLAGS += -I. -I$(top_srcdir)/kernel-module/ -I$(top_srcdir)/lib/
CFLAGS += -pthread
CFLAGS += -std=c11
CFLAGS += -D_GNU_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE
CFLAGS += -fPIE

ifeq ($(with_transcoding),yes)
CFLAGS += -DWITH_TRANSCODING
endif

LDFLAGS += -pie

LDLIBS := -lm -ldl -latomic
