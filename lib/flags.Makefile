with_transcoding ?= yes
CODEC_SRCS :=

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
CODEC_SRCS += g711.c g723.c g722.c qcelp.c g729.c speex.c gsm.c ilbc.strhash.c opus.strhash.c
CODEC_SRCS += evs.strhash.c vorbis.c ac3.c atrac.c evrc.c amr.strhash.c pseudo.c
CODEC_SRCS += g726.c l16.c u8.c mp3.c
endif

LDFLAGS += -pie

LDLIBS := -lm -ldl -latomic
