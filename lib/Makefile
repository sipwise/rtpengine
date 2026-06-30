export top_srcdir = ..

include ../lib/deps.Makefile

include ../lib/flags.Makefile

CFLAGS += $(CFLAGS_GLIB)
CFLAGS += $(CFLAGS_JSON_GLIB)
CFLAGS += $(CFLAGS_LIBPCRE)
ifeq ($(with_transcoding),yes)
CFLAGS += $(CFLAGS_OPUS)
endif

SRCS := auxlib.c bencode.c bufferpool.c codeclib.c dtmflib.c
SRCS += http.c loglib.c mix_buffer.c
SRCS += netfilter_api.c oauth.c poller.c resample.c
SRCS += rtplib.c s3utils.c socket.c
SRCS += ssllib.c str.c streambuf.c uring.c

ASM := mix_in_x64_avx2.S mix_in_x64_avx512bw.S mix_in_x64_sse2.S mvr2s_x64_avx2.S mvr2s_x64_avx512.S

include common.Makefile

all: $(OBJS)
