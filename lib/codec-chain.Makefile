ifneq (,$(filter pkg.ngcp-rtpengine.codec-chain,${DEB_BUILD_PROFILES}))
ifneq (,$(wildcard $(CODEC_CHAIN_HOME)/usr/include/codec-chain/client.h))
CFLAGS+=	-DHAVE_CODEC_CHAIN -I$(CODEC_CHAIN_HOME)/usr/include
else ifneq (,$(wildcard /usr/include/codec-chain/client.h))
CFLAGS+=	-DHAVE_CODEC_CHAIN
endif
endif
