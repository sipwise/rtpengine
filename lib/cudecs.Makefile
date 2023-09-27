ifneq (,$(filter pkg.ngcp-rtpengine.cudecs,${DEB_BUILD_PROFILES}))
ifneq (,$(wildcard $(CUDECS_HOME)/usr/include/cudecs/g711opus.h))
CFLAGS+=	-DHAVE_CUDECS -I$(CUDECS_HOME)/usr/include
else ifneq (,$(wildcard /usr/include/cudecs/g711opus.h))
CFLAGS+=	-DHAVE_CUDECS
endif
endif
