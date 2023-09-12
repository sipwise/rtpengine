ifneq (,$(filter pkg.ngcp-rtpengine.cudecs,${DEB_BUILD_PROFILES}))
ifneq (,$(wildcard $(CUDECS_HOME)/usr/include/cudecs/g711opus.h))
CFLAGS+=	-DHAVE_CUDECS -I$(CUDECS_HOME)/usr/include
LDLIBS+=	-L$(CUDECS_HOME)/usr/lib -lcudecs
else ifneq (,$(wildcard /usr/include/cudecs/g711opus.h))
CFLAGS+=	-DHAVE_CUDECS
LDLIBS+=	-lcudecs
endif
endif
