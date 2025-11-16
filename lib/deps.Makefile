# Define build flags for used dependencies.

$(top_srcdir)/config.mk: $(top_srcdir)/utils/gen-common-flags \
		$(top_srcdir)/utils/gen-bcg729-flags \
		$(top_srcdir)/utils/gen-codec-chain-flags
	$(top_srcdir)/utils/gen-common-flags >$@.new
ifeq (,$(filter pkg.ngcp-rtpengine.nobcg729,${DEB_BUILD_PROFILES}))
	$(top_srcdir)/utils/gen-bcg729-flags >>$@.new
endif
ifneq (,$(filter pkg.ngcp-rtpengine.codec-chain,${DEB_BUILD_PROFILES}))
	$(top_srcdir)/utils/gen-codec-chain-flags >>$@.new
endif
	mv $@.new $@

include $(top_srcdir)/config.mk
