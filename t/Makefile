RESULTS ?= reports

# run this in parallel!! -j is your friend
all: fake_check

build-env: .build-env-done

.build-env-done:
	mk-build-deps -i -r -t 'apt-get --no-install-recommends --assume-yes' \
		../debian/control
	touch $(@)

test-env: build-env .test-env-done

.test-env-done: build-env
	cd .. && MAKEFLAGS= dpkg-buildpackage -j1
	dpkg -i ../../ngcp-rtpengine-daemon_*.deb
	rm -f ../../ngcp-rtpengine*.{deb,dsc,tar.gz,changes}
	touch $(@)

fake_check: fake_check.py test-env
	which rtpengine
	mkdir -p $(RESULTS)
	./$(<) > ${RESULTS}/$(@).xml

clean:
	rm -rf $(RESULTS)
