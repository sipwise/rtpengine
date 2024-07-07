Unit-tests
==========

This is the page, which describes how to prepare unit tests for newly introduced features in rtpengine.

---

Adding of new tests is a required procedure, which allows us to cover fixes/changes/feature being added into rtpengine.\
They make sure, that:
* first, new changes being added are reflecting the intention of these change, and hence give expected results
* second, they will make sure, that this expected behavior (in this very scope) won’t get broken in the future, by newer changes. And even if, we will notice that and will make sure to fix it.

The main folder, as regularly, is: `t/` \
Here there is a bunch of files written in Perl, Python and C, dedicated for different kind of tests.

_NOTE: They are being run with `make check` and during packaging._
_Nevertheless, not everything in that directory is actually run as part of `make check` (some are for manual testing)._

These tests actually spawn a real rtpengine process in a fake network environment (see `tests-preload.c` and its invocation in the `makefile`, and also the command-line options given at the start of each of these scripts) and then facilitate real SDP offer/answer exchanges and test real RTP forwarding against it.

This is the closest possible way to simulate real SIP calls. The code supporting these tests is written using a few Perl libraries stored in `perl/` folder of the project, which are able to do the signalling, SRTP, ICE, etc.

Most importantly, there are some unit tests (e.g. `aead-aes-crypt` or `test-transcode`), but the most comprehensive test scripts are the ones called `auto-daemon-tests`.

Let’s take as an example the: `auto-daemon-tests.pl` \
This one has a huge amount of basic tests related to mostly general things rtpengine does.

Let’s have a look into one of the tests, in this case ‘SDP version force increase':

```
new_call;

# there is no 'monologue->last_out_sdp', but the version still gets increased
offer('SDP version force increase', { replace => ['force-increment-sdp-ver'] }, <<SDP);
v=0
o=- 1545997027 1 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# there is 'monologue->last_out_sdp' and it's equal to the newly given SDP,
# but the version still gets increased
offer('SDP version force increase', { replace => ['force-increment-sdp-ver'] }, <<SDP);
v=0
o=- 1545997027 2 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2000 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 3 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP

# there is 'monologue->last_out_sdp' and it's not equal to the newly given SDP,
# and the version gets increased, as if that would be increased with 'sdp-version'.
offer('SDP version force increase', { replace => ['force-increment-sdp-ver'] }, <<SDP);
v=0
o=- 1545997027 3 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio 2002 RTP/AVP 0
c=IN IP4 198.51.100.1
----------------------------
v=0
o=- 1545997027 4 IN IP4 198.51.100.1
s=tester
t=0 0
m=audio PORT RTP/AVP 0
c=IN IP4 203.0.113.1
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp:PORT
SDP
```

It is dedicated to check, whether under any possible conditions, the flag `force-increment-sdp-ver` (when calling the `rtpengine_offer()`), will increase the sessions version of this SDP.

The syntax here is:
* `new_call;` - start a new test procedure, kinda new call
* `'SDP version force increase'` - is a test’s name
* `replace => ['force-increment-sdp-ver']` - is a given flag (emulates as if we would add this flag, when calling the `rtpengine_offer()`)
* first instance of the SDP (so before `----------------------------`) - is what we hand to rtpengine
* second instance after that, is what we expect rtpengine to generate for us (as result)
* `SDP` - is an end of given SDPs for this sub-test

_NOTE: Every new test (new_call) can have many sub-tests included. So you can wrap into that something within one big scope, such as tests related to the SDP session version._

Generally said, if there is a new thing/feature being added into rtpengine, and this can potentially  affect the behavior (even under some really specific circumstances), it’s important to cover this change with tests. For example: to emulate the call with a newly given flag and see that the expected results is given.

_NOTE: run `make daemon-tests-main` inside of `/t` can be used to run the tests manually._

Individually the unit tests can be executed normally, but the `auto-daemon-tests` need special instrumentation. Either use `make daemon-tests-X` from within `t/`, or if there is a need to execute the test script manually and separately from rtpengine:
* Make sure `tests-preload.so` exists (`make -C t tests-preload.so`)
* In one shell: `LD_PRELOAD=t/tests-preload.so daemon/rtpengine --config-file=none -t -1 -i 203.0.113.1 ...` (CLI options taken from respective test script)
* In another shell: `LD_PRELOAD=t/tests-preload.so RTPE_TEST_NO_LAUNCH=1 perl -Iperl t/auto-daemon-tests.pl`

This even works with rtpengine running under a debugger or valgrind.

Another set of tests that is included is to run all of the `make check` tests under libasan. The top-level `make asan-check` target exists for that purpose and requires an initially clean source directory to execute properly.
