Troubleshooting Overview
========================

This is the page, which describes troubleshooting aspects of the rtpengine project.

---

Debug memory leaks
------------------

A subject, which requires a special mentioning here is — catching of memory leaks.

_NOTE: There is a nice and elaborate video in this regard: https://www.youtube.com/watch?v=vVbWOKpIjjo_ \
_On that video you can see what needs to be done for a proper memory leaks debug, step by step._\
_Visually it can be more clear to go ahead with all of this stuff._

Almost each time, when a new feature is being introduced, it is covered with automated tests in the repository. The project itself (internally) is covered with ASAN tests, in order to spot memory leaks in time. So that, in case a new feature introduced a bad way of memory management, it would likely be noticed.

But, in order to make sure, that there are indeed no memory leaks introduced (by new feature / bug fix etc.), it’s possible to manually run the tests and see, if the binary during this launch consumed more memory, than it freed after all.

### Valgrind ###

For that to work, there is a possibility to use the valgrind.
It’s required to install that before to go further.

First, the binary must be compiled:
```
make
```

It will be stored in the daemon/ folder. Alternatively the package binary can be used, so indeed one doesn’t particularly need to compile the binary.

After the compilation is finished, there is a need to also compile the tests-preload.so, the sources of it are in the t/ folder:
```
cd t/
make tests-preload.so
```

And then, the command to launch rtpengine via the valgrind is as following:
```
LD_PRELOAD=../t/tests-preload.so G_SLICE=always-malloc valgrind --leak-check=full ./rtpengine --config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1 -n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1
```

The options to start it, are just copied from the `auto-daemon-tests.pl`.\
Launch of the binary is done from the daemon/ folder in this case.

Important thing is to always point the `G_SLICE=always-malloc` environment variable, this is because the project uses heavily the Glib (GSlice allocator) and valgrind doesn’t know how to deal with this. So that, by using this environment variable, Glib is told to use the system alloc for memory allocation and valgrind will be able to track this memory.

Other than that, the valgrind option `--leak-check=full` is also quite important thing to have, since it tells where exactly the memory leak is.

At this point rtpengine is up and running. It’s time to launch, in a separate terminal, tests themselves (those tests, which were prepared to cover a new feature, or just common tests, if there is no new feature and it was a bug fix).

For that to work, the option telling that rtpengine is already running, must be given:
```
RTPE_TEST_NO_LAUNCH=1 LD_PRELOAD=./tests-preload.so perl -I../perl auto-daemon-tests.pl
```

This has been launched from the t/ folder. And the ‘RTPE_TEST_NO_LAUNCH=1’ tells the auto tests that rtpengine is already running and there is no need to launch another one.

_NOTE: Alternatively it’s possible to run tests with any other way sending commands to rtpengine, to let it do some work in the concerned scope._

After tests are finished, it’s time to collect the report from the valgrind.\
Ctrl+C the terminal, where the binary has been launched before, and if there are no issues, the report must look something like that:
```
==978252== HEAP SUMMARY:
==978252==     in use at exit: 58,918 bytes in 335 blocks
==978252==   total heap usage: 23,833 allocs, 23,498 frees, 3,749,442 bytes allocated
==978252== 
==978252== LEAK SUMMARY:
==978252==    definitely lost: 0 bytes in 0 blocks
==978252==    indirectly lost: 0 bytes in 0 blocks
==978252==      possibly lost: 0 bytes in 0 blocks
==978252==    still reachable: 56,902 bytes in 314 blocks
==978252==         suppressed: 0 bytes in 0 blocks
==978252== Reachable blocks (those to which a pointer was found) are not shown.
==978252== To see them, rerun with: --leak-check=full --show-leak-kinds=all
==978252== 
==978252== Use --track-origins=yes to see where uninitialised values come from
==978252== For lists of detected and suppressed errors, rerun with: -s
==978252== ERROR SUMMARY: 9 errors from 1 contexts (suppressed: 0 from 0)
```

_NOTE: The downside of using valgrind is that the processing takes perceptibly more time. In other words, it works slower as without it. But since it’s not meant for a production usage, it’s quite alright (for example, for memory leak tests)._

_NOTE: Another important thing to remember, when running under the valgrind, is to make sure that the limits for the opened file descriptors is large enough. Unfortunately the valgrind on its own doesn’t take care of that, so one has to point it explicitly with: ulimit -n <size>. Usually the value of 30000 is enough, so: ulimit -n 30000_

Running one particular test under the valgrind.\
In case there is a demand to run only one of those auto-daemon-tests under the valgrind, it’s possible to do so, just by editing the auto-daemon-tests.pl (or any other targeted test file indeed).

This detailed way of running one test, gives a list of advantages:
* there is the rtpengine log file in the end (usually in the /tmp folder)
* less time waiting, till test is finished
* for debugging memory issues, one can exactly see amount of bytes left not freed for this particular test (so no other tests will contribute here with not freed memory). Hence simpler to find the place triggering this memory leak.

For that to work, one just needs to copy-past that particular test and place it at the top of the `auto-daemon-tests.pl`. Since this file is the main auto tests file, it will run first, and therefore the interest is to stop the test process as fast as possible, and run only this particular test. That is why this test will be copy-pasted here, at the top.

Then, after the definition of the test, it’s just required to place this row:
```
done_testing;NGCP::Rtpengine::AutoTest::terminate('f00');exit;
```

Which will tell the auto tests to stop running and generate a log file in the end. Furthermore, in a such way of running, it’s even possible to get the coredump. The folder for storing that will be selected according to defaults of the environment, where rtpengine was run. For example, in the Ubuntu 22.04, by default coredumps are being stored in the: `/var/lib/apport/coredump`

### Address Sanitizer ###

If the performance penalty introduced by the valgrind is not acceptable, it’s possible to use alternatively the Address Sanitizer (lib ASAN).

To work with that, it’s required to do a special compilation. So that it’s not possible to work with a package binary (some particular flags will be needed to be set during the compilation).

Apart of that, it can be a bit tricky to run it, depending on the distribution one uses. Older distributions will likely not be a working scenario for that, that is because the relatively recent GCC version/Clang is required.

There is a list of different things, which can be done with help of lib ASAN, hence the compilation will be different depending on needs.

It’s worth mentioning, that build environment must be clean, it’s a must.\
So make sure to clean it beforehand:
```
git clean -fxd
```

There is one particular thing to be mentioned, it’s a make target dedicated for the asan checks (see Makefile in the project’s root folder):
```
asan-check:
        DO_ASAN_FLAGS=1 $(MAKE) check
```

This target is meant to run the build in tests. But in the end, this can be just used as an example how to create a build with the libasan included, for that one just needs to use the ‘DO_ASAN_FLAGS=1’ while doing the compilation:
```
DO_ASAN_FLAGS=1 make
```

which will give the binary with the libasan included.\
And now, after the compilation is finished, it possible to use this binary as usually, so without a need for a valgrind.

_NOTE: Remember, the approach with the valgrind and the one with the libasan are mutually exclusive._

Now there are a few run-time flags, which need to be exported to the environment before to proceed:
```
export ASAN_OPTIONS=verify_asan_link_order=0
export UBSAN_OPTIONS=print_stacktrace=1
export G_SLICE=always-malloc
```

And now it’s time to run the binary again, but this time without the valgrind, like so:
```
LD_PRELOAD=../t/tests-preload.so ./rtpengine --config-file=none -t -1 -i 203.0.113.1 -i 2001:db8:4321::1 -n 2223 -c 12345 -f -L 7 -E -u 2222 --silence-detect=1 
```

Of course the debug with the Address Sanitizer is not that comprehensive, as the run with the valgrind (it doesn’t detect as many thing as valgrind does). But it’s definitely faster in terms of processing. Now after running certain amount of tests and terminating the run of the binary with Ctrl+C, you can have a report telling whether or not some of the allocated bytes remained not freed.

Now getting back to the asan-check build target, let’s run this:
```
git clean -fxd
make asan-check
```

It will run a compilation with the libasan included and then just runs all the built-in unit tests using the gotten binary. And, if the memory leak issues can be captured by one of those unit tests, it will be reported as NOK test.

To remind again, the libasan will not tell the exact place in the code, which contributes with the memory not being freed. And if a particular test reproduces this issue, then it’s possible just to re-run that very test under the valgrind to get a detailed information on that. For that to work, just get back to the previous section to see how this can be done.
