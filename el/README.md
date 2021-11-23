rtpengine for Enterprise Linux
==================================

Installing from RPMs
--------------------

There are four RPMs:

- *ngcp-rtpengine*: the userspace daemon
- *ngcp-rtpengine-recording*: the recording daemon
- *ngcp-rtpengine-kernel*: the iptables plugin
- *ngcp-rtpengine-dkms*: the kernel module source

All of the RPMs have correctly set dependencies and if you just want the
userspace daemon you can install it with yum (assuming you have access to a repository).

The *ngcp-rtpengine-kernel* package is dependent on the
*ngcp-rtpengine*, and *ngcp-rtpengine-dkms* packages. The
*ngcp-rtpengine-dkms* package has a dependency (DKMS) that cannot be met
by the base repository. If you want to use in-kernel forwarding you
need to add the [*EPEL*](http://fedoraproject.org/wiki/EPEL) repository and
install the *dkms* package before attempting to install
*ngcp-rtpengine-dkms* or *ngcp-rtpengine-kernel*.

Note: installing *ngcp-rtpengine-dkms* builds a kernel module which requires
the sources for the running kernel. The *kernel-devel* and *kernel-headers*
packages are meta-packages that install the headers and source for the latest
kernel version. This will be what you want unless you are running a custom
or older kernel. *ngcp-rtpengine-dkms* does not have *kernel-devel* and
*kernel-headers* as dependencies as this could cause problems if you are using
a custom or older kernel, so you need to install these manually.


RPM Compilation
---------------

To build the RPMs you need all of the packages listed in the Manual Compilation
section (except for *kernel-devel* and *kernel-headers*) plus:

- *redhat-rpm-config*
- *rpm-build*

To build the RPMs:
- Checkout (clone) the Git repository
- Create the `~/rpmbuild/SOURCES` directory
- Create a tar archive.  For example, from within the cloned directory you can
  use
  `git archive --output ~/rpmbuild/SOURCES/ngcp-rtpengine-<version number>.tar.gz --prefix=ngcp-rtpengine-<version number>/ master`
  where `<version number>` is the version number of the master branch
- Build the RPMs. For example,
   `rpmbuild -ta ~/rpmbuild/SOURCES/ngcp-rtpengine-<version number>.tar.gz`

Once the build has completed the binary RPMs will be in `~/rpmbuild/RPMS`.


Manual Compilation
------------------

Check the main project README.
