This is the beginning of a port of ukvm to Hypervisor.framework on
MacOSX, so that Solo5/Mirage-based unikernels can run natively on that
system.  The goal is for ukvm to end up with both a KVM-based bottom
half and Hypervisor.framework-based bottom half, whereas the top half
is shared.

Solo5 doesn't build properly in OSX yet (although @hannesm has done a
bunch of work to make it build on FreeBSD, so I don't think it's far
off), so I build using Docker for Mac with a simple build container. I
also use containers to build Mirage unikernels.  See
https://github.com/djwillia/dockerfiles.

At the moment, uhvf can do the Solo5 hello test and ping_serve test
and also run the Mirage console and stackv4 test (from
mirage-skeleton).  Things left to do:

- need to implement other modules: blk, gdb (is it finished?)

- KVM doesn't allow a trap on `rdtsc` but it should if we want to use
  the same interface for ukvm and uhvf (for e.g., det replay).  

- `uhvf.c` and `ukvm-core.c` share a bunch of code; there should be a
  common part and a platform specific part at some point.  The same
  is true for the modules (e.g., `ukvm-net.c` and `uhvf-net.c`).

For networking, I'm using the `vmnet` framework.  We can test ping by
running the test_ping_serve unikernel:

    sudo ./uhvf ../tests/test_ping_serve/test_ping_serve.ukvm

And configure the host to know how to ping it like this (also in
`net-setup.bash`):

    BRIDGE=`ifconfig -l |grep -o bridge[0-9]* |tail -n 1`
    IF=`ifconfig -l |grep -o en[0-9]* |tail -n 1`
    sudo ifconfig $BRIDGE 10.0.0.1/24 -hostfilter $IF

Then:

    ping 10.0.0.2

Older notes:

- It looks like the PVCLOCK can be completely removed from the ukvm
  parts of Solo5, as long as we change the poll hypercall to send the
  `until_nsecs` directly

- All interrupt handlers can be removed from the solo5 parts of ukvm
  because we get to see what exception happened in uhvf





