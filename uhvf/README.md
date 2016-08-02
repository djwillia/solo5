This is the beginning of a port of ukvm to Hypervisor.framework on
MacOSX, so that Solo5/Mirage-based unikernels can run natively on that
system.  The goal is for ukvm to end up with both a KVM-based bottom
half and Hypervisor.framework-based bottom half, whereas the top half
is shared.

Solo5 doesn't build properly in OSX yet (although @hannesm has done a
bunch of work to make it build on FreeBSD, so I don't think it's far
off), so I build using Docker for Mac with a simple build container:

    docker run --rm -v "$PWD:/src" solo5-make

At the moment, it boots the unikernel, but stops at the PVCLOCK stuff,
as that is a KVM abstraction.
