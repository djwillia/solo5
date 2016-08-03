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


- It looks like the PVCLOCK can be completely removed from the ukvm
  parts of Solo5, as long as we change the poll hypercall to send the
  `until_nsecs` directly

- All interrupt handlers can be removed from the solo5 parts of ukvm
  because we get to see what exception happened in uhvf

- HLT isn't exiting (it looks like my Macbook VMX does not expose that
  capability), so we'll probably need a HLT hypercall.

  


