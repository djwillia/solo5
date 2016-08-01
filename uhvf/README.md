This is the beginning of a port of ukvm to Hypervisor.framework on
MacOSX, so that Solo5/Mirage-based unikernels can run natively on that
system.  The goal is for ukvm to end up with both a KVM-based bottom
half and Hypervisor.framework-based bottom half, whereas the top half
is shared.
