# Stealthy memory R/W driver

This is a rather basic but effective driver that can be used to read from and write to memory of an arbitrary possibly protected process from a user mode process. I created it to bypass anti-cheat system for various games and loaded it into the kernel with kdmapper. It covers it traces and communicates with a user mode client through shared memory inside that client. The client can then use the driver to read from and write to memory of an arbitrary process without any of the restrictions and difficulties imposed by user-mode cheats. It leaves a minimal trace in the systems kernel since it does not register any handles for communication and no callbacks which would usually be used to execute routines in a driver. Instead it hooks a function inside a legitimate official kernel module which is regularly called in small intervals. This hook is then used to check whether the client requested new memory operations. This makes it really hard for anti-cheat system to detect the driver and has never failed me so far.  The project is likely outdated by now but feel free to use it as an inspiration.