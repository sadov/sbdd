# Simple Block Device and Proxy Block Device Drivers
Implementation of Linux Kernel 5.4.X simple block device and proxy block device drivers.

## Build
- regular:
`$ make`
- with requests debug info:
uncomment `CFLAGS_sbdd.o := -DDEBUG` in `Kbuild`

## Clean
`$ make clean`

## Test
`$ make test`

## References
- [Linux Device Drivers](https://lwn.net/Kernel/LDD3/)
- [Linux Kernel Development](https://rlove.org)
- [Linux Kernel Teaching](https://linux-kernel-labs.github.io/refs/heads/master/labs/block_device_drivers.html)
- [Linux Kernel Sources](https://github.com/torvalds/linux)
