# broadcom wl driver with fixed monitor mode support

> This is a source mirror for the broadcom wl driver version 6.30.223.141 with fixed monitor mode

***

**Author:** Timo Furrer <tuxtimo@gmail.com>

## Installation

1. Compile kernel module:

```bash
make
```

2. Testing driver

```bash
insmod ./wl.ko
```

*Note: you may have to unload the currently loaded wl driver with `rmmod wl`.*

3. Enable monitor mode

```bash
bash -c "echo 1 > /proc/brcm_monitor0"
```

Now you should have an interface called `prism0` in monitor mode.
