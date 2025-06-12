---
sidebar_position: 2
description: Building STMicroelectronics/OpenOCD
---

# OpenOCD

**STM32H5** does not work with the original OpenOCD.
Currently, it only works with the STMicroelectronics' fork [STMicroelectronics/OpenOCD],
which has to be built from source.

In this guide, we describe how to do that.

Tested with revision [0de861e21c12fd39fdce7b6296994d89eca6146f] on macOS Big Sur 11.7.10

Follow [Building OpenOCD instructions] in README (starting from line 196).
Make sure you install all the required dependencies.

Here is a summary of the relevant dependencies:

- GCC or Clang
- make
- libtool
- pkg-config >= 0.23 or pkgconf
- autoconf >= 2.69
- automake >= 1.14
- texinfo >= 5.0
- libusb-1.0

On macOS, you can install them using brew:

```bash
brew install libtool pkgconf autoconf automake texinfo libusb
```

<details>

<summary>Expand to see the exact dependencies when I successfully built it on macOS.</summary>

macOS Big Sur 11.7.10

- system Clang (Apple clang version 13.0.0 (clang-1300.0.29.30))
  - system make (GNU Make 3.81)
  - dependencies installed via brew:
    - libtool 2.4.7
    - pkgconf 2.3.0_1
    - autoconf 2.72
    - automake 1.17
    - texinfo 7.2
    - libusb 1.0.26

</details>

Once you have all the required dependencies, proceed with building STMicroelectronics/OpenOCD.
To avoid the need for `sudo make install` and to avoid overwriting existing OpenOCD installation,
we will use an installation prefix (via `./configure --prefix`). Note that the prefix passed to the configure script
must be an absolute path.

```bash
mkdir stm-openocd-install
CUSTOM_PREFIX="$PWD/stm-openocd-install"
git clone https://github.com/STMicroelectronics/OpenOCD.git stm-openocd
cd stm-openocd
./bootstrap
./configure --prefix "$CUSTOM_PREFIX"
make
make install
$CUSTOM_PREFIX/bin/openocd --version
# should print something like this: Open On-Chip Debugger 0.12.0-00033-g0de861e21 (2025-03-13-02:03) [https://github.com/STMicroelectronics/OpenOCD]
# Note: The "g0de861e21" suffix (formatted as "g<rev>") indicates the git commit revision hash of the OpenOCD repo.
```

[STMicroelectronics/OpenOCD]: https://github.com/STMicroelectronics/OpenOCD
[0de861e21c12fd39fdce7b6296994d89eca6146f]: https://github.com/STMicroelectronics/OpenOCD/commit/0de861e21c12fd39fdce7b6296994d89eca6146f
[Building OpenOCD instructions]: https://github.com/STMicroelectronics/OpenOCD/blob/openocd-cubeide-r6/README#L196
