<p align="center"><img src="./docs/assets/img/lionkey-logo-v2-no-padding.svg" title="LionKey" alt="LionKey logo" height="100"></p>

# LionKey: An open-source FIDO2 USB Security Key

[![build status](https://img.shields.io/github/actions/workflow/status/pokusew/lionkey/ci.yml?logo=github)](https://github.com/pokusew/lionkey/actions/workflows/ci.yml)

A working [FIDO2]/[WebAuthn] USB hardware external authenticator (also called “security key”) 🔑
implemented on STM32H533.

In terms of [WebAuthn], **LionKey** is a _roaming authenticator_ with _cross-platform attachment_
using CTAP 2.1 over USB 2.0 (CTAPHID) as the communication protocol,
supporting _user verification_ using PIN (CTAP2 ClientPIN),
and capable of storing **passkeys** _(client-side discoverable credentials)_.

Key features:
* **Fully compliant implementation of [CTAP 2.1].**
  * Implements all mandatory features.
  * Written in **C**.
  * No dynamic memory allocations.
  * Designed for use in resource-constrained environments.
  * MCU independent, easily portable, can be used as a library (see the [core](./core) dir).
  * Just a single external dependency ([TinyCBOR]).
* Running on the **[NUCLEO-H533RE]** board with the **[STM32H533RET6]** MCU.
* Uses [STM32CubeH5](#stm32cubeH5).
* **Hardware-accelerated cryptography** on STM32H533 (using the RNG, PKA, AES, SHA peripherals).

> [!WARNING]  
> 🚧 This is still a work in progress. **The security key is already usable.**
> More detailed documentation will be added soon.
> The main missing feature is state persistence to the flash memory on STM32H533
(currently all state is reset when power is lost).

## Content

<!-- **Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)* -->
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Development](#development)
  - [Requirements](#requirements)
  - [Cloning the Project](#cloning-the-project)
  - [Build from the Command Line](#build-from-the-command-line)
  - [Using IDE](#using-ide)
  - [SVD file for the MCU](#svd-file-for-the-mcu)
- [STM32CubeH5](#stm32cubeh5)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Development


### Requirements

- [CMake] _(tested with version 3.30.5)_
  * Note: [CLion](#using-ide) has a bundled CMake so there is no need to install it.

- [Arm GNU Toolchain] _(tested with Version 14.2.Rel1)_
  * Download _AArch32 bare-metal target (arm-none-eabi)_ from the Arm website [here][Arm GNU Toolchain].
  * On macOS, `brew install --cask gcc-arm-embedded` can be used.

- [OpenOCD] or any other tool for programming and debugging Arm Cortex-M microcontrollers,
  such as pyOCD or ST-LINK_gdbserver (a part of STM32CubeIDE).

> [!CAUTION]  
> **STM32H5** does not work with the original OpenOCD.
> Currently, it only works with the STMicroelectronics' fork [STMicroelectronics/OpenOCD],
> which has to be built from source,
> **see 👉 [this guide for the instructions](./docs/content/development/openocd.md)**.


### Cloning the Project

The project uses [Git submodules] to manage some of the external dependencies (see [.gitmodules](./.gitmodules)).

There are two options how to get the contents of the submodules:

**When cloning the project**, you can use:
```bash
git clone --recurse-submodules https://github.com/pokusew/lionkey.git
```

**If you already cloned the project** and forgot `--recurse-submodules`, you can use:
```bash
git submodule update --init --recursive
```


### Build from the Command Line

It is possible to build, flash and start the whole project from the command line.

Building is done via `cmake` since this project is a standard [CMake] project (see [CMakeLists.txt](./CMakeLists.txt)).
We also included a [CMakePresets.json](CMakePresets.json) to simplify passing common options.

Here is an example how to build the executable for the NUCLEO-H533RE board with the STM32H533RET6 MCU.
```bash
# configure step (only has to be done once)
cmake --preset stm32h533-debug
# build step
cmake --build --preset stm32h533-debug
```

Flashing can be done for example using `openocd` like this (run from the project root):
```bash
openocd -s /usr/local/share/openocd/scripts -f targets/stm32h533/st_nucleo_h5.cfg -c 'tcl_port disabled' -c 'gdb_port disabled' -c 'program "build/stm32h533-debug/targets/stm32h533/lionkey_stm32h533.elf"' -c reset -c shutdown
```


### Using IDE

**Use JetBrains [CLion] (free for non-commercial use) for development.**
The project is already imported and fully configured, use _File > Open..._ to just open it.

If you have all the [tools](#requirements) installed, you should be able to open, build and run the project from CLion.

You can read more in this [CLion's Embedded development with STM32CubeMX projects][CLion-Embedded-Development]
guide.

Note that CLion bundles CMake (and other tools). Those can be used outside CLion from terminal as well.
On a x64 macOS system, the CLion's `cmake` binary
is located at `/Applications/CLion.app/Contents/bin/cmake/mac/x64/bin/cmake`.
If you add the `/Applications/CLion.app/Contents/bin/cmake/mac/x64/bin/` dir to your PATH,
then you can run CLion's CMake just by typing `cmake` in your terminal.


### SVD file for the MCU

CLion and other IDEs support SVD files for describing the layout of registers for debugging.

See the [README in the tools/svd dir](./tools/svd/README.md) which lists the available SVD files you can use.


## STM32CubeH5

We use the **STM32CubeH5** package (CMSIS, HAL, LL) via the [STM32CubeMX] generator.

The STM32CubeH5 includes the CMSIS modules (for the Arm Cortex-M33 core and for the STM32H5 MCUs),
and the HAL (hardware abstraction layer) and LL (low-level) drivers for the STM32H5 MCUs.

**Relevant resources:**
* see [STM32CubeH5 GitHub repo][STM32CubeH5-GitHub]
* see [product page with docs on st.com][STM32CubeH5-Product-Page]
* see [UM3132 Description of STM32H5 HAL and low-layer drivers][UM3132]


<!-- links references -->

[Thesis]: https://github.com/pokusew/fel-masters-thesis

[Thesis-PDF]: https://github.com/pokusew/fel-masters-thesis/raw/main/docs/FIDO2_USB_Security_Key.pdf

[FIDO2]: https://fidoalliance.org/specifications/

[WebAuthn]: https://w3c.github.io/webauthn/

[CTAP 2.1]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html

[TinyCBOR]: https://github.com/intel/tinycbor

[NUCLEO-H533RE]: https://www.st.com/en/evaluation-tools/nucleo-h533re.html

[STM32H533RET6]: https://www.st.com/en/microcontrollers-microprocessors/stm32h533re.html

[STM32CubeH5-GitHub]: https://github.com/STMicroelectronics/STM32CubeH5

[STM32CubeH5-Product-Page]: https://www.st.com/en/embedded-software/stm32cubeh5.html#documentation

[UM3132]: https://www.st.com/resource/en/user_manual/um3132-description-of-stm32h5-hal-and-lowlayer-drivers-stmicroelectronics.pdf

[STM32CubeMX]: https://www.st.com/en/development-tools/stm32cubemx.html

[CLion]: https://www.jetbrains.com/clion/

[CLion-Embedded-Development]: https://www.jetbrains.com/help/clion/embedded-development.html

[Arm GNU Toolchain]: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

[OpenOCD]: https://openocd.org/pages/getting-openocd.html

[STMicroelectronics/OpenOCD]: https://github.com/STMicroelectronics/OpenOCD

[xPack OpenOCD Releases]: https://github.com/xpack-dev-tools/openocd-xpack/releases

[CMake]: https://cmake.org/

[Git submodules]: https://git-scm.com/docs/gitsubmodules
