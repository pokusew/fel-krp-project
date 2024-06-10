# FIDO2 USB Security Key

A working [FIDO2] USB hardware external authenticator (also called “security key”) 🔑 implemented on STM32F4.

Running on the **[STM3240G-EVAL]** board with the **[STM32F407IGH6]** MCU.

Written in **C**. Uses [STM32CubeF4](#stm32cubef4).

See the full 👉 **[Project Description].**

_Note: This project was originally created as a semestral project in the B4M38KRP (Computer Interfaces) course
and later extended as a part of my pre-thesis project (B4MSVP) at CTU FEE (ČVUT FEL)._


## Content

<!-- **Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)* -->
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Development](#development)
  - [Requirements](#requirements)
  - [Cloning the Project](#cloning-the-project)
  - [Building the External Dependencies](#building-the-external-dependencies)
    - [salty](#salty)
  - [Build from the Command Line](#build-from-the-command-line)
  - [Using IDE](#using-ide)
  - [SVD file for the MCU](#svd-file-for-the-mcu)
- [STM32CubeF4](#stm32cubef4)
- [STM32CubeMX](#stm32cubemx)
  - [Customization](#customization)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Development


### Requirements

- [CMake] _(tested with version 3.27.8 and 3.29.3)_
  * Note: CLion has a bundled CMake so there is no need to install it.

- [Arm GNU Toolchain] _(tested with Version 13.2.Rel1)_
  * Download _AArch32 bare-metal target (arm-none-eabi)_ from the Arm website [here][Arm GNU Toolchain].
  * On macOS, `brew install --cask gcc-arm-embedded` can be used.

- [OpenOCD] _(tested with version 0.12.0)_
  * Download prebuilt binary from [xPack OpenOCD Releases].
  * Note, that the packages in apt repository in Ubuntu are outdated.
  * On macOS, `brew install open-ocd` can be used.


### Cloning the Project

The project uses [Git submodules] to manage some of the external dependencies (see [.gitmodules](./.gitmodules)).

There are two options how to get the contents of the submodules:

**When cloning the project**, you can use:
```bash
git clone --recurse-submodules https://github.com/pokusew/fel-krp-project.git
```

**If you already cloned the project** and forgot `--recurse-submodules`, you can use:
```bash
git submodule update --init --recursive
```


### Building the External Dependencies

Currently, some of the external dependencies (specifically [salty](#salty)) need to be built manually
before we can build the project. In the future, we plan to integrate all dependencies
into the main project build process.


#### salty

salty is an implementation of Ed25519 signatures for microcontrollers.
It is written in [Rust], but it also provides a C API.

In order to build it, you need a working [Rust] installation with the `thumbv7em-none-eabihf` target:
```bash
rustup target add thumbv7em-none-eabihf
```

Then from the project root run the following commands:
```bash
cd crypto/salty/c-api
cargo clean
make build
```


### Build from the Command Line

It is possible to build, flash and start the whole project from the command line.

Building is done via `cmake` since this project is a standard [CMake] project (see [CMakeLists.txt](./CMakeLists.txt)).
```bash
cmake -DCMAKE_BUILD_TYPE=debug -B cmake-build-debug-arm
cmake --build cmake-build-debug-arm
```

Flashing can be done for example using `openocd` like this (run from the project root):
```bash
openocd -s /usr/local/share/openocd/scripts -f stm3240g_eval_stlink.cfg -c "tcl_port disabled" -c "gdb_port disabled" -c "tcl_port disabled" -c "program \"cmake-build-debug/fel-krp-project.elf\"" -c reset -c shutdown
```


### Using IDE

**Use JetBrains [CLion] (free for non-commercial use for students) for development.**
The project is already imported and fully configured, use _File > Open..._ to just open it.

If you have all the [tools](#requirements) installed, you should be able to open, build and run the project from CLion.

You can read more in this [CLion's Embedded development with STM32CubeMX projects][CLion-Embedded-Development]
guide.


### SVD file for the MCU

CLion and other IDEs support SVD files for describing the layout of registers for debugging.

**Note:** We downloaded the SVD file to [svd/STM32F407.svd](./svd/STM32F407.svd),
so you don't need to download it yourselves.

For more information, see the [README in the svd dir](./svd/README.md).


## STM32CubeF4

We use the **STM32CubeF4** package via the [STM32CubeMX] generator.

**Relevant resources:**
* see [STM32CubeF4 GitHub repo][STM32CubeF4-GitHub]
* see [product page with docs on st.com][STM32CubeF4-Product-Page]
* see [UM1725 Description of STM32F4 HAL and low-layer drivers][UM1725]
* see [UM1734 STM32Cube USB device library][UM1734]
  * In this project, we use the USB device library and its **Custom HID** class.
    Unfortunately, its customizability is limited, so we had to change some of the hardcoded template values.
    See more info [below](#customization).


## STM32CubeMX

**Note:** _This section is here only for future reference. You don't need to download STM32CubeMX and don't need to
follow steps in this section._

This project was created by [STM32CubeMX]. Here is the procedure we used:
1. _New Project_ > _Board Selector_ > **STM3240G-EVAL** > _Start Project_ > _Initialize all peripherals with their
   default Mode?_
   **Yes**
2. Then in the _Project Manager_ tab:
	1. Fill in the _Project Name._
	2. Change the _Application structure_ to **Basic**. Keep the _Do not generate the main()_ unchecked.
	3. Change the _Toolchain / IDE_ to STM32CubeIDE (so that the project is compatible with CLion). **Check** _Generate
	   Under Root_ option.
	4. The other fields should be okay with the default values.


### Customization

We tried to maintain compatibility with the STM32CubeMX as much as we could (so that the project could be modified in
STM32CubeMX while the custom code remained in place). This was somehow possible until we implemented USB support.
The generated USB middleware is very hard to customize, and some required changes must be made in the automatically
generated code. So for now, one must carefully diff the changes using git after using STM32CubeMX to avoid losing
some of our custom changes.


<!-- links references -->

[FIDO2]: https://fidoalliance.org/specifications/

[Project Description]: https://docs.google.com/document/d/1BrdMIrTAtqBxYBKOv0oa9b2yFZZl3MrpsmLCvSa47Ak/edit

[STM3240G-EVAL]: https://www.st.com/en/evaluation-tools/stm3240g-eval.html

[STM32F407IGH6]: https://www.st.com/en/microcontrollers-microprocessors/stm32f407ig.html

[STM32CubeF4-GitHub]: https://github.com/STMicroelectronics/STM32CubeF4

[STM32CubeF4-Product-Page]: https://www.st.com/en/embedded-software/stm32cubef4.html#documentation

[UM1725]: https://www.st.com/resource/en/user_manual/um1725-description-of-stm32f4-hal-and-lowlayer-drivers-stmicroelectronics.pdf

[UM1734]: https://www.st.com/resource/en/user_manual/um1734-stm32cube-usb-device-library-stmicroelectronics.pdf

[STM32CubeMX]: https://www.st.com/en/development-tools/stm32cubemx.html

[CLion]: https://www.jetbrains.com/clion/

[CLion-Embedded-Development]: https://www.jetbrains.com/help/clion/embedded-development.html

[Arm GNU Toolchain]: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

[OpenOCD]: https://openocd.org/pages/getting-openocd.html

[xPack OpenOCD Releases]: https://github.com/xpack-dev-tools/openocd-xpack/releases

[CMake]: https://cmake.org/

[Git submodules]: https://git-scm.com/docs/gitsubmodules

[Rust]: https://www.rust-lang.org/
