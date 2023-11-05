# FIDO2 USB Security Key

See the [Project Proposal].

Running on the **[STM3240G-EVAL]** board with the **[STM32F407IGH6]** MCU.

Written in C. Using STM32CubeF4 (see [GitHub repo](https://github.com/STMicroelectronics/STM32CubeF4),
see [product page with docs on st.com](https://www.st.com/en/embedded-software/stm32cubef4.html#documentation),
see [UM1725 Description of STM32F4 HAL and low-layer drivers][UM1725]).


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


## Development

**Use JetBrains [CLion] (free for non-commercial use for students) for development.**
The project is already imported and fully configured, use _File > Open..._ to just open it.

**But before** opening, you'll probably need to install a few things in your system:
1. [Arm GNU Toolchain]
	* Download _AArch32 bare-metal target (arm-none-eabi)_ from the Arm website [here][Arm GNU Toolchain].
	* On macOS, `brew install --cask gcc-arm-embedded` can be used.
2. [OpenOCD]
	* Download prebuilt binary from [xPack OpenOCD Releases].
	* Note, that the packages in apt repository in Ubuntu are outdated.
	* On macOS, `brew install open-ocd` can be used.

If you have all the tools installed, you should be able to open, build and run the project from CLion.

You can read more in this [CLion's Embedded development with STM32CubeMX projects][CLion-Embedded-Development]
guide.


## SVD file for the MCU

CLion and other IDEs support SVD files for describing the layout of registers for debugging.

**Note:** We downloaded the SVD file to [svd/STM32F407.svd](./svd/STM32F407.svd),
so you don't need to download it yourselves.

For more information, see the [README in the svd dir](./svd/README.md).


<!-- links references -->

[Project Proposal]: https://docs.google.com/document/d/1BrdMIrTAtqBxYBKOv0oa9b2yFZZl3MrpsmLCvSa47Ak/edit

[STM3240G-EVAL]: https://www.st.com/en/evaluation-tools/stm3240g-eval.html

[STM32F407IGH6]: https://www.st.com/en/microcontrollers-microprocessors/stm32f407ig.html

[UM1725]: https://www.st.com/resource/en/user_manual/um1725-description-of-stm32f4-hal-and-lowlayer-drivers-stmicroelectronics.pdf

[STM32CubeMX]: https://www.st.com/en/development-tools/stm32cubemx.html

[CLion]: https://www.jetbrains.com/clion/

[CLion-Embedded-Development]: https://www.jetbrains.com/help/clion/embedded-development.html

[Arm GNU Toolchain]: https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

[OpenOCD]: https://openocd.org/pages/getting-openocd.html

[xPack OpenOCD Releases]: https://github.com/xpack-dev-tools/openocd-xpack/releases
