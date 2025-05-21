# STM32F407

**[STM3240G-EVAL]** board with the **[STM32F407IGH6]** MCU.

Uses [STM32CubeF4](#stm32cubef4).


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
   3. Change the _Toolchain / IDE_ to STM32CubeIDE (so that the project is compatible with CLion).
      **Check** _Generate Under Root_ option.
	 4. The other fields should be okay with the default values.


### Customization

We tried to maintain compatibility with the STM32CubeMX as much as we could (so that the project could be modified in
STM32CubeMX while the custom code remained in place). This was somehow possible until we implemented USB support.
The generated USB middleware is very hard to customize, and some required changes must be made in the automatically
generated code. So for now, one must carefully diff the changes using git after using STM32CubeMX to avoid losing
some of our custom changes.


<!-- links references -->

[STM3240G-EVAL]: https://www.st.com/en/evaluation-tools/stm3240g-eval.html

[STM32F407IGH6]: https://www.st.com/en/microcontrollers-microprocessors/stm32f407ig.html

[STM32CubeF4-GitHub]: https://github.com/STMicroelectronics/STM32CubeF4

[STM32CubeF4-Product-Page]: https://www.st.com/en/embedded-software/stm32cubef4.html#documentation

[UM1725]: https://www.st.com/resource/en/user_manual/um1725-description-of-stm32f4-hal-and-lowlayer-drivers-stmicroelectronics.pdf

[UM1734]: https://www.st.com/resource/en/user_manual/um1734-stm32cube-usb-device-library-stmicroelectronics.pdf

[STM32CubeMX]: https://www.st.com/en/development-tools/stm32cubemx.html
