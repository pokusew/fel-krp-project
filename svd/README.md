# SVD file for the MCU

CLion and other IDEs support SVD files for describing the layout of registers for debugging.

**Note:** We downloaded the SVD file to [STM32F407.svd](./STM32F407.svd), so you don't need to download it
yourselves.

ST does not provide SVD files for their MCUs. Fortunately, we can get one from the Arm Keil IDE website.
1. Go to [Arm Keil | CMSIS Packs](https://www.keil.arm.com/packs/) and search for _STM32F4xx_.
2. There should be one result: [STM32F4xx_DFP](https://www.keil.arm.com/packs/stm32f4xx_dfp-keil/overview/).
3. Click on _Download STM32F4xx_DFP 3.0.0_ or use
   this [direct download link](https://www.keil.com/pack/Keil.STM32F4xx_DFP.3.0.0.pack) (might stop working in the
   future).
4. Note: At the time we downloaded it, it was `Version 3.0.0: Oct. 11, 2024 Keil.STM32F4xx_DFP.3.0.0.pack`.
5. Rename `.pack` to `.zip`. Then unzip it.
6. Open the `Keil.STM32F4xx_DFP.3.0.0` dir, go to `CMSIS/SVD` subdir.
   There should be the `STM32F407.svd` file.
   That's the one you are looking for.

## CMSIS

CMSIS stands for _Common Microcontroller Software Interface Standard_.

* [CMIS Arm website](https://www.arm.com/technologies/cmsis)
* [CMIS on GitHub](https://github.com/ARM-software/CMSIS_5)
* [CMIS SVD documentation](https://arm-software.github.io/CMSIS_5/SVD/html/index.html)
  and [CMIS SVD Schema](https://arm-software.github.io/CMSIS_5/SVD/html/schema_1_2_gr.html)
