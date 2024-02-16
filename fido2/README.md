# FIDO2

This implementation originally comes from the [SoloKeys Solo 1] project.

However, some of the parts have been rewritten / refactored / modified / fixed,
so it is could be used with our hardware (for example, different flash memory layout).
Additionally, some fixes
such as [Replace `defined(STM32L432xx)` with `defined(STM32L432xx) || defined(STM32F407xx)`][STM32-defined-fix]
were needed in multiple places.

The ultimate goal is to rewrite the whole implementation from scratch and make sure it is fully tested
(Test-Driven-Development and sufficient test coverage).


<!-- links references -->

[SoloKeys Solo 1]: https://github.com/solokeys/solo1/tree/master/fido2

[STM32-defined-fix]: https://github.com/pokusew/fel-krp-project/commit/90268a509a55b628ec30cd4475dec076a1ad6888
