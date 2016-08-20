/* STM32F205RE - 512K Flash, 128K RAM */
/* program starts at 0x20016000 */
MEMORY
{
	rom (rx) : ORIGIN = 0x20016000, LENGTH = 40K
	ram (rwx) : ORIGIN = 0x20000000, LENGTH = 128K - 40K
}

INCLUDE libopencm3_stm32f2.ld
