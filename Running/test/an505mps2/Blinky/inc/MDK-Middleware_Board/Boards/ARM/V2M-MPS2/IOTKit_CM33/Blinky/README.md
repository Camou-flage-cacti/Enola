Blinky project
==================

The **Blinky** project is a simple example for
ARM **IOTKit_CM33_FP** microcontroller using ARM **V2M-MPS2+** Evaluation Board.
Compliant to Cortex Microcontroller Software Interface Standard (CMSIS).

Example functionality
---------------------
Clock Settings:
 - XTAL  =  50 MHz
 - CCLK  =  25 MHz

Timer0 is used in interrupt mode\
LEDs are blinking with speed depending on Timer0 interrupt period\
colour GLCD display shows:
 - init message
 - Button status
 - LED status
 - Touch status

'Hello World' is output onto serial port USART0
 - USART0 settings: 115200 baud, 8 data bits, no parity, 1 stop bit


Available targets
-----------------
 - FVP:        configured for Fast Models Fixed Virtual Platforms
 - V2M-MPS2+:  configured for MPS2+ (uses onboard CMSIS-DAP as debugger)

MPS2+ image: AN505 (+ MB BIOS image V2.2.0)

Note:
  Example runs in secure mode only. Non-secure mode is not used.