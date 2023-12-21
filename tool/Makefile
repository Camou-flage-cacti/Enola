 This makefile will use arm-none-eabi-gcc as default toolchain

# COMPILER=<PATH_TO_OTHER_GCC_VERSION>/arm-none-eabi-gcc make
# COMPILER=clang make

# outs
#BIN := Blinky.elf
BIN := Blinky1.axf
#BIN2 := Blinky2.axf
#BIN_BC := Blinky_all.bc
#BIN_S := Blinky_all.s
BUILD_DIR := build

# libs
ROOT_REL := ../Running/1.3.0
ROOT_DIR := $(abspath $(ROOT_REL))
BOARD_DIR := $(ROOT_DIR)/Board/
CMSIS_DIR := $(ROOT_DIR)/CMSIS_Driver/
DEVICE_DIR := $(ROOT_DIR)/Device/
APP_REL := ../Running/Examples/Blinky
APP_DIR := $(abspath $(APP_REL))

#ARM_COMPILER_DIR := $(ARM_DIR)/Keil/ARM_Compiler/1.6.3/Source
#RET_DIR_REL := ./RTE/Device/IOTKit_CM33_FP
#RET_DIR := $(abspath $(RET_DIR_REL))

#############   source files    ##############
#  Can get from the .uvprojx <Component> label
SRCS += $(APP_DIR)/Blinky.c
SRCS += $(APP_DIR)/main.c
SRCS += $(APP_DIR)/API/Source/led_port.c
SRCS += $(CMSIS_DIR)/Driver_USART.c
SRCS += retarget_io.c
SRCS += $(BOARD_DIR)/Device_Definition/device_definition.c
SRCS += $(DEVICE_DIR)/Source/arm_mps3_io_drv.c
SRCS += $(DEVICE_DIR)/Source/stdout_USART.c
SRCS += $(DEVICE_DIR)/Source/syscounter_armv8-m_cntrl_drv.c
SRCS += $(DEVICE_DIR)/Source/syscounter_armv8-m_read_drv.c
SRCS += $(DEVICE_DIR)/Source/systimer_armv8-m_drv.c
SRCS += $(DEVICE_DIR)/Source/systimer_armv8-m_timeout.c
SRCS += $(DEVICE_DIR)/Source/uart_cmsdk_drv.c
SRCS += $(DEVICE_DIR)/Source/startup_SSE310MPS3.c
SRCS += $(DEVICE_DIR)/Source/system_SSE310MPS3.c


#############   include    ##############
# Fix those include files
INCLUDE_DIRS =
INCLUDE_DIRS += -I $(APP_DIR)/API/Include
INCLUDE_DIRS += -I $(APP_DIR)
INCLUDE_DIRS += -I $(CMSIS_DIR)/Config
INCLUDE_DIRS += -I $(DEVICE_DIR)/Config
INCLUDE_DIRS += -I $(DEVICE_DIR)/Include
# Compiler & Linker

#############  CFLAGS   ##############
# by default it arm-none-eabi-gcc
COMPILER = clang

# get from the Keil IDE project settings
CPU_FLAGS = -mcpu=cortex-m85+pacbti 
ARCH_FLAGS = -mthumb -mfloat-abi=hard 
#-c -mlittle-endian -gdwarf-4
# get from the .dep file
DEFINES += -D__UVISION_VERSION="537" -D_RTE_ -DCORSTONE310_FVP -D_RTE_

#ifneq '' '$(findstring clang,$(COMPILER))'
#$(info ===Clang Compiler Detected===)
CROSS_COMPILE	=/home/tomal/llvm_all/llvm-project/build/bin

CC 				= $(CROSS_COMPILE)/clang
CXX				= $(CROSS_COMPILE)/clang++
LLC				= /home/tomal/llvm_all/llvm-project/build/bin/llc
LINK			= $(CROSS_COMPILE)/llvm-link
SIZE			= $(CROSS_COMPILE)/llvm-size
OBJDUMP			= $(CROSS_COMPILE)/llvm-objdump
OBJCOPY			= $(CROSS_COMPILE)/llvm-objcopy
STRIP			= $(CROSS_COMPILE)/llvm-strip

#LLVM_FLAGS += --config armv8m.main_hard_fp_rdimon_baremetal
#COMPILER_SPECIFIC_CFLAGS += $(LLVM_FLAGS) --target=arm-none-eabi -Oz 
#COMPILER_SPECIFIC_ASFLAGS += --target=arm-none-eabi -masm=gnu -c -mlittle-endian
COMIPLER_CONTROL_STRING += -xc -std=c99 --target=arm-arm-none-eabi -mcpu=cortex-m85+pacbti -mfloat-abi=hard -c -fno-rtti -funsigned-char -fshort-enums -fshort-wchar -mlittle-endian -gdwarf-4 -O2 -ffunction-sections -Wno-packed -Wno-missing-variable-declarations -Wno-missing-prototypes -Wno-missing-noreturn -Wno-sign-conversion -Wno-nonportable-include-path -Wno-reserved-id-macro -Wno-unused-macros -Wno-documentation-unknown-command -Wno-documentation -Wno-license-management -Wno-parentheses-equality -Wno-reserved-identifier -Wno-padded -Wno-covered-switch-default $(DEFINES) -o ../build/Objects/*.o -MD

MISC_CONTROL += -Wno-padded -Wno-covered-switch-default
#COMPILER_SPECIFIC_LDFLAGS += 

ASM_FLAGS += -Wa,-defsym,__UVISION_VERSION=537 -Wa,-defsym,_RTE_=1 -Wa,-defsym,CORSTONE310_FVP=1 -Wa,-defsym,_RTE_=1 -o ./Objects/*.o

LDSCRIPT = linker_SSE310MPS3_secure.ld

LINKER_FLAG += --cpu=Cortex-M85 --fpu=FPv5_D16 ../build/objects/*.o --summary_stderr --info summarysizes --map --load_addr_map_info --xref --callgraph --symbols --info sizes --info totals --info unused --info veneers --list ".\Listings\Blinky.map" -o ..\build\Objects\Blinky.axf
# --import=".\Out\Blinky_CMSE_Lib.o" \
# 							--summary_stderr --info summarysizes --map --load_addr_map_info \
# 							--xref --callgraph --symbols \
# 							--info sizes --info totals --info unused --info veneers
#endif


#CFLAGS += $(COMPILER_SPECIFIC_CFLAGS)
#LDFLAGS += $(COMPILER_SPECIFIC_LDFLAGS)
#ASFLAGS += $(COMPILER_SPECIFIC_ASFLAGS)

#############   flags  for arm gcc  ##############
#COMMON_FLAGS = -Wall -Wextra -Wfatal-errors

# Compile flags
#CFLAGS += $(COMMON_FLAGS)
#CFLAGS += -fno-rtti -funsigned-char
#CFLAGS += -gdwarf-4 -MD -fno-function-sections -Wno-padded -Wno-covered-switch-default

# asm flags
#ASFLAGS = $(COMMON_FLAGS)
#ASFLAGS += $(CPU_FLAGS) -c -gdwarf-3
#ASFLAGS += -Wa,-defsym,_RTE_=1 -Wa,-defsym,IOTKit_CM33_FP=1 -Wa,-defsym,_RTE_=1

# Link flags
# -A=cortex-m33
#LDFLAGS += -g -T $(LDSCRIPT)
#  -import-cmse-lib-out=${BUILD_DIR}/Blinky_CMSE_Lib.o

####################
#LIBS = 

#OBJ_FILES := $(SRCS:%.c=$(BUILD_DIR)/%.o) 
#BC_FILES := $(SRCS:%.c=$(BUILD_DIR)/%.bc) 
# $(ASMS:%.S=$(BUILD_DIR)/%.o)

#CFLAGS += $(INCLUDE_DIRS)

.PHONY: clean



clean:
	-rm -rf build *.bc *.i *.s	
