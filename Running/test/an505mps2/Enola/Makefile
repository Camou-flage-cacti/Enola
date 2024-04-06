# Define the build directory
BUILD_DIR := build

UNINSTRUMENTED_DIR := uninsrumented_source
CLANG_LIB_PATH := /home/tomal/llvm_all/llvm-armv16-plain/LLVMEmbeddedToolchainForArm-16.0.0-Linux-x86_64/lib/clang-runtimes/arm-none-eabi/armv8m.main_hard_fp

# BIN_PATH=../../../build/llvm/bin
BIN_PATH=/home/tomal/llvm_all/llvm-armv16-plain/LLVMEmbeddedToolchainForArm-16.0.0-Linux-x86_64/bin
ENOLA_LIB_PATH=/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/lib/LLVMEnolaPass.so

# include ../../Makefile.conf

vpath %.c ./ ./inc/V2M-MPS2_IOTKit_BSP/1.5.0/Boards/ARM/V2M-MPS2/Common ./inc/V2M-MPS2_IOTKit_BSP/1.5.0/CMSIS/Driver ./RTE/Device/IOTKit_CM33_FP
# ../../1.3.0/CMSIS_Driver ../../1.3.0/Device/Source ./ARM/RTE/Device/SSE-310-MPS3_FVP ../../1.3.0/Board/Device_Definition

# Makefile generated from Keil project file

# Include directories (converted to Unix-style paths)
INCLUDES = -I./RTE/Device/IOTKit_CM33_FP -I./RTE/_V2M-MPS2_ 
INCLUDES += -I./inc
INCLUDES += -I./inc/V2M-MPS2_IOTKit_BSP/1.5.0/Device/IOTKit_CM33/Include
INCLUDES += -I./inc/CMSIS_Core_Include
INCLUDES += -I./inc/CMSIS_Device_Include
INCLUDES += -I./inc/MDK-Middleware_Board
INCLUDES += -I./inc/V2M-MPS2_IOTKit_BSP/1.5.0/Boards/ARM/V2M-MPS2/Common
INCLUDES += -I./inc/V2M-MPS2_IOTKit_BSP/1.5.0/CMSIS/Driver
INCLUDES += -Iuninsrumented_source
# INCLUDES += -I~/Documents/GitHub/LLVM-embedded-toolchain-for-Arm/build/llvm/lib/clang-runtimes/arm-none-eabi/armv8m.main_hard_fp/include
# INCLUDES += -I../../../repos/llvm-project/libcxx/include
# INCLUDES += -I/usr/include

# Source files (converted to Unix-style paths)
#SOURCES = Blinky.c
#SOURCES += Buttons_V2M-MPS2.c
#SOURCES += GLCD_Fonts.c
#SOURCES += GLCD_V2M-MPS2.c
#SOURCES += LED_V2M-MPS2.c
#SOURCES += Touch_V2M-MPS2.c

SOURCES = main.c
SOURCES += application.c

SOURCES += USART_V2M-MPS2.c
SOURCES += retarget_io.c

# SOURCES += Driver_USART.c
SOURCES += stdout.c
SOURCES += ./RTE/Device/IOTKit_CM33_FP/startup_IOTKit_CM33.c ./RTE/Device/IOTKit_CM33_FP/system_IOTKit_CM33.c


# Compiler settings
CC = $(BIN_PATH)/clang
# -std=gnu99 enables GNU extensions such as asm, while still keeping the language C99-like.
# CFLAGS = -std=gnu99 --target=arm-arm-none-eabi -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mcmse -c -fno-rtti -O3 -fno-function-sections
CFLAGS = -std=gnu99 --sysroot=$(CLANG_LIB_PATH) --target=thumbv8m.main-none-eabihf -mcpu=cortex-m33 -mfloat-abi=hard -march=thumbv8m.main -mfpu=fpv5-sp-d16 -mcmse -c -mthumb -gdwarf-2 -H -pedantic -O1 -Wno-keyword-macro
# CFLAGS += -I./inc/V2M-MPS2_IOTKit_BSP/1.5.0/Device/IOTKit_CM33/Include/system_IOTKit_CM33.h


CFLAGS += -D_RTE_ -DIOTKit_CM33_FP -D__USE_LCD -D__USE_TIMER0 -D__USE_FPGA -D__USE_SECURE

CFLAGS += $(INCLUDES)
LDFLAGS = -T ./gcc_arm.ld
LDFLAGS += -g -L./inc/lib
# LDFLAGS += -std=gnu99 --target=arm-arm-none-eabi -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mcmse -fno-rtti -O3 -fno-function-sections
# LDFLAGS = -std=c99 --target=thumbv8m.main-none-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -c -mthumb -gdwarf-2 -H -pedantic -O3 -Wno-keyword-macro 
LDFLAGS += -std=gnu99 --sysroot=$(CLANG_LIB_PATH) --target=thumbv8m.main-none-eabihf -mcpu=cortex-m33 -mfloat-abi=hard -march=thumbv8m.main -mfpu=fpv5-sp-d16 -mcmse -mthumb -gdwarf-2 -H -pedantic -O1 -Wno-keyword-macro

# Object files
# OBJECTS = $(SOURCES:.c=.o)
# Object files with build directory
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SOURCES)))

# Name of executable Blinky
TARGET = Blinky.axf

# Default target
all: $(BUILD_DIR) $(TARGET)

# enolaAE:
# 	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/enolaTrampoline.c -o $(BUILD_DIR)/enolaTrampoline.o
# 	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/startup_IOTKit_CM33.c -o $(BUILD_DIR)/startup_IOTKit_CM33.o
# 	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/system_SSE310MPS3.c -o $(BUILD_DIR)/system_SSE310MPS3.o
# 	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/stdout.c -o $(BUILD_DIR)/stdout.o
# 	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/Driver_USART.c -o $(BUILD_DIR)/Driver_USART.o
# 	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/retarget_io.c -o $(BUILD_DIR)/retarget_io.o 
# 	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/uart_cmsdk_drv.c -o $(BUILD_DIR)/uart_cmsdk_drv.o

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^
# Rule to compile .c files to .o files
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
#	$(CC) $(CFLAGS) $(INCLUDES) $< -S -emit-llvm -o $(BUILD_DIR)/$*.ll
#	$(OPT) -enable-new-pm=0 -load $(ENOLA_LIB_PATH) -EnolaPass $(BUILD_DIR)/$*.ll -S -o $(BUILD_DIR)/$*_opt.ll
#	$(LLC) -march=arm -filetype=obj --mattr=+pacbti $(BUILD_DIR)/$*_opt.ll -o $@

# To remove generated files
clean:
	rm -rf $(BUILD_DIR) $(TARGET) *.ll *.o

.PHONY: all clean
