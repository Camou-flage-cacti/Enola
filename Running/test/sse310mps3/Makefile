# Define the build directory
BUILD_DIR := build

#BIN_PATH=/home/tancy/Documents/LLVM-embedded-toolchain-for-Arm/build/llvm/bin
BIN_PATH=/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin
vpath %.c ./ ../../1.3.0/CMSIS_Driver ../../1.3.0/Device/Source ./ARM/RTE/Device/SSE-310-MPS3_FVP ../../1.3.0/Board/Device_Definition

# Makefile generated from Keil project file

# Include directories (converted to Unix-style paths)

INCLUDES += -I./ARM/RTE/Device/SSE-310-MPS3_FVP -I./ARM/RTE/_ARMCLANG  
INCLUDES += -I../../../tool/misc_header
INCLUDES += -I../../1.3.0/Board/Device_Definition 
INCLUDES += -I../../1.3.0/Board/Platform
INCLUDES += -I../../1.3.0/CMSIS_Driver
INCLUDES += -I../../1.3.0/Device/Include
#INCLUDES += -I/home/tomal/llvm_all/LLVM-ARM/LLVM-embedded-toolchain-for-Arm-release-17.0.1/build/llvm/lib/clang-runtimes/arm-none-eabi/armv8.1m.main_hard_nofp_mve/include

# Source files (converted to Unix-style paths)
SOURCES = main.c
SOURCES += Driver_USART.c
SOURCES += retarget_io.c
# SOURCES += stdout_USART.c
SOURCES += stdout.c
SOURCES += uart_cmsdk_drv.c
SOURCES += startup_SSE310MPS3.c system_SSE310MPS3.c 
SOURCES += device_definition.c
SOURCES += enolaTrampoline.c
#SOURCES += application.c

# Compiler settings
CC = $(BIN_PATH)/clang
CFLAGS = -std=c99 --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -c -mthumb -gdwarf-2 -H -pedantic -O0 -Wno-keyword-macro 
#CFLAGS = -std=c99 --sysroot=/home/tomal/llvm_all/LLVM-ARM/LLVM-embedded-toolchain-for-Arm-release-17.0.1/build/llvm/lib/clang-runtimes/arm-none-eabi/armv8.1m.main_hard_nofp_mve --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -c -mthumb -gdwarf-2 -H -pedantic -Os -Wno-keyword-macro 


CFLAGS += $(INCLUDES)
# LDFLAGS = -T ../../../tool/linker_SSE310MPS3_secure.ld
LDFLAGS = -T ./ARM/RTE/Device/SSE-310-MPS3_FVP/linker_SSE310MPS3_secure.ld
LDFLAGS += -std=c99 --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -mthumb -gdwarf-2 -pedantic -O0
LIB_PATH += -L/home/tomal/llvm_all/LLVM-ARM/LLVM-embedded-toolchain-for-Arm-release-17.0.1/build/llvm/lib/clang-runtimes/arm-none-eabi/armv8.1m.main_hard_nofp_mve/lib
# Object files
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SOURCES)))

# Name of executable output
TARGET = Blinky.axf

# Default target
all: $(BUILD_DIR) app $(TARGET)
#all: $(BUILD_DIR) $(TARGET)

app:
	/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/clang $(CFLAGS) application.c -S -emit-llvm -o application.ll 
	/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/opt -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/lib/LLVMEnolaPass.so -EnolaPass application.ll -S -o application_opt.ll
	/home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/llc -filetype=obj application_opt.ll -o $(BUILD_DIR)/application.o
	
#application.o: Application/application.c:
#	clang $(CFLAGS) application.c -S -emit-llvm -o application.ll
#	opt $(CFLAGS) -enable-new-pm=0 -load /home/tomal/llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/lib/LLVMEnolaPass.so -EnolaPass application.ll -S -o application_opt.ll
#	llc $(CFLAGS) -filetype=obj application_opt.ll -o application_opt.o
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
#	$(CC) $(INCLUDES) $(LDFLAGS)  -o $@ $^
	$(CC) $(INCLUDES) $(LDFLAGS)  -o $@ $(BUILD_DIR)/application.o $^

# Rule to compile .c files to .o files
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# To remove generated files
clean:
	rm -rf $(BUILD_DIR) $(TARGET) *.ll *.o

.PHONY: all clean

