# Define the build directory
BUILD_DIR := build

UNINSTRUMENTED_DIR := uninsrumented_source
BIN_PATH=/plain_llvm_root_path/LLVMEmbeddedToolchainForArm-16.0.0-Linux-x86_64/bin

vpath %.c ./ root-path/Running/1.3.0/CMSIS_Driver root-path/Running/1.3.0/Device/Source ./ARM/RTE/Device/SSE-310-MPS3_FVP root-path/Running/1.3.0/Board/Device_Definition

# Makefile generated from Keil project file

# Include directories (converted to Unix-style paths)

INCLUDES += -I./ARM/RTE/Device/SSE-310-MPS3_FVP -I./ARM/RTE/_ARMCLANG  
INCLUDES += -Iroot-path/tool/misc_header
INCLUDES += -Iroot-path/Running/1.3.0/Board/Device_Definition 
INCLUDES += -Iroot-path/Running/1.3.0/Board/Platform
INCLUDES += -Iroot-path/Running/1.3.0/CMSIS_Driver
INCLUDES += -Iroot-path/Running/1.3.0/Device/Include
#INCLUDES += -Iuninsrumented_source


# Source files (converted to Unix-style paths)
SOURCES = main.c
SOURCES += Driver_USART.c
SOURCES += retarget_io.c
SOURCES += stdout.c
SOURCES += uart_cmsdk_drv.c
SOURCES += startup_SSE310MPS3.c system_SSE310MPS3.c 
SOURCES += device_definition.c
SOURCES += enolaTrampoline.c
SOURCES += blake2s.c
SOURCES += sha256.c

# Compiler settings
CC = $(BIN_PATH)/clang
OPT = $(BIN_PATH)/opt
LLC = $(BIN_PATH)/llc
CFLAGS = -std=c99 --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -c -mthumb -gdwarf-2 -H -pedantic -Oz -Wno-keyword-macro -mcpu=cortex-m85


CFLAGS += $(INCLUDES)
# LDFLAGS = -T ../../../tool/linker_SSE310MPS3_secure.ld
LDFLAGS = -T ./ARM/RTE/Device/SSE-310-MPS3_FVP/linker_SSE310MPS3_secure.ld
LDFLAGS += -std=c99 --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -mthumb -gdwarf-2 -pedantic -Oz -Wno-keyword-macro -mcpu=cortex-m85

# Object files
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SOURCES)))

# Name of executable output
TARGET = Blinky.axf

# Default target
all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
	$(CC) $(INCLUDES) $(LDFLAGS)  -o $@ $^

# Rule to compile .c files to .o files
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# To remove generated files
clean:
	rm -rf $(BUILD_DIR) $(TARGET) *.ll *.o

.PHONY: all clean
