# Define the build directory
BUILD_DIR := build

UNINSTRUMENTED_DIR := uninsrumented_source
#BIN_PATH=/plain_llvm_root_path/LLVMEmbeddedToolchainForArm-16.0.0-Linux-x86_64/bin
BIN_PATH="your llvm path"
ENOLA_LIB_PATH="your-path/LLVMEnolaPass.so"

vpath %.c ./ root-path/Running/1.3.0/Device/Source ./ARM/RTE/Device/SSE-310-MPS3_FVP root-path/Running/1.3.0/Board/Device_Definition

# Makefile generated from Keil project file

# Include directories (converted to Unix-style paths)

INCLUDES += -I./ARM/RTE/Device/SSE-310-MPS3_FVP -I./ARM/RTE/_ARMCLANG  
INCLUDES += -Iroot-path/tool/misc_header
INCLUDES += -Iroot-path/Running/1.3.0/Board/Device_Definition 
INCLUDES += -Iroot-path/Running/1.3.0/Board/Platform
INCLUDES += -Iroot-path/Running/1.3.0/CMSIS_Driver
INCLUDES += -Iroot-path/Running/1.3.0/Device/Include
INCLUDES += -Iuninsrumented_source

# Source files (converted to Unix-style paths)
SOURCES = main.c
#SOURCES += Driver_USART.c
#SOURCES += retarget_io.c
# SOURCES += stdout_USART.c
#SOURCES += stdout.c
#SOURCES += uart_cmsdk_drv.c
#SOURCES += startup_SSE310MPS3.c system_SSE310MPS3.c 
SOURCES += device_definition.c
#SOURCES += enolaTrampoline.c
SOURCES += application.c

# Compiler settings
CC = $(BIN_PATH)/clang
OPT = $(BIN_PATH)/opt
LLC = $(BIN_PATH)/llc
CFLAGS = -std=c99 --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -c -mthumb -gdwarf-2 -H -pedantic -O0 -Wno-keyword-macro -mcpu=cortex-m85



CFLAGS += $(INCLUDES)
# LDFLAGS = -T ../../../tool/linker_SSE310MPS3_secure.ld
LDFLAGS = -T ./ARM/RTE/Device/SSE-310-MPS3_FVP/linker_SSE310MPS3_secure.ld
LDFLAGS += -std=c99 --target=thumbv8.1m.main-none-unknown-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -mthumb -gdwarf-2 -pedantic -O0 -Wno-keyword-macro -mcpu=cortex-m85

# Object files
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SOURCES)))

# Name of executable output
TARGET = Blinky.axf

# Default target
all: $(BUILD_DIR) enolaME $(TARGET)
#all: $(BUILD_DIR) $(TARGET)

# app:
# 	$(CC) $(CFLAGS) application.c -S -emit-llvm -o application.ll 
# 	$(OPT) -enable-new-pm=0 -load $(ENOLA_LIB_PATH) -EnolaPass application.ll -S -o application_opt.ll
# 	$(LLC) -filetype=obj -march=arm -mcpu=cortex-m85 --mattr=+pacbti application_opt.ll -O0 -o $(BUILD_DIR)/application.o
# test:
# 	$(CC) $(CFLAGS) $(INCLUDES) main.c -S -emit-llvm -o main.ll
# 	$(OPT) -enable-new-pm=0 -load $(ENOLA_LIB_PATH) -EnolaPass main.ll -S -o main_opt.ll
# 	$(LLC) -march=arm -filetype=obj --mattr=+pacbti main_opt.ll -O0 -o main.o
enolaME:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/enolaTrampoline.c -o $(BUILD_DIR)/enolaTrampoline.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/startup_SSE310MPS3.c -o $(BUILD_DIR)/startup_SSE310MPS3.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/system_SSE310MPS3.c -o $(BUILD_DIR)/system_SSE310MPS3.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/stdout.c -o $(BUILD_DIR)/stdout.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/Driver_USART.c -o $(BUILD_DIR)/Driver_USART.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/retarget_io.c -o $(BUILD_DIR)/retarget_io.o 
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/uart_cmsdk_drv.c -o $(BUILD_DIR)/uart_cmsdk_drv.o
	
#application.o: Application/application.c:
#	clang $(CFLAGS) application.c -S -emit-llvm -o application.ll
#	opt $(CFLAGS) -enable-new-pm=0 -load root_path_of_llvm/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/lib/LLVMEnolaPass.so -EnolaPass application.ll -S -o application_opt.ll
#	llc $(CFLAGS) -filetype=obj application_opt.ll -o application_opt.o
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
#	$(CC) $(INCLUDES) $(LDFLAGS)  -o $@ $^
	$(CC) $(INCLUDES) $(LDFLAGS)  -o $@ $(BUILD_DIR)/enolaTrampoline.o $(BUILD_DIR)/system_SSE310MPS3.o $(BUILD_DIR)/startup_SSE310MPS3.o $(BUILD_DIR)/stdout.o  $(BUILD_DIR)/Driver_USART.o  $(BUILD_DIR)/retarget_io.o  $(BUILD_DIR)/uart_cmsdk_drv.o $^
#	$(CC) $(INCLUDES) $(LDFLAGS)  -o $@ $(BUILD_DIR)/enolaTrampoline.o $(BUILD_DIR)/system_SSE310MPS3.o $(BUILD_DIR)/startup_SSE310MPS3.o $^

# Rule to compile .c files to .o files
$(BUILD_DIR)/%.o: %.c
#	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
	$(CC) $(CFLAGS) $(INCLUDES) $< -S -emit-llvm -o $(BUILD_DIR)/$*.ll
	$(OPT) -enable-new-pm=0 -load $(ENOLA_LIB_PATH) -EnolaPass $(BUILD_DIR)/$*.ll -S -o $(BUILD_DIR)/$*_opt.ll
	$(LLC) -march=arm -filetype=obj --mattr=+pacbti $(BUILD_DIR)/$*_opt.ll -O0 -o $@

# To remove generated files
clean:
	rm -rf $(BUILD_DIR) $(TARGET) *.ll *.o

.PHONY: all clean
