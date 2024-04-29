# Define the build directory
BUILD_DIR := build

UNINSTRUMENTED_DIR := uninsrumented_source
CLANG_LIB_PATH := /home/tomal/llvm_all/llvm-armv16-plain/LLVMEmbeddedToolchainForArm-16.0.0-Linux-x86_64/lib/clang-runtimes/arm-none-eabi/armv8m.main_hard_fp
UNINSTRUMENTED_START_UP := ./RTE/Device/IOTKit_CM33_FP
BIN_PATH=root_path_of_llvm/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin
#BIN_PATH=/home/tomal/llvm_all/llvm-armv16-plain/LLVMEmbeddedToolchainForArm-16.0.0-Linux-x86_64/bin
ENOLA_LIB_PATH=root_path_of_llvm/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/lib/LLVMEnolaPass.so

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
INCLUDES += -I./uninsrumented_source


SOURCES = main.c
SOURCES += rsa.c
SOURCES += hash.c
SOURCES += sha.c
#SOURCES += dsa.c
#SOURCES += aes.c
SOURCES += asn.c
SOURCES += md5.c
SOURCES += sp_int.c
SOURCES += random.c
SOURCES += sha256.c
SOURCES += memory.c
# Compiler settings
CC = $(BIN_PATH)/clang
OPT = $(BIN_PATH)/opt
LLC = $(BIN_PATH)/llc
# -std=gnu99 enables GNU extensions such as asm, while still keeping the language C99-like.
CFLAGS = -std=gnu99 --sysroot=$(CLANG_LIB_PATH) --target=thumbv8m.main-none-eabihf -mcpu=cortex-m33 -mfloat-abi=hard -march=thumbv8m.main -mfpu=fpv5-sp-d16 -mcmse -c -mthumb -H -pedantic -O2 -Wno-keyword-macro -enable-fastmath -disable-shared
# CFLAGS += -I./inc/V2M-MPS2_IOTKit_BSP/1.5.0/Device/IOTKit_CM33/Include/system_IOTKit_CM33.h

#CFLAGS += -D_RTE_ -DIOTKit_CM33_FP -D__USE_SECURE -DENOLA_TRACE_DISPLAY
#CFLAGS += -D_RTE_ -DIOTKit_CM33_FP -D__USE_SECURE -DENOLA_DEBUG
#CFLAGS += -D_RTE_ -DIOTKit_CM33_FP -D__USE_SECURE -DENOLA_DEBUG -DENOLA_TRACE_DEBUG
CFLAGS += -D_RTE_ -DIOTKit_CM33_FP -D__USE_SECURE -DSINGLE_THREADED -DNO_WOLFSSL_DIR -DWOLFSSL_AES_DIRECT -DCRYPTO_EXAMPLE=1 -DHAVE_PK_CALLBACKS -DWOLFSSL_USER_IO -DNO_WRITEV -DTIME_T_NOT_64BIT -DWOLFSSL_NO_MALLOC -DNO_DEV_URANDOM -DNO_FILESYSTEM -DWOLFSSL_SP_NO_3072 -DWC_NO_RNG -DNO_DH -DNO_DSA -DNO_ASN -DNO_WOLFSSL_THREAD -DWOLFSSL_KEY_GEN -DNO_WOLFSSL_MEMORY -DWOLFSSL_CERT_GEN

CFLAGS += $(INCLUDES)
LDFLAGS = -T ./gcc_arm.ld
LDFLAGS += -g -L./inc/lib
# LDFLAGS += -std=gnu99 --target=arm-arm-none-eabi -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mcmse -fno-rtti -O3 -fno-function-sections
# LDFLAGS = -std=c99 --target=thumbv8m.main-none-eabihf -march=thumbv8.1m.main+dsp+mve -mfpu=none -c -mthumb -gdwarf-2 -H -pedantic -O3 -Wno-keyword-macro 
LDFLAGS += -std=gnu99 --sysroot=$(CLANG_LIB_PATH) --target=thumbv8m.main-none-eabihf -mcpu=cortex-m33 -mfloat-abi=hard -march=thumbv8m.main -mfpu=fpv5-sp-d16 -mcmse -mthumb -H -pedantic -O2 -Wno-keyword-macro

# Object files
# OBJECTS = $(SOURCES:.c=.o)
# Object files with build directory
OBJECTS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SOURCES)))

# Name of executable Blinky
TARGET = Blinky.axf

# Default target
all: $(BUILD_DIR) enolaAE $(TARGET)

enolaAE:
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/enolaTrampoline.c -o $(BUILD_DIR)/enolaTrampoline.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_START_UP)/startup_IOTKit_CM33.c -o $(BUILD_DIR)/startup_IOTKit_CM33.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_START_UP)/system_IOTKit_CM33.c -o $(BUILD_DIR)/system_IOTKit_CM33.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/stdout.c -o $(BUILD_DIR)/stdout.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/USART_V2M-MPS2.c -o $(BUILD_DIR)/USART_V2M-MPS2.o
	$(CC) $(INCLUDES) $(CFLAGS) -c $(UNINSTRUMENTED_DIR)/retarget_io.c -o $(BUILD_DIR)/retarget_io.o

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJECTS)
	$(CC) $(INCLUDES) $(LDFLAGS)  -o $@ $(BUILD_DIR)/enolaTrampoline.o $(BUILD_DIR)/startup_IOTKit_CM33.o $(BUILD_DIR)/system_IOTKit_CM33.o $(BUILD_DIR)/stdout.o  $(BUILD_DIR)/USART_V2M-MPS2.o  $(BUILD_DIR)/retarget_io.o $^
# Rule to compile .c files to .o files
$(BUILD_DIR)/%.o: %.c
#	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@
	$(CC) $(CFLAGS) $(INCLUDES) $< -S -emit-llvm -o $(BUILD_DIR)/$*.ll
	$(OPT) -enable-new-pm=0 -load $(ENOLA_LIB_PATH) -EnolaPass $(BUILD_DIR)/$*.ll -S -o $(BUILD_DIR)/$*_opt.ll
	$(LLC) -march=arm -filetype=obj $(BUILD_DIR)/$*_opt.ll -o $@


# To remove generated files
clean:
	rm -rf $(BUILD_DIR) $(TARGET) *.ll *.o

.PHONY: all clean
