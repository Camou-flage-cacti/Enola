# Enola: Efficient Control-Flow Attestation for Embedded Systems
This repository contains the LLVM implementation code, evaluation code, measurement attestation engine code, offline analysis tools  of the Enola framework.

## Directory Structure
- [Evaluaton](Evaluation/): Contains the Evaluation code to generate evaluation data on [Emebnch](https://github.com/embench/embench-iot) and [wolfSSL](https://github.com/wolfSSL/wolfssl) applications
- [Enola_compiler](Enola_compiler/): Contains the modified files with the LLVM sourcode.
- [Running](Running/): Contains some examples appliations that can run on Cortex-m85 CPU.
- [tool](tool/): Contains the Enola code scanner, Enola analyzer, and measurment engine implementations.
- [Test_tz](Test_tz/): Contains our attempt to configure a TrustZone project for Cortex-m85 CPU.
- [QARMA5](QARMA5/): Contains a software implementation of ARM PA measurement hardware, which can be used by the verifier.
- [doc](doc/): Contains related documents for AN555 FPGA image.
- [Helpful documentation](tool/progress.md): Contains different challeges we faced for LLVM implementation, this may help other project aiming to modify the compiler.

## Hardware Reuirements
- [MPS3 FPGA Development Board](https://developer.arm.com/Tools%20and%20Software/MPS3%20FPGA%20Prototyping%20Board)
- A SD card to program the FPGA image on the board.
- A windows machine to setup [Keil IDE](https://www.keil.com/)
- An ubuntu machine to setup [LLVM Compiler](https://github.com/ARM-software/LLVM-embedded-toolchain-for-Arm)

## Software Requirements
- [AN555 FGA Image](https://developer.arm.com/downloads/-/download-fpga-images)
- [Keil IDE](https://www.keil.com/)
- [LLVM Compiler](https://github.com/ARM-software/LLVM-embedded-toolchain-for-Arm)
- A serial console to view the output of the applications like [PuTTY](https://www.putty.org/)




## Setting up LLVM Embedded Toolchain for Arm
We will be using the LLVM arm tool chain version 16.0.0, Link: https://github.com/ARM-software/LLVM-embedded-toolchain-for-Arm/tree/llvm-16
Follow the readme file and build from source markup files. Run the below commands to configure the environment.
The [generate_version_txt.cmake](Enola_compiler/Environment-config/generate_version_txt.cmake) file has some issues when dowlaoded from release, We need to replace that file in directory: LLVM-embedded-toolchain-for-Arm-release-16.0.0/cmake

1. mkdir repos
2. git -C repos clone --branch llvmorg-16.0.0 https://github.com/llvm/llvm-project.git
3. git -C repos/llvm-project apply ../../patches/llvm-project.patch
4. git -C repos clone https://github.com/picolibc/picolibc.git && git -C repos/picolibc checkout 35c504ff6065b2a87ea8a106ae0d0d61d1e7ece5
5. git -C repos/picolibc apply ../../patches/picolibc.patch
6. Replace the Enola LLVM Source files according to [this](Enola_compiler/Readme.md)
7. mkdir build
8. cd build
9. cmake .. -GNinja -DFETCHCONTENT_SOURCE_DIR_LLVMPROJECT=../repos/llvm-project -DFETCHCONTENT_SOURCE_DIR_PICOLIBC=../repos/picolibc
10. ninja