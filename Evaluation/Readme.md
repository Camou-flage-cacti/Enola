# Instructions to compile
- First install the llvm toolchain with Enola files as per the document in [Enola_compiler](../Enola_compiler/) folder.
- make sure to run `ninja` command under llvm build directory after any change in the llvm soruce code
- Locate your `.so` static library file that runs thorugh the `opt` tool. if you have not changed the name it would be named `LLVMEnolaPass.so`
- In all the make files replace the `root_path_of_llvm` with your actual path.
- For each application there are corresponding make files, please rename them to `Make` when you want to run each application.

# Instructions to execute the applications.

- All applications will be compiled as `Blinky.axf` file.
- First create Blinky example project in Keil for cortex-m85: in Windows
- Example projects can be found [here](../Running/test/sse310mps3/)
- Compile the project with Keil
- Replace your `Blinky.axf` file to project_root/ARM/Objects folder.
- Debug with Keil
- Get get performence overhead value, we utilized DWT, more detials can be found [here](https://embeddedcomputing.com/technology/processing/measuring-code-execution-time-on-arm-cortex-m-mcus) 
