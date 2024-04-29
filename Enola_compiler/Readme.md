# LLVM embedded toolchain for ARM
- [Enola Annotator](Enola-Annotator/): Contains the source code of the Enola Annotator frontend pass
- [Enola Instrumentor](Enola-Instrumentor): Contains the source code Enola Instrumentor backend pass

# Instructions to merge into LLVM-embedded-toolchain-for-Arm

- Create a folder name `EnolaPass` under `root_path_of_llvm/repos/llvm-project/llvm/lib/Transforms`
- Copy all files from [Enola Annotator](Enola-Annotator/) to `EnolaPass`
- Copy and replace all files from [Enola Instrumentor](Enola-Instrumentor) to `root_path_of_llvm/repos/llvm-project/llvm/lib/Target/ARM`