; ModuleID = 'main.c'
source_filename = "main.c"
target datalayout = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64"
target triple = "thumbv8.1m.main-none-unknown-eabihf"

%struct.__file = type { i16, i8, ptr, ptr, ptr }

@__stdio = internal global %struct.__file { i16 0, i8 2, ptr @stdout_putchar, ptr null, ptr null }, align 4, !dbg !0
@stdin = dso_local constant ptr @__stdio, align 4, !dbg !5
@.str = private unnamed_addr constant [18 x i8] c"\0D\0A= setup done=\0D\0A\00", align 1, !dbg !37
@.str.1 = private unnamed_addr constant [24 x i8] c"\0D\0A= INitializing IBT=\0D\0A\00", align 1, !dbg !42
@.str.2 = private unnamed_addr constant [21 x i8] c"\0D\0A= IBT init done=\0D\0A\00", align 1, !dbg !47
@.str.3 = private unnamed_addr constant [36 x i8] c"\0D\0A= mod2 function call result %d=\0D\0A\00", align 1, !dbg !52
@.str.4 = private unnamed_addr constant [19 x i8] c"\0D\0A= loopOver %d=\0D\0A\00", align 1, !dbg !57
@.str.5 = private unnamed_addr constant [21 x i8] c"\0D\0A= switchcase %d=\0D\0A\00", align 1, !dbg !62
@__const.main.nums = private unnamed_addr constant [5 x i32] [i32 0, i32 1, i32 0, i32 3, i32 12], align 4

@stdout = dso_local alias ptr, ptr @stdin
@stderr = dso_local alias ptr, ptr @stdin

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !73 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  %8 = alloca ptr, align 4
  %9 = alloca [5 x i32], align 4
  store i32 0, ptr %1, align 4
  %10 = call i32 @stdout_init(), !dbg !77
  call void @elapsed_time_init(), !dbg !78
  call void @llvm.dbg.declare(metadata ptr %2, metadata !79, metadata !DIExpression()), !dbg !81
  store i32 0, ptr %2, align 4, !dbg !81
  br label %11, !dbg !82

11:                                               ; preds = %15, %0
  %12 = load i32, ptr %2, align 4, !dbg !83
  %13 = icmp slt i32 %12, 10, !dbg !85
  br i1 %13, label %14, label %18, !dbg !86

14:                                               ; preds = %11
  call void @elapsed_time_start(i32 noundef 0), !dbg !87
  call void @setup_S_PAC_Keys(), !dbg !89
  call void @init_registers(), !dbg !90
  call void @elapsed_time_stop(i32 noundef 0), !dbg !91
  br label %15, !dbg !92

15:                                               ; preds = %14
  %16 = load i32, ptr %2, align 4, !dbg !93
  %17 = add nsw i32 %16, 1, !dbg !93
  store i32 %17, ptr %2, align 4, !dbg !93
  br label %11, !dbg !94, !llvm.loop !95

18:                                               ; preds = %11
  call void @enable_PAC(), !dbg !97
  call void @llvm.dbg.declare(metadata ptr %3, metadata !98, metadata !DIExpression()), !dbg !100
  store i32 0, ptr %3, align 4, !dbg !100
  br label %19, !dbg !101

19:                                               ; preds = %23, %18
  %20 = load i32, ptr %3, align 4, !dbg !102
  %21 = icmp slt i32 %20, 10, !dbg !104
  br i1 %21, label %22, label %26, !dbg !105

22:                                               ; preds = %19
  call void @elapsed_time_start(i32 noundef 1), !dbg !106
  call void @init_trampoline(), !dbg !108
  call void @elapsed_time_stop(i32 noundef 1), !dbg !109
  br label %23, !dbg !110

23:                                               ; preds = %22
  %24 = load i32, ptr %3, align 4, !dbg !111
  %25 = add nsw i32 %24, 1, !dbg !111
  store i32 %25, ptr %3, align 4, !dbg !111
  br label %19, !dbg !112, !llvm.loop !113

26:                                               ; preds = %19
  %27 = call i32 (ptr, ...) @printf(ptr noundef @.str), !dbg !115
  %28 = call i32 (ptr, ...) @printf(ptr noundef @.str.1), !dbg !116
  call void @llvm.dbg.declare(metadata ptr %4, metadata !117, metadata !DIExpression()), !dbg !119
  store i32 0, ptr %4, align 4, !dbg !119
  br label %29, !dbg !120

29:                                               ; preds = %33, %26
  %30 = load i32, ptr %4, align 4, !dbg !121
  %31 = icmp slt i32 %30, 10, !dbg !123
  br i1 %31, label %32, label %36, !dbg !124

32:                                               ; preds = %29
  call void @elapsed_time_start(i32 noundef 2), !dbg !125
  call void @intialize_IBT(), !dbg !127
  call void @elapsed_time_stop(i32 noundef 2), !dbg !128
  br label %33, !dbg !129

33:                                               ; preds = %32
  %34 = load i32, ptr %4, align 4, !dbg !130
  %35 = add nsw i32 %34, 1, !dbg !130
  store i32 %35, ptr %4, align 4, !dbg !130
  br label %29, !dbg !131, !llvm.loop !132

36:                                               ; preds = %29
  call void @llvm.dbg.declare(metadata ptr %5, metadata !134, metadata !DIExpression()), !dbg !136
  store i32 0, ptr %5, align 4, !dbg !136
  br label %37, !dbg !137

37:                                               ; preds = %41, %36
  %38 = load i32, ptr %5, align 4, !dbg !138
  %39 = icmp slt i32 %38, 10, !dbg !140
  br i1 %39, label %40, label %44, !dbg !141

40:                                               ; preds = %37
  call void @elapsed_time_start(i32 noundef 3), !dbg !142
  call void @secure_trace_storage(), !dbg !144
  call void @elapsed_time_stop(i32 noundef 3), !dbg !145
  br label %41, !dbg !146

41:                                               ; preds = %40
  %42 = load i32, ptr %5, align 4, !dbg !147
  %43 = add nsw i32 %42, 1, !dbg !147
  store i32 %43, ptr %5, align 4, !dbg !147
  br label %37, !dbg !148, !llvm.loop !149

44:                                               ; preds = %37
  %45 = call i32 (ptr, ...) @printf(ptr noundef @.str.2), !dbg !151
  call void @llvm.dbg.declare(metadata ptr %6, metadata !152, metadata !DIExpression()), !dbg !153
  store i32 32, ptr %6, align 4, !dbg !153
  call void @llvm.dbg.declare(metadata ptr %7, metadata !154, metadata !DIExpression()), !dbg !155
  %46 = load i32, ptr %6, align 4, !dbg !156
  %47 = call i32 @mod2(i32 noundef %46), !dbg !157
  store i32 %47, ptr %7, align 4, !dbg !155
  %48 = load i32, ptr %7, align 4, !dbg !158
  %49 = call i32 (ptr, ...) @printf(ptr noundef @.str.3, i32 noundef %48), !dbg !159
  %50 = load i32, ptr %6, align 4, !dbg !160
  %51 = call i32 @loopOver(i32 noundef %50), !dbg !161
  store i32 %51, ptr %7, align 4, !dbg !162
  %52 = load i32, ptr %7, align 4, !dbg !163
  %53 = call i32 (ptr, ...) @printf(ptr noundef @.str.4, i32 noundef %52), !dbg !164
  %54 = load i32, ptr %6, align 4, !dbg !165
  %55 = call i32 @switchcase(i32 noundef %54), !dbg !166
  store i32 %55, ptr %7, align 4, !dbg !167
  %56 = load i32, ptr %7, align 4, !dbg !168
  %57 = call i32 (ptr, ...) @printf(ptr noundef @.str.5, i32 noundef %56), !dbg !169
  call void @llvm.dbg.declare(metadata ptr %8, metadata !170, metadata !DIExpression()), !dbg !174
  store ptr @func, ptr %8, align 4, !dbg !174
  %58 = load ptr, ptr %8, align 4, !dbg !175
  %59 = call i32 %58(i32 noundef 10), !dbg !176
  call void @llvm.dbg.declare(metadata ptr %9, metadata !177, metadata !DIExpression()), !dbg !181
  call void @llvm.memcpy.p0.p0.i32(ptr align 4 %9, ptr align 4 @__const.main.nums, i32 20, i1 false), !dbg !181
  %60 = getelementptr inbounds [5 x i32], ptr %9, i32 0, i32 0, !dbg !182
  call void @moveZeros(ptr noundef %60, i32 noundef 5), !dbg !183
  call void @display_elapsed_times(), !dbg !184
  ret i32 0, !dbg !185
}

declare dso_local i32 @stdout_init() #1

declare dso_local void @elapsed_time_init() #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #2

declare dso_local void @elapsed_time_start(i32 noundef) #1

declare dso_local void @setup_S_PAC_Keys(...) #1

declare dso_local void @init_registers(...) #1

declare dso_local void @elapsed_time_stop(i32 noundef) #1

declare dso_local void @enable_PAC(...) #1

declare dso_local void @init_trampoline(...) #1

declare dso_local i32 @printf(ptr noundef, ...) #1

declare dso_local void @intialize_IBT(...) #1

declare dso_local void @secure_trace_storage(...) #1

declare dso_local i32 @mod2(i32 noundef) #1

declare dso_local i32 @loopOver(i32 noundef) #1

declare dso_local i32 @switchcase(i32 noundef) #1

declare dso_local i32 @func(i32 noundef) #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i32(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i32, i1 immarg) #3

declare dso_local void @moveZeros(ptr noundef, i32 noundef) #1

declare dso_local void @display_elapsed_times(...) #1

declare dso_local i32 @stdout_putchar(i8 noundef zeroext, ptr noundef) #1

attributes #0 = { noinline nounwind optnone "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="cortex-m85" "target-features"="+armv8.1-m.main,+dsp,+hwdiv,+lob,+mve,+pacbti,+ras,+strict-align,+thumb-mode,-aes,-bf16,-cdecp0,-cdecp1,-cdecp2,-cdecp3,-cdecp4,-cdecp5,-cdecp6,-cdecp7,-crc,-crypto,-d32,-dotprod,-fp-armv8,-fp-armv8d16,-fp-armv8d16sp,-fp-armv8sp,-fp16,-fp16fml,-fp64,-fullfp16,-hwdiv-arm,-i8mm,-mve.fp,-neon,-sb,-sha2,-vfp2,-vfp2sp,-vfp3,-vfp3d16,-vfp3d16sp,-vfp3sp,-vfp4,-vfp4d16,-vfp4d16sp,-vfp4sp" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="cortex-m85" "target-features"="+armv8.1-m.main,+dsp,+hwdiv,+lob,+mve,+pacbti,+ras,+strict-align,+thumb-mode,-aes,-bf16,-cdecp0,-cdecp1,-cdecp2,-cdecp3,-cdecp4,-cdecp5,-cdecp6,-cdecp7,-crc,-crypto,-d32,-dotprod,-fp-armv8,-fp-armv8d16,-fp-armv8d16sp,-fp-armv8sp,-fp16,-fp16fml,-fp64,-fullfp16,-hwdiv-arm,-i8mm,-mve.fp,-neon,-sb,-sha2,-vfp2,-vfp2sp,-vfp3,-vfp3d16,-vfp3d16sp,-vfp3sp,-vfp4,-vfp4d16,-vfp4d16sp,-vfp4sp" }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!67, !68, !69, !70, !71}
!llvm.ident = !{!72}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "__stdio", scope: !2, file: !3, line: 7, type: !9, isLocal: true, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 16.0.0", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !4, imports: !64, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "main.c", directory: "/home/tomal/Desktop/cacti_lab/code-CFA-with-pac/Evaluation/engine/sse310mps3")
!4 = !{!5, !37, !42, !47, !52, !57, !62, !0}
!5 = !DIGlobalVariableExpression(var: !6, expr: !DIExpression())
!6 = distinct !DIGlobalVariable(name: "stdin", scope: !2, file: !3, line: 8, type: !7, isLocal: false, isDefinition: true)
!7 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !8)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 32)
!9 = !DIDerivedType(tag: DW_TAG_typedef, name: "FILE", file: !10, line: 135, baseType: !11)
!10 = !DIFile(filename: "llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/../lib/clang-runtimes/arm-none-eabi/armv8.1m.main_hard_nofp_mve/include/stdio.h", directory: "/home/tomal")
!11 = !DIDerivedType(tag: DW_TAG_typedef, name: "__FILE", file: !10, line: 133, baseType: !12)
!12 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "__file", file: !10, line: 84, size: 128, elements: !13)
!13 = !{!14, !21, !25, !32, !36}
!14 = !DIDerivedType(tag: DW_TAG_member, name: "unget", scope: !12, file: !10, line: 85, baseType: !15, size: 16)
!15 = !DIDerivedType(tag: DW_TAG_typedef, name: "__ungetc_t", file: !10, line: 81, baseType: !16)
!16 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint16_t", file: !17, line: 36, baseType: !18)
!17 = !DIFile(filename: "llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/../lib/clang-runtimes/arm-none-eabi/armv8.1m.main_hard_nofp_mve/include/sys/_stdint.h", directory: "/home/tomal")
!18 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint16_t", file: !19, line: 57, baseType: !20)
!19 = !DIFile(filename: "llvm_all/llvm-armv16/LLVM-embedded-toolchain-for-Arm-release-16.0.0/build/llvm/bin/../lib/clang-runtimes/arm-none-eabi/armv8.1m.main_hard_nofp_mve/include/machine/_default_types.h", directory: "/home/tomal")
!20 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "flags", scope: !12, file: !10, line: 86, baseType: !22, size: 8, offset: 16)
!22 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint8_t", file: !17, line: 24, baseType: !23)
!23 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint8_t", file: !19, line: 43, baseType: !24)
!24 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "put", scope: !12, file: !10, line: 95, baseType: !26, size: 32, offset: 32)
!26 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !27, size: 32)
!27 = !DISubroutineType(types: !28)
!28 = !{!29, !30, !31}
!29 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!30 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_unsigned_char)
!31 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 32)
!32 = !DIDerivedType(tag: DW_TAG_member, name: "get", scope: !12, file: !10, line: 96, baseType: !33, size: 32, offset: 64)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 32)
!34 = !DISubroutineType(types: !35)
!35 = !{!29, !31}
!36 = !DIDerivedType(tag: DW_TAG_member, name: "flush", scope: !12, file: !10, line: 97, baseType: !33, size: 32, offset: 96)
!37 = !DIGlobalVariableExpression(var: !38, expr: !DIExpression())
!38 = distinct !DIGlobalVariable(scope: null, file: !3, line: 38, type: !39, isLocal: true, isDefinition: true)
!39 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 144, elements: !40)
!40 = !{!41}
!41 = !DISubrange(count: 18)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(scope: null, file: !3, line: 39, type: !44, isLocal: true, isDefinition: true)
!44 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 192, elements: !45)
!45 = !{!46}
!46 = !DISubrange(count: 24)
!47 = !DIGlobalVariableExpression(var: !48, expr: !DIExpression())
!48 = distinct !DIGlobalVariable(scope: null, file: !3, line: 52, type: !49, isLocal: true, isDefinition: true)
!49 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 168, elements: !50)
!50 = !{!51}
!51 = !DISubrange(count: 21)
!52 = !DIGlobalVariableExpression(var: !53, expr: !DIExpression())
!53 = distinct !DIGlobalVariable(scope: null, file: !3, line: 57, type: !54, isLocal: true, isDefinition: true)
!54 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 288, elements: !55)
!55 = !{!56}
!56 = !DISubrange(count: 36)
!57 = !DIGlobalVariableExpression(var: !58, expr: !DIExpression())
!58 = distinct !DIGlobalVariable(scope: null, file: !3, line: 59, type: !59, isLocal: true, isDefinition: true)
!59 = !DICompositeType(tag: DW_TAG_array_type, baseType: !30, size: 152, elements: !60)
!60 = !{!61}
!61 = !DISubrange(count: 19)
!62 = !DIGlobalVariableExpression(var: !63, expr: !DIExpression())
!63 = distinct !DIGlobalVariable(scope: null, file: !3, line: 61, type: !49, isLocal: true, isDefinition: true)
!64 = !{!65, !66}
!65 = !DIImportedEntity(tag: DW_TAG_imported_declaration, name: "stdout", scope: !2, entity: !6, file: !3, line: 9)
!66 = !DIImportedEntity(tag: DW_TAG_imported_declaration, name: "stderr", scope: !2, entity: !6, file: !3, line: 10)
!67 = !{i32 7, !"Dwarf Version", i32 2}
!68 = !{i32 2, !"Debug Info Version", i32 3}
!69 = !{i32 1, !"wchar_size", i32 4}
!70 = !{i32 1, !"min_enum_size", i32 4}
!71 = !{i32 7, !"frame-pointer", i32 2}
!72 = !{!"clang version 16.0.0"}
!73 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 20, type: !74, scopeLine: 21, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !76)
!74 = !DISubroutineType(types: !75)
!75 = !{!29}
!76 = !{}
!77 = !DILocation(line: 22, column: 2, scope: !73)
!78 = !DILocation(line: 23, column: 2, scope: !73)
!79 = !DILocalVariable(name: "i", scope: !80, file: !3, line: 24, type: !29)
!80 = distinct !DILexicalBlock(scope: !73, file: !3, line: 24, column: 2)
!81 = !DILocation(line: 24, column: 10, scope: !80)
!82 = !DILocation(line: 24, column: 6, scope: !80)
!83 = !DILocation(line: 24, column: 16, scope: !84)
!84 = distinct !DILexicalBlock(scope: !80, file: !3, line: 24, column: 2)
!85 = !DILocation(line: 24, column: 17, scope: !84)
!86 = !DILocation(line: 24, column: 2, scope: !80)
!87 = !DILocation(line: 26, column: 3, scope: !88)
!88 = distinct !DILexicalBlock(scope: !84, file: !3, line: 25, column: 2)
!89 = !DILocation(line: 27, column: 3, scope: !88)
!90 = !DILocation(line: 28, column: 3, scope: !88)
!91 = !DILocation(line: 29, column: 3, scope: !88)
!92 = !DILocation(line: 30, column: 2, scope: !88)
!93 = !DILocation(line: 24, column: 22, scope: !84)
!94 = !DILocation(line: 24, column: 2, scope: !84)
!95 = distinct !{!95, !86, !96}
!96 = !DILocation(line: 30, column: 2, scope: !80)
!97 = !DILocation(line: 31, column: 2, scope: !73)
!98 = !DILocalVariable(name: "i", scope: !99, file: !3, line: 32, type: !29)
!99 = distinct !DILexicalBlock(scope: !73, file: !3, line: 32, column: 2)
!100 = !DILocation(line: 32, column: 10, scope: !99)
!101 = !DILocation(line: 32, column: 6, scope: !99)
!102 = !DILocation(line: 32, column: 16, scope: !103)
!103 = distinct !DILexicalBlock(scope: !99, file: !3, line: 32, column: 2)
!104 = !DILocation(line: 32, column: 17, scope: !103)
!105 = !DILocation(line: 32, column: 2, scope: !99)
!106 = !DILocation(line: 34, column: 3, scope: !107)
!107 = distinct !DILexicalBlock(scope: !103, file: !3, line: 33, column: 2)
!108 = !DILocation(line: 35, column: 3, scope: !107)
!109 = !DILocation(line: 36, column: 3, scope: !107)
!110 = !DILocation(line: 37, column: 2, scope: !107)
!111 = !DILocation(line: 32, column: 22, scope: !103)
!112 = !DILocation(line: 32, column: 2, scope: !103)
!113 = distinct !{!113, !105, !114}
!114 = !DILocation(line: 37, column: 2, scope: !99)
!115 = !DILocation(line: 38, column: 2, scope: !73)
!116 = !DILocation(line: 39, column: 2, scope: !73)
!117 = !DILocalVariable(name: "i", scope: !118, file: !3, line: 40, type: !29)
!118 = distinct !DILexicalBlock(scope: !73, file: !3, line: 40, column: 2)
!119 = !DILocation(line: 40, column: 10, scope: !118)
!120 = !DILocation(line: 40, column: 6, scope: !118)
!121 = !DILocation(line: 40, column: 16, scope: !122)
!122 = distinct !DILexicalBlock(scope: !118, file: !3, line: 40, column: 2)
!123 = !DILocation(line: 40, column: 17, scope: !122)
!124 = !DILocation(line: 40, column: 2, scope: !118)
!125 = !DILocation(line: 42, column: 3, scope: !126)
!126 = distinct !DILexicalBlock(scope: !122, file: !3, line: 41, column: 2)
!127 = !DILocation(line: 43, column: 3, scope: !126)
!128 = !DILocation(line: 44, column: 3, scope: !126)
!129 = !DILocation(line: 45, column: 2, scope: !126)
!130 = !DILocation(line: 40, column: 22, scope: !122)
!131 = !DILocation(line: 40, column: 2, scope: !122)
!132 = distinct !{!132, !124, !133}
!133 = !DILocation(line: 45, column: 2, scope: !118)
!134 = !DILocalVariable(name: "i", scope: !135, file: !3, line: 46, type: !29)
!135 = distinct !DILexicalBlock(scope: !73, file: !3, line: 46, column: 2)
!136 = !DILocation(line: 46, column: 10, scope: !135)
!137 = !DILocation(line: 46, column: 6, scope: !135)
!138 = !DILocation(line: 46, column: 16, scope: !139)
!139 = distinct !DILexicalBlock(scope: !135, file: !3, line: 46, column: 2)
!140 = !DILocation(line: 46, column: 17, scope: !139)
!141 = !DILocation(line: 46, column: 2, scope: !135)
!142 = !DILocation(line: 48, column: 3, scope: !143)
!143 = distinct !DILexicalBlock(scope: !139, file: !3, line: 47, column: 2)
!144 = !DILocation(line: 49, column: 3, scope: !143)
!145 = !DILocation(line: 50, column: 3, scope: !143)
!146 = !DILocation(line: 51, column: 2, scope: !143)
!147 = !DILocation(line: 46, column: 22, scope: !139)
!148 = !DILocation(line: 46, column: 2, scope: !139)
!149 = distinct !{!149, !141, !150}
!150 = !DILocation(line: 51, column: 2, scope: !135)
!151 = !DILocation(line: 52, column: 2, scope: !73)
!152 = !DILocalVariable(name: "x", scope: !73, file: !3, line: 54, type: !29)
!153 = !DILocation(line: 54, column: 6, scope: !73)
!154 = !DILocalVariable(name: "result", scope: !73, file: !3, line: 56, type: !29)
!155 = !DILocation(line: 56, column: 6, scope: !73)
!156 = !DILocation(line: 56, column: 20, scope: !73)
!157 = !DILocation(line: 56, column: 15, scope: !73)
!158 = !DILocation(line: 57, column: 52, scope: !73)
!159 = !DILocation(line: 57, column: 2, scope: !73)
!160 = !DILocation(line: 58, column: 20, scope: !73)
!161 = !DILocation(line: 58, column: 11, scope: !73)
!162 = !DILocation(line: 58, column: 9, scope: !73)
!163 = !DILocation(line: 59, column: 35, scope: !73)
!164 = !DILocation(line: 59, column: 2, scope: !73)
!165 = !DILocation(line: 60, column: 22, scope: !73)
!166 = !DILocation(line: 60, column: 11, scope: !73)
!167 = !DILocation(line: 60, column: 9, scope: !73)
!168 = !DILocation(line: 61, column: 37, scope: !73)
!169 = !DILocation(line: 61, column: 2, scope: !73)
!170 = !DILocalVariable(name: "func_ptr", scope: !73, file: !3, line: 62, type: !171)
!171 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !172, size: 32)
!172 = !DISubroutineType(types: !173)
!173 = !{!29, !29}
!174 = !DILocation(line: 62, column: 8, scope: !73)
!175 = !DILocation(line: 63, column: 4, scope: !73)
!176 = !DILocation(line: 63, column: 2, scope: !73)
!177 = !DILocalVariable(name: "nums", scope: !73, file: !3, line: 64, type: !178)
!178 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 160, elements: !179)
!179 = !{!180}
!180 = !DISubrange(count: 5)
!181 = !DILocation(line: 64, column: 6, scope: !73)
!182 = !DILocation(line: 65, column: 12, scope: !73)
!183 = !DILocation(line: 65, column: 2, scope: !73)
!184 = !DILocation(line: 66, column: 2, scope: !73)
!185 = !DILocation(line: 67, column: 2, scope: !73)
