; ModuleID = 'build/main.ll'
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
define dso_local i32 @main() #0 !dbg !73 !Enola-back-end-flag !77 {
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
  %10 = call i32 @stdout_init(), !dbg !78
  call void @elapsed_time_init(), !dbg !79
  call void @llvm.dbg.declare(metadata ptr %2, metadata !80, metadata !DIExpression()), !dbg !82
  store i32 0, ptr %2, align 4, !dbg !82
  br label %11, !dbg !83

11:                                               ; preds = %15, %0
  %12 = load i32, ptr %2, align 4, !dbg !84
  %13 = icmp slt i32 %12, 10, !dbg !86
  br i1 %13, label %14, label %18, !dbg !87

14:                                               ; preds = %11
  call void (...) @secure_trace_storage(), !dbg !88
  call void @elapsed_time_start(i32 noundef 0), !dbg !88
  call void @setup_S_PAC_Keys(), !dbg !90
  call void @init_registers(), !dbg !91
  call void @elapsed_time_stop(i32 noundef 0), !dbg !92
  br label %15, !dbg !93

15:                                               ; preds = %14
  %16 = load i32, ptr %2, align 4, !dbg !94
  %17 = add nsw i32 %16, 1, !dbg !94
  store i32 %17, ptr %2, align 4, !dbg !94
  br label %11, !dbg !95, !llvm.loop !96

18:                                               ; preds = %11
  call void (...) @secure_trace_storage(), !dbg !98
  call void @enable_PAC(), !dbg !98
  call void @llvm.dbg.declare(metadata ptr %3, metadata !99, metadata !DIExpression()), !dbg !101
  store i32 0, ptr %3, align 4, !dbg !101
  br label %19, !dbg !102

19:                                               ; preds = %23, %18
  %20 = load i32, ptr %3, align 4, !dbg !103
  %21 = icmp slt i32 %20, 10, !dbg !105
  br i1 %21, label %22, label %26, !dbg !106

22:                                               ; preds = %19
  call void (...) @secure_trace_storage(), !dbg !107
  call void @elapsed_time_start(i32 noundef 1), !dbg !107
  call void @init_trampoline(), !dbg !109
  call void @elapsed_time_stop(i32 noundef 1), !dbg !110
  br label %23, !dbg !111

23:                                               ; preds = %22
  %24 = load i32, ptr %3, align 4, !dbg !112
  %25 = add nsw i32 %24, 1, !dbg !112
  store i32 %25, ptr %3, align 4, !dbg !112
  br label %19, !dbg !113, !llvm.loop !114

26:                                               ; preds = %19
  call void (...) @secure_trace_storage(), !dbg !116
  %27 = call i32 (ptr, ...) @printf(ptr noundef @.str), !dbg !116
  %28 = call i32 (ptr, ...) @printf(ptr noundef @.str.1), !dbg !117
  call void @llvm.dbg.declare(metadata ptr %4, metadata !118, metadata !DIExpression()), !dbg !120
  store i32 0, ptr %4, align 4, !dbg !120
  br label %29, !dbg !121

29:                                               ; preds = %33, %26
  %30 = load i32, ptr %4, align 4, !dbg !122
  %31 = icmp slt i32 %30, 10, !dbg !124
  br i1 %31, label %32, label %36, !dbg !125

32:                                               ; preds = %29
  call void (...) @secure_trace_storage(), !dbg !126
  call void @elapsed_time_start(i32 noundef 2), !dbg !126
  call void @intialize_IBT(), !dbg !128
  call void @elapsed_time_stop(i32 noundef 2), !dbg !129
  br label %33, !dbg !130

33:                                               ; preds = %32
  %34 = load i32, ptr %4, align 4, !dbg !131
  %35 = add nsw i32 %34, 1, !dbg !131
  store i32 %35, ptr %4, align 4, !dbg !131
  br label %29, !dbg !132, !llvm.loop !133

36:                                               ; preds = %29
  call void (...) @secure_trace_storage(), !dbg !135
  call void @llvm.dbg.declare(metadata ptr %5, metadata !137, metadata !DIExpression()), !dbg !135
  store i32 0, ptr %5, align 4, !dbg !135
  br label %37, !dbg !138

37:                                               ; preds = %41, %36
  %38 = load i32, ptr %5, align 4, !dbg !139
  %39 = icmp slt i32 %38, 10, !dbg !141
  br i1 %39, label %40, label %44, !dbg !142

40:                                               ; preds = %37
  call void (...) @secure_trace_storage(), !dbg !143
  call void @elapsed_time_start(i32 noundef 3), !dbg !143
  call void @secure_trace_storage(), !dbg !145
  call void @elapsed_time_stop(i32 noundef 3), !dbg !146
  br label %41, !dbg !147

41:                                               ; preds = %40
  %42 = load i32, ptr %5, align 4, !dbg !148
  %43 = add nsw i32 %42, 1, !dbg !148
  store i32 %43, ptr %5, align 4, !dbg !148
  br label %37, !dbg !149, !llvm.loop !150

44:                                               ; preds = %37
  call void (...) @secure_trace_storage(), !dbg !152
  %45 = call i32 (ptr, ...) @printf(ptr noundef @.str.2), !dbg !152
  call void @llvm.dbg.declare(metadata ptr %6, metadata !153, metadata !DIExpression()), !dbg !154
  store i32 32, ptr %6, align 4, !dbg !154
  call void @llvm.dbg.declare(metadata ptr %7, metadata !155, metadata !DIExpression()), !dbg !156
  %46 = load i32, ptr %6, align 4, !dbg !157
  %47 = call i32 @mod2(i32 noundef %46), !dbg !158
  store i32 %47, ptr %7, align 4, !dbg !156
  %48 = load i32, ptr %7, align 4, !dbg !159
  %49 = call i32 (ptr, ...) @printf(ptr noundef @.str.3, i32 noundef %48), !dbg !160
  %50 = load i32, ptr %6, align 4, !dbg !161
  %51 = call i32 @loopOver(i32 noundef %50), !dbg !162
  store i32 %51, ptr %7, align 4, !dbg !163
  %52 = load i32, ptr %7, align 4, !dbg !164
  %53 = call i32 (ptr, ...) @printf(ptr noundef @.str.4, i32 noundef %52), !dbg !165
  %54 = load i32, ptr %6, align 4, !dbg !166
  %55 = call i32 @switchcase(i32 noundef %54), !dbg !167
  store i32 %55, ptr %7, align 4, !dbg !168
  %56 = load i32, ptr %7, align 4, !dbg !169
  %57 = call i32 (ptr, ...) @printf(ptr noundef @.str.5, i32 noundef %56), !dbg !170
  call void @llvm.dbg.declare(metadata ptr %8, metadata !171, metadata !DIExpression()), !dbg !175
  store ptr @func, ptr %8, align 4, !dbg !175
  %58 = load ptr, ptr %8, align 4, !dbg !176
  call void @indirect_secure_trace_storage(), !dbg !177
  %59 = call i32 %58(i32 noundef 10), !dbg !177
  call void @llvm.dbg.declare(metadata ptr %9, metadata !178, metadata !DIExpression()), !dbg !182
  call void @llvm.memcpy.p0.p0.i32(ptr align 4 %9, ptr align 4 @__const.main.nums, i32 20, i1 false), !dbg !182
  %60 = getelementptr inbounds [5 x i32], ptr %9, i32 0, i32 0, !dbg !183
  call void @moveZeros(ptr noundef %60, i32 noundef 5), !dbg !184
  call void @display_elapsed_times(), !dbg !185
  ret i32 0, !dbg !186
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

declare void @indirect_secure_trace_storage()

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
!77 = !{!"main"}
!78 = !DILocation(line: 22, column: 2, scope: !73)
!79 = !DILocation(line: 23, column: 2, scope: !73)
!80 = !DILocalVariable(name: "i", scope: !81, file: !3, line: 24, type: !29)
!81 = distinct !DILexicalBlock(scope: !73, file: !3, line: 24, column: 2)
!82 = !DILocation(line: 24, column: 10, scope: !81)
!83 = !DILocation(line: 24, column: 6, scope: !81)
!84 = !DILocation(line: 24, column: 16, scope: !85)
!85 = distinct !DILexicalBlock(scope: !81, file: !3, line: 24, column: 2)
!86 = !DILocation(line: 24, column: 17, scope: !85)
!87 = !DILocation(line: 24, column: 2, scope: !81)
!88 = !DILocation(line: 26, column: 3, scope: !89)
!89 = distinct !DILexicalBlock(scope: !85, file: !3, line: 25, column: 2)
!90 = !DILocation(line: 27, column: 3, scope: !89)
!91 = !DILocation(line: 28, column: 3, scope: !89)
!92 = !DILocation(line: 29, column: 3, scope: !89)
!93 = !DILocation(line: 30, column: 2, scope: !89)
!94 = !DILocation(line: 24, column: 22, scope: !85)
!95 = !DILocation(line: 24, column: 2, scope: !85)
!96 = distinct !{!96, !87, !97}
!97 = !DILocation(line: 30, column: 2, scope: !81)
!98 = !DILocation(line: 31, column: 2, scope: !73)
!99 = !DILocalVariable(name: "i", scope: !100, file: !3, line: 32, type: !29)
!100 = distinct !DILexicalBlock(scope: !73, file: !3, line: 32, column: 2)
!101 = !DILocation(line: 32, column: 10, scope: !100)
!102 = !DILocation(line: 32, column: 6, scope: !100)
!103 = !DILocation(line: 32, column: 16, scope: !104)
!104 = distinct !DILexicalBlock(scope: !100, file: !3, line: 32, column: 2)
!105 = !DILocation(line: 32, column: 17, scope: !104)
!106 = !DILocation(line: 32, column: 2, scope: !100)
!107 = !DILocation(line: 34, column: 3, scope: !108)
!108 = distinct !DILexicalBlock(scope: !104, file: !3, line: 33, column: 2)
!109 = !DILocation(line: 35, column: 3, scope: !108)
!110 = !DILocation(line: 36, column: 3, scope: !108)
!111 = !DILocation(line: 37, column: 2, scope: !108)
!112 = !DILocation(line: 32, column: 22, scope: !104)
!113 = !DILocation(line: 32, column: 2, scope: !104)
!114 = distinct !{!114, !106, !115}
!115 = !DILocation(line: 37, column: 2, scope: !100)
!116 = !DILocation(line: 38, column: 2, scope: !73)
!117 = !DILocation(line: 39, column: 2, scope: !73)
!118 = !DILocalVariable(name: "i", scope: !119, file: !3, line: 40, type: !29)
!119 = distinct !DILexicalBlock(scope: !73, file: !3, line: 40, column: 2)
!120 = !DILocation(line: 40, column: 10, scope: !119)
!121 = !DILocation(line: 40, column: 6, scope: !119)
!122 = !DILocation(line: 40, column: 16, scope: !123)
!123 = distinct !DILexicalBlock(scope: !119, file: !3, line: 40, column: 2)
!124 = !DILocation(line: 40, column: 17, scope: !123)
!125 = !DILocation(line: 40, column: 2, scope: !119)
!126 = !DILocation(line: 42, column: 3, scope: !127)
!127 = distinct !DILexicalBlock(scope: !123, file: !3, line: 41, column: 2)
!128 = !DILocation(line: 43, column: 3, scope: !127)
!129 = !DILocation(line: 44, column: 3, scope: !127)
!130 = !DILocation(line: 45, column: 2, scope: !127)
!131 = !DILocation(line: 40, column: 22, scope: !123)
!132 = !DILocation(line: 40, column: 2, scope: !123)
!133 = distinct !{!133, !125, !134}
!134 = !DILocation(line: 45, column: 2, scope: !119)
!135 = !DILocation(line: 46, column: 10, scope: !136)
!136 = distinct !DILexicalBlock(scope: !73, file: !3, line: 46, column: 2)
!137 = !DILocalVariable(name: "i", scope: !136, file: !3, line: 46, type: !29)
!138 = !DILocation(line: 46, column: 6, scope: !136)
!139 = !DILocation(line: 46, column: 16, scope: !140)
!140 = distinct !DILexicalBlock(scope: !136, file: !3, line: 46, column: 2)
!141 = !DILocation(line: 46, column: 17, scope: !140)
!142 = !DILocation(line: 46, column: 2, scope: !136)
!143 = !DILocation(line: 48, column: 3, scope: !144)
!144 = distinct !DILexicalBlock(scope: !140, file: !3, line: 47, column: 2)
!145 = !DILocation(line: 49, column: 3, scope: !144)
!146 = !DILocation(line: 50, column: 3, scope: !144)
!147 = !DILocation(line: 51, column: 2, scope: !144)
!148 = !DILocation(line: 46, column: 22, scope: !140)
!149 = !DILocation(line: 46, column: 2, scope: !140)
!150 = distinct !{!150, !142, !151}
!151 = !DILocation(line: 51, column: 2, scope: !136)
!152 = !DILocation(line: 52, column: 2, scope: !73)
!153 = !DILocalVariable(name: "x", scope: !73, file: !3, line: 54, type: !29)
!154 = !DILocation(line: 54, column: 6, scope: !73)
!155 = !DILocalVariable(name: "result", scope: !73, file: !3, line: 56, type: !29)
!156 = !DILocation(line: 56, column: 6, scope: !73)
!157 = !DILocation(line: 56, column: 20, scope: !73)
!158 = !DILocation(line: 56, column: 15, scope: !73)
!159 = !DILocation(line: 57, column: 52, scope: !73)
!160 = !DILocation(line: 57, column: 2, scope: !73)
!161 = !DILocation(line: 58, column: 20, scope: !73)
!162 = !DILocation(line: 58, column: 11, scope: !73)
!163 = !DILocation(line: 58, column: 9, scope: !73)
!164 = !DILocation(line: 59, column: 35, scope: !73)
!165 = !DILocation(line: 59, column: 2, scope: !73)
!166 = !DILocation(line: 60, column: 22, scope: !73)
!167 = !DILocation(line: 60, column: 11, scope: !73)
!168 = !DILocation(line: 60, column: 9, scope: !73)
!169 = !DILocation(line: 61, column: 37, scope: !73)
!170 = !DILocation(line: 61, column: 2, scope: !73)
!171 = !DILocalVariable(name: "func_ptr", scope: !73, file: !3, line: 62, type: !172)
!172 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !173, size: 32)
!173 = !DISubroutineType(types: !174)
!174 = !{!29, !29}
!175 = !DILocation(line: 62, column: 8, scope: !73)
!176 = !DILocation(line: 63, column: 4, scope: !73)
!177 = !DILocation(line: 63, column: 2, scope: !73)
!178 = !DILocalVariable(name: "nums", scope: !73, file: !3, line: 64, type: !179)
!179 = !DICompositeType(tag: DW_TAG_array_type, baseType: !29, size: 160, elements: !180)
!180 = !{!181}
!181 = !DISubrange(count: 5)
!182 = !DILocation(line: 64, column: 6, scope: !73)
!183 = !DILocation(line: 65, column: 12, scope: !73)
!184 = !DILocation(line: 65, column: 2, scope: !73)
!185 = !DILocation(line: 66, column: 2, scope: !73)
!186 = !DILocation(line: 67, column: 2, scope: !73)
