; ModuleID = 'build/application.ll'
source_filename = "application.c"
target datalayout = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64"
target triple = "thumbv8.1m.main-none-unknown-eabihf"

; Function Attrs: noinline nounwind optnone
define dso_local i32 @mod2(i32 noundef %0) #0 !dbg !8 !Enola-back-end-flag !13 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !14, metadata !DIExpression()), !dbg !15
  %4 = load i32, ptr %3, align 4, !dbg !16
  %5 = srem i32 %4, 2, !dbg !18
  %6 = icmp eq i32 %5, 0, !dbg !19
  br i1 %6, label %7, label %10, !dbg !20

7:                                                ; preds = %1
  call void @secure_trace_storage(), !dbg !21
  %8 = load i32, ptr %3, align 4, !dbg !21
  %9 = add nsw i32 0, %8, !dbg !22
  store i32 %9, ptr %2, align 4, !dbg !23
  br label %13, !dbg !23

10:                                               ; preds = %1
  call void @secure_trace_storage(), !dbg !24
  %11 = load i32, ptr %3, align 4, !dbg !24
  %12 = add nsw i32 1, %11, !dbg !25
  store i32 %12, ptr %2, align 4, !dbg !26
  br label %13, !dbg !26

13:                                               ; preds = %10, %7
  %14 = load i32, ptr %2, align 4, !dbg !27
  ret i32 %14, !dbg !27
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone
define dso_local i32 @loopOver(i32 noundef %0) #0 !dbg !28 !Enola-back-end-flag !29 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !30, metadata !DIExpression()), !dbg !31
  call void @llvm.dbg.declare(metadata ptr %3, metadata !32, metadata !DIExpression()), !dbg !34
  store i32 0, ptr %3, align 4, !dbg !34
  br label %4, !dbg !35

4:                                                ; preds = %10, %1
  %5 = load i32, ptr %2, align 4, !dbg !36
  %6 = icmp sgt i32 %5, 1, !dbg !38
  br i1 %6, label %7, label %13, !dbg !39

7:                                                ; preds = %4
  call void @secure_trace_storage(), !dbg !40
  %8 = load i32, ptr %2, align 4, !dbg !40
  %9 = sdiv i32 %8, 2, !dbg !42
  store i32 %9, ptr %2, align 4, !dbg !43
  br label %10, !dbg !44

10:                                               ; preds = %7
  %11 = load i32, ptr %3, align 4, !dbg !45
  %12 = add nsw i32 %11, 1, !dbg !45
  store i32 %12, ptr %3, align 4, !dbg !45
  br label %4, !dbg !46, !llvm.loop !47

13:                                               ; preds = %4
  call void @secure_trace_storage(), !dbg !49
  %14 = load i32, ptr %2, align 4, !dbg !49
  ret i32 %14, !dbg !50
}

; Function Attrs: noinline nounwind optnone
define dso_local void @moveZeros(ptr noundef %0, i32 noundef %1) #0 !dbg !51 !Enola-back-end-flag !55 {
  %3 = alloca ptr, align 4
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  store ptr %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !56, metadata !DIExpression()), !dbg !57
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !58, metadata !DIExpression()), !dbg !59
  call void @llvm.dbg.declare(metadata ptr %5, metadata !60, metadata !DIExpression()), !dbg !61
  store i32 -1, ptr %5, align 4, !dbg !61
  call void @llvm.dbg.declare(metadata ptr %6, metadata !62, metadata !DIExpression()), !dbg !63
  store i32 0, ptr %6, align 4, !dbg !63
  call void @llvm.dbg.declare(metadata ptr %7, metadata !64, metadata !DIExpression()), !dbg !66
  store i32 0, ptr %7, align 4, !dbg !66
  br label %8, !dbg !67

8:                                                ; preds = %47, %2
  %9 = load i32, ptr %7, align 4, !dbg !68
  %10 = load i32, ptr %4, align 4, !dbg !70
  %11 = icmp slt i32 %9, %10, !dbg !71
  br i1 %11, label %12, label %50, !dbg !72

12:                                               ; preds = %8
  call void @secure_trace_storage(), !dbg !73
  %13 = load ptr, ptr %3, align 4, !dbg !73
  %14 = load i32, ptr %7, align 4, !dbg !76
  %15 = getelementptr inbounds i32, ptr %13, i32 %14, !dbg !73
  %16 = load i32, ptr %15, align 4, !dbg !73
  %17 = icmp eq i32 %16, 0, !dbg !77
  br i1 %17, label %18, label %23, !dbg !78

18:                                               ; preds = %12
  call void @secure_trace_storage(), !dbg !79
  %19 = load i32, ptr %5, align 4, !dbg !79
  %20 = icmp eq i32 %19, -1, !dbg !80
  br i1 %20, label %21, label %23, !dbg !81

21:                                               ; preds = %18
  call void @secure_trace_storage(), !dbg !82
  %22 = load i32, ptr %7, align 4, !dbg !82
  store i32 %22, ptr %5, align 4, !dbg !83
  br label %46, !dbg !84

23:                                               ; preds = %18, %12
  call void @secure_trace_storage(), !dbg !85
  %24 = load ptr, ptr %3, align 4, !dbg !85
  %25 = load i32, ptr %7, align 4, !dbg !87
  %26 = getelementptr inbounds i32, ptr %24, i32 %25, !dbg !85
  %27 = load i32, ptr %26, align 4, !dbg !85
  %28 = icmp ne i32 %27, 0, !dbg !88
  br i1 %28, label %29, label %45, !dbg !89

29:                                               ; preds = %23
  call void @secure_trace_storage(), !dbg !90
  %30 = load i32, ptr %5, align 4, !dbg !90
  %31 = icmp ne i32 %30, -1, !dbg !91
  br i1 %31, label %32, label %45, !dbg !92

32:                                               ; preds = %29
  call void @secure_trace_storage(), !dbg !93
  %33 = load ptr, ptr %3, align 4, !dbg !93
  %34 = load i32, ptr %7, align 4, !dbg !95
  %35 = getelementptr inbounds i32, ptr %33, i32 %34, !dbg !93
  %36 = load i32, ptr %35, align 4, !dbg !93
  %37 = load ptr, ptr %3, align 4, !dbg !96
  %38 = load i32, ptr %5, align 4, !dbg !97
  %39 = getelementptr inbounds i32, ptr %37, i32 %38, !dbg !96
  store i32 %36, ptr %39, align 4, !dbg !98
  %40 = load ptr, ptr %3, align 4, !dbg !99
  %41 = load i32, ptr %7, align 4, !dbg !100
  %42 = getelementptr inbounds i32, ptr %40, i32 %41, !dbg !99
  store i32 0, ptr %42, align 4, !dbg !101
  %43 = load i32, ptr %5, align 4, !dbg !102
  %44 = add nsw i32 %43, 1, !dbg !102
  store i32 %44, ptr %5, align 4, !dbg !102
  br label %45, !dbg !103

45:                                               ; preds = %32, %29, %23
  call void @secure_trace_storage()
  br label %46

46:                                               ; preds = %45, %21
  br label %47, !dbg !104

47:                                               ; preds = %46
  %48 = load i32, ptr %7, align 4, !dbg !105
  %49 = add nsw i32 %48, 1, !dbg !105
  store i32 %49, ptr %7, align 4, !dbg !105
  br label %8, !dbg !106, !llvm.loop !107

50:                                               ; preds = %8
  call void @secure_trace_storage(), !dbg !109
  ret void, !dbg !109
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @switchcase(i32 noundef %0) #0 !dbg !110 !Enola-back-end-flag !111 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !112, metadata !DIExpression()), !dbg !113
  %3 = load i32, ptr %2, align 4, !dbg !114
  %4 = srem i32 %3, 3, !dbg !115
  switch i32 %4, label %14 [
    i32 0, label %5
    i32 1, label %8
    i32 2, label %11
  ], !dbg !116

5:                                                ; preds = %1
  call void @secure_trace_storage(), !dbg !117
  %6 = load i32, ptr %2, align 4, !dbg !117
  %7 = srem i32 %6, 4, !dbg !119
  store i32 %7, ptr %2, align 4, !dbg !120
  br label %15, !dbg !121

8:                                                ; preds = %1
  call void @secure_trace_storage(), !dbg !122
  %9 = load i32, ptr %2, align 4, !dbg !122
  %10 = srem i32 %9, 5, !dbg !123
  store i32 %10, ptr %2, align 4, !dbg !124
  br label %15, !dbg !125

11:                                               ; preds = %1
  call void @secure_trace_storage(), !dbg !126
  %12 = load i32, ptr %2, align 4, !dbg !126
  %13 = srem i32 %12, 6, !dbg !127
  store i32 %13, ptr %2, align 4, !dbg !128
  br label %15, !dbg !129

14:                                               ; preds = %1
  call void @secure_trace_storage(), !dbg !130
  br label %15, !dbg !130

15:                                               ; preds = %14, %11, %8, %5
  %16 = load i32, ptr %2, align 4, !dbg !131
  ret i32 %16, !dbg !132
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @func(i32 noundef %0) #0 !dbg !133 !Enola-back-end-flag !134 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !135, metadata !DIExpression()), !dbg !136
  %3 = load i32, ptr %2, align 4, !dbg !137
  %4 = mul nsw i32 %3, 10, !dbg !138
  ret i32 %4, !dbg !139
}

declare void @secure_trace_storage()

attributes #0 = { noinline nounwind optnone "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="cortex-m85" "target-features"="+armv8.1-m.main,+dsp,+hwdiv,+lob,+mve,+pacbti,+ras,+strict-align,+thumb-mode,-aes,-bf16,-cdecp0,-cdecp1,-cdecp2,-cdecp3,-cdecp4,-cdecp5,-cdecp6,-cdecp7,-crc,-crypto,-d32,-dotprod,-fp-armv8,-fp-armv8d16,-fp-armv8d16sp,-fp-armv8sp,-fp16,-fp16fml,-fp64,-fullfp16,-hwdiv-arm,-i8mm,-mve.fp,-neon,-sb,-sha2,-vfp2,-vfp2sp,-vfp3,-vfp3d16,-vfp3d16sp,-vfp3sp,-vfp4,-vfp4d16,-vfp4d16sp,-vfp4sp" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3, !4, !5, !6}
!llvm.ident = !{!7}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 16.0.0", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "application.c", directory: "/home/tomal/Desktop/cacti_lab/code-CFA-with-pac/Evaluation/engine/sse310mps3")
!2 = !{i32 7, !"Dwarf Version", i32 2}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!5 = !{i32 1, !"min_enum_size", i32 4}
!6 = !{i32 7, !"frame-pointer", i32 2}
!7 = !{!"clang version 16.0.0"}
!8 = distinct !DISubprogram(name: "mod2", scope: !1, file: !1, line: 2, type: !9, scopeLine: 3, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!9 = !DISubroutineType(types: !10)
!10 = !{!11, !11}
!11 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!12 = !{}
!13 = !{!"mod2"}
!14 = !DILocalVariable(name: "x", arg: 1, scope: !8, file: !1, line: 2, type: !11)
!15 = !DILocation(line: 2, column: 14, scope: !8)
!16 = !DILocation(line: 4, column: 6, scope: !17)
!17 = distinct !DILexicalBlock(scope: !8, file: !1, line: 4, column: 6)
!18 = !DILocation(line: 4, column: 7, scope: !17)
!19 = !DILocation(line: 4, column: 10, scope: !17)
!20 = !DILocation(line: 4, column: 6, scope: !8)
!21 = !DILocation(line: 5, column: 14, scope: !17)
!22 = !DILocation(line: 5, column: 12, scope: !17)
!23 = !DILocation(line: 5, column: 3, scope: !17)
!24 = !DILocation(line: 7, column: 14, scope: !17)
!25 = !DILocation(line: 7, column: 12, scope: !17)
!26 = !DILocation(line: 7, column: 3, scope: !17)
!27 = !DILocation(line: 8, column: 1, scope: !8)
!28 = distinct !DISubprogram(name: "loopOver", scope: !1, file: !1, line: 9, type: !9, scopeLine: 10, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!29 = !{!"loopOver"}
!30 = !DILocalVariable(name: "x", arg: 1, scope: !28, file: !1, line: 9, type: !11)
!31 = !DILocation(line: 9, column: 18, scope: !28)
!32 = !DILocalVariable(name: "i", scope: !33, file: !1, line: 11, type: !11)
!33 = distinct !DILexicalBlock(scope: !28, file: !1, line: 11, column: 2)
!34 = !DILocation(line: 11, column: 10, scope: !33)
!35 = !DILocation(line: 11, column: 6, scope: !33)
!36 = !DILocation(line: 11, column: 17, scope: !37)
!37 = distinct !DILexicalBlock(scope: !33, file: !1, line: 11, column: 2)
!38 = !DILocation(line: 11, column: 19, scope: !37)
!39 = !DILocation(line: 11, column: 2, scope: !33)
!40 = !DILocation(line: 13, column: 7, scope: !41)
!41 = distinct !DILexicalBlock(scope: !37, file: !1, line: 12, column: 2)
!42 = !DILocation(line: 13, column: 9, scope: !41)
!43 = !DILocation(line: 13, column: 5, scope: !41)
!44 = !DILocation(line: 14, column: 2, scope: !41)
!45 = !DILocation(line: 11, column: 25, scope: !37)
!46 = !DILocation(line: 11, column: 2, scope: !37)
!47 = distinct !{!47, !39, !48}
!48 = !DILocation(line: 14, column: 2, scope: !33)
!49 = !DILocation(line: 15, column: 9, scope: !28)
!50 = !DILocation(line: 15, column: 2, scope: !28)
!51 = distinct !DISubprogram(name: "moveZeros", scope: !1, file: !1, line: 18, type: !52, scopeLine: 19, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!52 = !DISubroutineType(types: !53)
!53 = !{null, !54, !11}
!54 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 32)
!55 = !{!"moveZeros"}
!56 = !DILocalVariable(name: "nums", arg: 1, scope: !51, file: !1, line: 18, type: !54)
!57 = !DILocation(line: 18, column: 20, scope: !51)
!58 = !DILocalVariable(name: "n", arg: 2, scope: !51, file: !1, line: 18, type: !11)
!59 = !DILocation(line: 18, column: 32, scope: !51)
!60 = !DILocalVariable(name: "x", scope: !51, file: !1, line: 20, type: !11)
!61 = !DILocation(line: 20, column: 7, scope: !51)
!62 = !DILocalVariable(name: "y", scope: !51, file: !1, line: 20, type: !11)
!63 = !DILocation(line: 20, column: 15, scope: !51)
!64 = !DILocalVariable(name: "i", scope: !65, file: !1, line: 21, type: !11)
!65 = distinct !DILexicalBlock(scope: !51, file: !1, line: 21, column: 2)
!66 = !DILocation(line: 21, column: 10, scope: !65)
!67 = !DILocation(line: 21, column: 6, scope: !65)
!68 = !DILocation(line: 21, column: 18, scope: !69)
!69 = distinct !DILexicalBlock(scope: !65, file: !1, line: 21, column: 2)
!70 = !DILocation(line: 21, column: 22, scope: !69)
!71 = !DILocation(line: 21, column: 20, scope: !69)
!72 = !DILocation(line: 21, column: 2, scope: !65)
!73 = !DILocation(line: 23, column: 6, scope: !74)
!74 = distinct !DILexicalBlock(scope: !75, file: !1, line: 23, column: 6)
!75 = distinct !DILexicalBlock(scope: !69, file: !1, line: 22, column: 2)
!76 = !DILocation(line: 23, column: 11, scope: !74)
!77 = !DILocation(line: 23, column: 14, scope: !74)
!78 = !DILocation(line: 23, column: 19, scope: !74)
!79 = !DILocation(line: 23, column: 22, scope: !74)
!80 = !DILocation(line: 23, column: 24, scope: !74)
!81 = !DILocation(line: 23, column: 6, scope: !75)
!82 = !DILocation(line: 24, column: 8, scope: !74)
!83 = !DILocation(line: 24, column: 6, scope: !74)
!84 = !DILocation(line: 24, column: 4, scope: !74)
!85 = !DILocation(line: 25, column: 11, scope: !86)
!86 = distinct !DILexicalBlock(scope: !74, file: !1, line: 25, column: 11)
!87 = !DILocation(line: 25, column: 16, scope: !86)
!88 = !DILocation(line: 25, column: 19, scope: !86)
!89 = !DILocation(line: 25, column: 24, scope: !86)
!90 = !DILocation(line: 25, column: 27, scope: !86)
!91 = !DILocation(line: 25, column: 29, scope: !86)
!92 = !DILocation(line: 25, column: 11, scope: !74)
!93 = !DILocation(line: 27, column: 14, scope: !94)
!94 = distinct !DILexicalBlock(scope: !86, file: !1, line: 26, column: 3)
!95 = !DILocation(line: 27, column: 19, scope: !94)
!96 = !DILocation(line: 27, column: 4, scope: !94)
!97 = !DILocation(line: 27, column: 9, scope: !94)
!98 = !DILocation(line: 27, column: 12, scope: !94)
!99 = !DILocation(line: 28, column: 4, scope: !94)
!100 = !DILocation(line: 28, column: 9, scope: !94)
!101 = !DILocation(line: 28, column: 12, scope: !94)
!102 = !DILocation(line: 29, column: 5, scope: !94)
!103 = !DILocation(line: 30, column: 3, scope: !94)
!104 = !DILocation(line: 31, column: 2, scope: !75)
!105 = !DILocation(line: 21, column: 26, scope: !69)
!106 = !DILocation(line: 21, column: 2, scope: !69)
!107 = distinct !{!107, !72, !108}
!108 = !DILocation(line: 31, column: 2, scope: !65)
!109 = !DILocation(line: 32, column: 1, scope: !51)
!110 = distinct !DISubprogram(name: "switchcase", scope: !1, file: !1, line: 34, type: !9, scopeLine: 35, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!111 = !{!"switchcase"}
!112 = !DILocalVariable(name: "x", arg: 1, scope: !110, file: !1, line: 34, type: !11)
!113 = !DILocation(line: 34, column: 20, scope: !110)
!114 = !DILocation(line: 36, column: 9, scope: !110)
!115 = !DILocation(line: 36, column: 11, scope: !110)
!116 = !DILocation(line: 36, column: 2, scope: !110)
!117 = !DILocation(line: 39, column: 8, scope: !118)
!118 = distinct !DILexicalBlock(scope: !110, file: !1, line: 37, column: 2)
!119 = !DILocation(line: 39, column: 10, scope: !118)
!120 = !DILocation(line: 39, column: 6, scope: !118)
!121 = !DILocation(line: 40, column: 4, scope: !118)
!122 = !DILocation(line: 42, column: 8, scope: !118)
!123 = !DILocation(line: 42, column: 10, scope: !118)
!124 = !DILocation(line: 42, column: 6, scope: !118)
!125 = !DILocation(line: 43, column: 4, scope: !118)
!126 = !DILocation(line: 45, column: 8, scope: !118)
!127 = !DILocation(line: 45, column: 10, scope: !118)
!128 = !DILocation(line: 45, column: 6, scope: !118)
!129 = !DILocation(line: 46, column: 4, scope: !118)
!130 = !DILocation(line: 48, column: 4, scope: !118)
!131 = !DILocation(line: 51, column: 9, scope: !110)
!132 = !DILocation(line: 51, column: 2, scope: !110)
!133 = distinct !DISubprogram(name: "func", scope: !1, file: !1, line: 54, type: !9, scopeLine: 55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!134 = !{!"func"}
!135 = !DILocalVariable(name: "a", arg: 1, scope: !133, file: !1, line: 54, type: !11)
!136 = !DILocation(line: 54, column: 14, scope: !133)
!137 = !DILocation(line: 56, column: 16, scope: !133)
!138 = !DILocation(line: 56, column: 17, scope: !133)
!139 = !DILocation(line: 56, column: 9, scope: !133)
