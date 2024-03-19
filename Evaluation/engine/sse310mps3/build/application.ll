; ModuleID = 'application.c'
source_filename = "application.c"
target datalayout = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64"
target triple = "thumbv8.1m.main-none-unknown-eabihf"

; Function Attrs: noinline nounwind optnone
define dso_local i32 @mod2(i32 noundef %0) #0 !dbg !8 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !13, metadata !DIExpression()), !dbg !14
  %4 = load i32, ptr %3, align 4, !dbg !15
  %5 = srem i32 %4, 2, !dbg !17
  %6 = icmp eq i32 %5, 0, !dbg !18
  br i1 %6, label %7, label %10, !dbg !19

7:                                                ; preds = %1
  %8 = load i32, ptr %3, align 4, !dbg !20
  %9 = add nsw i32 0, %8, !dbg !21
  store i32 %9, ptr %2, align 4, !dbg !22
  br label %13, !dbg !22

10:                                               ; preds = %1
  %11 = load i32, ptr %3, align 4, !dbg !23
  %12 = add nsw i32 1, %11, !dbg !24
  store i32 %12, ptr %2, align 4, !dbg !25
  br label %13, !dbg !25

13:                                               ; preds = %10, %7
  %14 = load i32, ptr %2, align 4, !dbg !26
  ret i32 %14, !dbg !26
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone
define dso_local i32 @loopOver(i32 noundef %0) #0 !dbg !27 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !28, metadata !DIExpression()), !dbg !29
  call void @llvm.dbg.declare(metadata ptr %3, metadata !30, metadata !DIExpression()), !dbg !32
  store i32 0, ptr %3, align 4, !dbg !32
  br label %4, !dbg !33

4:                                                ; preds = %10, %1
  %5 = load i32, ptr %2, align 4, !dbg !34
  %6 = icmp sgt i32 %5, 1, !dbg !36
  br i1 %6, label %7, label %13, !dbg !37

7:                                                ; preds = %4
  %8 = load i32, ptr %2, align 4, !dbg !38
  %9 = sdiv i32 %8, 2, !dbg !40
  store i32 %9, ptr %2, align 4, !dbg !41
  br label %10, !dbg !42

10:                                               ; preds = %7
  %11 = load i32, ptr %3, align 4, !dbg !43
  %12 = add nsw i32 %11, 1, !dbg !43
  store i32 %12, ptr %3, align 4, !dbg !43
  br label %4, !dbg !44, !llvm.loop !45

13:                                               ; preds = %4
  %14 = load i32, ptr %2, align 4, !dbg !47
  ret i32 %14, !dbg !48
}

; Function Attrs: noinline nounwind optnone
define dso_local void @moveZeros(ptr noundef %0, i32 noundef %1) #0 !dbg !49 {
  %3 = alloca ptr, align 4
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  store ptr %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !53, metadata !DIExpression()), !dbg !54
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !55, metadata !DIExpression()), !dbg !56
  call void @llvm.dbg.declare(metadata ptr %5, metadata !57, metadata !DIExpression()), !dbg !58
  store i32 -1, ptr %5, align 4, !dbg !58
  call void @llvm.dbg.declare(metadata ptr %6, metadata !59, metadata !DIExpression()), !dbg !60
  store i32 0, ptr %6, align 4, !dbg !60
  call void @llvm.dbg.declare(metadata ptr %7, metadata !61, metadata !DIExpression()), !dbg !63
  store i32 0, ptr %7, align 4, !dbg !63
  br label %8, !dbg !64

8:                                                ; preds = %47, %2
  %9 = load i32, ptr %7, align 4, !dbg !65
  %10 = load i32, ptr %4, align 4, !dbg !67
  %11 = icmp slt i32 %9, %10, !dbg !68
  br i1 %11, label %12, label %50, !dbg !69

12:                                               ; preds = %8
  %13 = load ptr, ptr %3, align 4, !dbg !70
  %14 = load i32, ptr %7, align 4, !dbg !73
  %15 = getelementptr inbounds i32, ptr %13, i32 %14, !dbg !70
  %16 = load i32, ptr %15, align 4, !dbg !70
  %17 = icmp eq i32 %16, 0, !dbg !74
  br i1 %17, label %18, label %23, !dbg !75

18:                                               ; preds = %12
  %19 = load i32, ptr %5, align 4, !dbg !76
  %20 = icmp eq i32 %19, -1, !dbg !77
  br i1 %20, label %21, label %23, !dbg !78

21:                                               ; preds = %18
  %22 = load i32, ptr %7, align 4, !dbg !79
  store i32 %22, ptr %5, align 4, !dbg !80
  br label %46, !dbg !81

23:                                               ; preds = %18, %12
  %24 = load ptr, ptr %3, align 4, !dbg !82
  %25 = load i32, ptr %7, align 4, !dbg !84
  %26 = getelementptr inbounds i32, ptr %24, i32 %25, !dbg !82
  %27 = load i32, ptr %26, align 4, !dbg !82
  %28 = icmp ne i32 %27, 0, !dbg !85
  br i1 %28, label %29, label %45, !dbg !86

29:                                               ; preds = %23
  %30 = load i32, ptr %5, align 4, !dbg !87
  %31 = icmp ne i32 %30, -1, !dbg !88
  br i1 %31, label %32, label %45, !dbg !89

32:                                               ; preds = %29
  %33 = load ptr, ptr %3, align 4, !dbg !90
  %34 = load i32, ptr %7, align 4, !dbg !92
  %35 = getelementptr inbounds i32, ptr %33, i32 %34, !dbg !90
  %36 = load i32, ptr %35, align 4, !dbg !90
  %37 = load ptr, ptr %3, align 4, !dbg !93
  %38 = load i32, ptr %5, align 4, !dbg !94
  %39 = getelementptr inbounds i32, ptr %37, i32 %38, !dbg !93
  store i32 %36, ptr %39, align 4, !dbg !95
  %40 = load ptr, ptr %3, align 4, !dbg !96
  %41 = load i32, ptr %7, align 4, !dbg !97
  %42 = getelementptr inbounds i32, ptr %40, i32 %41, !dbg !96
  store i32 0, ptr %42, align 4, !dbg !98
  %43 = load i32, ptr %5, align 4, !dbg !99
  %44 = add nsw i32 %43, 1, !dbg !99
  store i32 %44, ptr %5, align 4, !dbg !99
  br label %45, !dbg !100

45:                                               ; preds = %32, %29, %23
  br label %46

46:                                               ; preds = %45, %21
  br label %47, !dbg !101

47:                                               ; preds = %46
  %48 = load i32, ptr %7, align 4, !dbg !102
  %49 = add nsw i32 %48, 1, !dbg !102
  store i32 %49, ptr %7, align 4, !dbg !102
  br label %8, !dbg !103, !llvm.loop !104

50:                                               ; preds = %8
  ret void, !dbg !106
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @switchcase(i32 noundef %0) #0 !dbg !107 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !108, metadata !DIExpression()), !dbg !109
  %3 = load i32, ptr %2, align 4, !dbg !110
  %4 = srem i32 %3, 3, !dbg !111
  switch i32 %4, label %14 [
    i32 0, label %5
    i32 1, label %8
    i32 2, label %11
  ], !dbg !112

5:                                                ; preds = %1
  %6 = load i32, ptr %2, align 4, !dbg !113
  %7 = srem i32 %6, 4, !dbg !115
  store i32 %7, ptr %2, align 4, !dbg !116
  br label %15, !dbg !117

8:                                                ; preds = %1
  %9 = load i32, ptr %2, align 4, !dbg !118
  %10 = srem i32 %9, 5, !dbg !119
  store i32 %10, ptr %2, align 4, !dbg !120
  br label %15, !dbg !121

11:                                               ; preds = %1
  %12 = load i32, ptr %2, align 4, !dbg !122
  %13 = srem i32 %12, 6, !dbg !123
  store i32 %13, ptr %2, align 4, !dbg !124
  br label %15, !dbg !125

14:                                               ; preds = %1
  br label %15, !dbg !126

15:                                               ; preds = %14, %11, %8, %5
  %16 = load i32, ptr %2, align 4, !dbg !127
  ret i32 %16, !dbg !128
}

; Function Attrs: noinline nounwind optnone
define dso_local i32 @func(i32 noundef %0) #0 !dbg !129 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !130, metadata !DIExpression()), !dbg !131
  %3 = load i32, ptr %2, align 4, !dbg !132
  %4 = mul nsw i32 %3, 10, !dbg !133
  ret i32 %4, !dbg !134
}

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
!13 = !DILocalVariable(name: "x", arg: 1, scope: !8, file: !1, line: 2, type: !11)
!14 = !DILocation(line: 2, column: 14, scope: !8)
!15 = !DILocation(line: 4, column: 6, scope: !16)
!16 = distinct !DILexicalBlock(scope: !8, file: !1, line: 4, column: 6)
!17 = !DILocation(line: 4, column: 7, scope: !16)
!18 = !DILocation(line: 4, column: 10, scope: !16)
!19 = !DILocation(line: 4, column: 6, scope: !8)
!20 = !DILocation(line: 5, column: 14, scope: !16)
!21 = !DILocation(line: 5, column: 12, scope: !16)
!22 = !DILocation(line: 5, column: 3, scope: !16)
!23 = !DILocation(line: 7, column: 14, scope: !16)
!24 = !DILocation(line: 7, column: 12, scope: !16)
!25 = !DILocation(line: 7, column: 3, scope: !16)
!26 = !DILocation(line: 8, column: 1, scope: !8)
!27 = distinct !DISubprogram(name: "loopOver", scope: !1, file: !1, line: 9, type: !9, scopeLine: 10, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!28 = !DILocalVariable(name: "x", arg: 1, scope: !27, file: !1, line: 9, type: !11)
!29 = !DILocation(line: 9, column: 18, scope: !27)
!30 = !DILocalVariable(name: "i", scope: !31, file: !1, line: 11, type: !11)
!31 = distinct !DILexicalBlock(scope: !27, file: !1, line: 11, column: 2)
!32 = !DILocation(line: 11, column: 10, scope: !31)
!33 = !DILocation(line: 11, column: 6, scope: !31)
!34 = !DILocation(line: 11, column: 17, scope: !35)
!35 = distinct !DILexicalBlock(scope: !31, file: !1, line: 11, column: 2)
!36 = !DILocation(line: 11, column: 19, scope: !35)
!37 = !DILocation(line: 11, column: 2, scope: !31)
!38 = !DILocation(line: 13, column: 7, scope: !39)
!39 = distinct !DILexicalBlock(scope: !35, file: !1, line: 12, column: 2)
!40 = !DILocation(line: 13, column: 9, scope: !39)
!41 = !DILocation(line: 13, column: 5, scope: !39)
!42 = !DILocation(line: 14, column: 2, scope: !39)
!43 = !DILocation(line: 11, column: 25, scope: !35)
!44 = !DILocation(line: 11, column: 2, scope: !35)
!45 = distinct !{!45, !37, !46}
!46 = !DILocation(line: 14, column: 2, scope: !31)
!47 = !DILocation(line: 15, column: 9, scope: !27)
!48 = !DILocation(line: 15, column: 2, scope: !27)
!49 = distinct !DISubprogram(name: "moveZeros", scope: !1, file: !1, line: 18, type: !50, scopeLine: 19, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!50 = !DISubroutineType(types: !51)
!51 = !{null, !52, !11}
!52 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 32)
!53 = !DILocalVariable(name: "nums", arg: 1, scope: !49, file: !1, line: 18, type: !52)
!54 = !DILocation(line: 18, column: 20, scope: !49)
!55 = !DILocalVariable(name: "n", arg: 2, scope: !49, file: !1, line: 18, type: !11)
!56 = !DILocation(line: 18, column: 32, scope: !49)
!57 = !DILocalVariable(name: "x", scope: !49, file: !1, line: 20, type: !11)
!58 = !DILocation(line: 20, column: 7, scope: !49)
!59 = !DILocalVariable(name: "y", scope: !49, file: !1, line: 20, type: !11)
!60 = !DILocation(line: 20, column: 15, scope: !49)
!61 = !DILocalVariable(name: "i", scope: !62, file: !1, line: 21, type: !11)
!62 = distinct !DILexicalBlock(scope: !49, file: !1, line: 21, column: 2)
!63 = !DILocation(line: 21, column: 10, scope: !62)
!64 = !DILocation(line: 21, column: 6, scope: !62)
!65 = !DILocation(line: 21, column: 18, scope: !66)
!66 = distinct !DILexicalBlock(scope: !62, file: !1, line: 21, column: 2)
!67 = !DILocation(line: 21, column: 22, scope: !66)
!68 = !DILocation(line: 21, column: 20, scope: !66)
!69 = !DILocation(line: 21, column: 2, scope: !62)
!70 = !DILocation(line: 23, column: 6, scope: !71)
!71 = distinct !DILexicalBlock(scope: !72, file: !1, line: 23, column: 6)
!72 = distinct !DILexicalBlock(scope: !66, file: !1, line: 22, column: 2)
!73 = !DILocation(line: 23, column: 11, scope: !71)
!74 = !DILocation(line: 23, column: 14, scope: !71)
!75 = !DILocation(line: 23, column: 19, scope: !71)
!76 = !DILocation(line: 23, column: 22, scope: !71)
!77 = !DILocation(line: 23, column: 24, scope: !71)
!78 = !DILocation(line: 23, column: 6, scope: !72)
!79 = !DILocation(line: 24, column: 8, scope: !71)
!80 = !DILocation(line: 24, column: 6, scope: !71)
!81 = !DILocation(line: 24, column: 4, scope: !71)
!82 = !DILocation(line: 25, column: 11, scope: !83)
!83 = distinct !DILexicalBlock(scope: !71, file: !1, line: 25, column: 11)
!84 = !DILocation(line: 25, column: 16, scope: !83)
!85 = !DILocation(line: 25, column: 19, scope: !83)
!86 = !DILocation(line: 25, column: 24, scope: !83)
!87 = !DILocation(line: 25, column: 27, scope: !83)
!88 = !DILocation(line: 25, column: 29, scope: !83)
!89 = !DILocation(line: 25, column: 11, scope: !71)
!90 = !DILocation(line: 27, column: 14, scope: !91)
!91 = distinct !DILexicalBlock(scope: !83, file: !1, line: 26, column: 3)
!92 = !DILocation(line: 27, column: 19, scope: !91)
!93 = !DILocation(line: 27, column: 4, scope: !91)
!94 = !DILocation(line: 27, column: 9, scope: !91)
!95 = !DILocation(line: 27, column: 12, scope: !91)
!96 = !DILocation(line: 28, column: 4, scope: !91)
!97 = !DILocation(line: 28, column: 9, scope: !91)
!98 = !DILocation(line: 28, column: 12, scope: !91)
!99 = !DILocation(line: 29, column: 5, scope: !91)
!100 = !DILocation(line: 30, column: 3, scope: !91)
!101 = !DILocation(line: 31, column: 2, scope: !72)
!102 = !DILocation(line: 21, column: 26, scope: !66)
!103 = !DILocation(line: 21, column: 2, scope: !66)
!104 = distinct !{!104, !69, !105}
!105 = !DILocation(line: 31, column: 2, scope: !62)
!106 = !DILocation(line: 32, column: 1, scope: !49)
!107 = distinct !DISubprogram(name: "switchcase", scope: !1, file: !1, line: 34, type: !9, scopeLine: 35, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!108 = !DILocalVariable(name: "x", arg: 1, scope: !107, file: !1, line: 34, type: !11)
!109 = !DILocation(line: 34, column: 20, scope: !107)
!110 = !DILocation(line: 36, column: 9, scope: !107)
!111 = !DILocation(line: 36, column: 11, scope: !107)
!112 = !DILocation(line: 36, column: 2, scope: !107)
!113 = !DILocation(line: 39, column: 8, scope: !114)
!114 = distinct !DILexicalBlock(scope: !107, file: !1, line: 37, column: 2)
!115 = !DILocation(line: 39, column: 10, scope: !114)
!116 = !DILocation(line: 39, column: 6, scope: !114)
!117 = !DILocation(line: 40, column: 4, scope: !114)
!118 = !DILocation(line: 42, column: 8, scope: !114)
!119 = !DILocation(line: 42, column: 10, scope: !114)
!120 = !DILocation(line: 42, column: 6, scope: !114)
!121 = !DILocation(line: 43, column: 4, scope: !114)
!122 = !DILocation(line: 45, column: 8, scope: !114)
!123 = !DILocation(line: 45, column: 10, scope: !114)
!124 = !DILocation(line: 45, column: 6, scope: !114)
!125 = !DILocation(line: 46, column: 4, scope: !114)
!126 = !DILocation(line: 48, column: 4, scope: !114)
!127 = !DILocation(line: 51, column: 9, scope: !107)
!128 = !DILocation(line: 51, column: 2, scope: !107)
!129 = distinct !DISubprogram(name: "func", scope: !1, file: !1, line: 54, type: !9, scopeLine: 55, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !12)
!130 = !DILocalVariable(name: "a", arg: 1, scope: !129, file: !1, line: 54, type: !11)
!131 = !DILocation(line: 54, column: 14, scope: !129)
!132 = !DILocation(line: 56, column: 16, scope: !129)
!133 = !DILocation(line: 56, column: 17, scope: !129)
!134 = !DILocation(line: 56, column: 9, scope: !129)
