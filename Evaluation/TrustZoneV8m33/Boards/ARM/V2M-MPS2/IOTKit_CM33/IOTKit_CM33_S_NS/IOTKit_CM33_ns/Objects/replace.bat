@echo off

REM Define file paths
set "target_file=IOTKit_CM33_ns.axf"
set "source_file=Blinky.axf"

REM Check if the target file exists and delete it
if exist "%target_file%" (
    del "%target_file%"
    echo Deleted %target_file%
)

REM Check if the source file exists and rename it
if exist "%source_file%" (
    rename "%source_file%" "%target_file%"
    echo Renamed %source_file% to %target_file%
) else (
    echo %source_file% not found.
)

pause