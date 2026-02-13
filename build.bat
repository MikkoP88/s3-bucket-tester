@echo off
REM S3 Bucket Tester - Windows Build Script
REM This script builds s3tester binary for Windows

setlocal enabledelayedexpansion

set BINARY_NAME=s3tester
set VERSION=1.0.0
set BUILD_DIR=build
set MAIN_PATH=./cmd/s3tester
set LDFLAGS=-ldflags="-s -w -X main.version=%VERSION%"

echo S3 Bucket Tester - Windows Build Script
echo.

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Build for Windows
echo Building %BINARY_NAME%.exe for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build %LDFLAGS% -o %BUILD_DIR%\%BINARY_NAME%.exe %MAIN_PATH%
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)
echo Build complete: %BUILD_DIR%\%BINARY_NAME%.exe
echo.

echo Done!
