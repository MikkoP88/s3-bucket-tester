@echo off
REM S3 Bucket Tester - Windows Build Script
REM This script builds s3tester binary for all platforms

setlocal enabledelayedexpansion

set BINARY_NAME=s3tester
set VERSION=1.1.1
set BUILD_DIR=build
set MAIN_PATH=./cmd/s3tester
set LDFLAGS="-ldflags=-s -w -X main.version=%VERSION% -X github.com/s3-bucket-tester/s3tester/pkg/config.version=%VERSION%"

echo S3 Bucket Tester - Build Script for All Platforms
echo.

REM Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

REM Build for Windows (amd64)
echo Building %BINARY_NAME%-windows-amd64.exe for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build %LDFLAGS% -o %BUILD_DIR%\%BINARY_NAME%-windows-amd64.exe %MAIN_PATH%
if errorlevel 1 (
    echo Windows build failed!
    exit /b 1
)
echo Build complete: %BUILD_DIR%\%BINARY_NAME%-windows-amd64.exe
echo.

REM Build for Linux (amd64)
echo Building %BINARY_NAME%-linux-amd64 for Linux (amd64)...
set GOOS=linux
set GOARCH=amd64
go build %LDFLAGS% -o %BUILD_DIR%\%BINARY_NAME%-linux-amd64 %MAIN_PATH%
if errorlevel 1 (
    echo Linux amd64 build failed!
    exit /b 1
)
echo Build complete: %BUILD_DIR%\%BINARY_NAME%-linux-amd64
echo.

REM Build for Linux (arm64)
echo Building %BINARY_NAME%-linux-arm64 for Linux (arm64)...
set GOOS=linux
set GOARCH=arm64
go build %LDFLAGS% -o %BUILD_DIR%\%BINARY_NAME%-linux-arm64 %MAIN_PATH%
if errorlevel 1 (
    echo Linux arm64 build failed!
    exit /b 1
)
echo Build complete: %BUILD_DIR%\%BINARY_NAME%-linux-arm64
echo.

REM Build for macOS (amd64)
echo Building %BINARY_NAME%-darwin-amd64 for macOS (amd64)...
set GOOS=darwin
set GOARCH=amd64
go build %LDFLAGS% -o %BUILD_DIR%\%BINARY_NAME%-darwin-amd64 %MAIN_PATH%
if errorlevel 1 (
    echo macOS amd64 build failed!
    exit /b 1
)
echo Build complete: %BUILD_DIR%\%BINARY_NAME%-darwin-amd64
echo.

REM Build for macOS (arm64)
echo Building %BINARY_NAME%-darwin-arm64 for macOS (arm64)...
set GOOS=darwin
set GOARCH=arm64
go build %LDFLAGS% -o %BUILD_DIR%\%BINARY_NAME%-darwin-arm64 %MAIN_PATH%
if errorlevel 1 (
    echo macOS arm64 build failed!
    exit /b 1
)
echo Build complete: %BUILD_DIR%\%BINARY_NAME%-darwin-arm64
echo.

echo All builds complete!
echo.
echo Binaries are in the %BUILD_DIR% directory:
dir /B %BUILD_DIR%\%BINARY_NAME%*.exe
dir /B %BUILD_DIR%\%BINARY_NAME%*-*
echo.
echo Done!
