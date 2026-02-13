#!/bin/bash
# S3 Bucket Tester - Linux Build Script
# This script builds the s3tester binary for Linux

BINARY_NAME="s3tester"
VERSION="1.0.0"
BUILD_DIR="build"
MAIN_PATH="./cmd/s3tester"
LDFLAGS="-ldflags=-s -w -X main.version=${VERSION}"

echo "S3 Bucket Tester - Linux Build Script"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Detect OS
OS=$(uname -s)
ARCH=$(uname -m)

# Map architecture
case $ARCH in
    x86_64)
        GOARCH="amd64"
        ;;
    aarch64|arm64)
        GOARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Build for current platform
echo "Building $BINARY_NAME for $OS ($GOARCH)..."
GOOS=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
GOARCH=$GOARCH go build $LDFLAGS -o "$BUILD_DIR/$BINARY_NAME" "$MAIN_PATH"
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi
echo "Build complete: $BUILD_DIR/$BINARY_NAME"
echo ""

# Ask if user wants to build for other platforms
read -p "Build for all platforms (Windows, Linux, macOS)? (y/n): " BUILD_ALL
if [ "$BUILD_ALL" = "y" ] || [ "$BUILD_ALL" = "Y" ]; then
    echo ""
    echo "Building for all platforms..."

    # Windows amd64
    echo "Building for Windows (amd64)..."
    GOOS=windows GOARCH=amd64 go build $LDFLAGS -o "$BUILD_DIR/$BINARY_NAME-windows-amd64.exe" "$MAIN_PATH"

    # Linux amd64
    echo "Building for Linux (amd64)..."
    GOOS=linux GOARCH=amd64 go build $LDFLAGS -o "$BUILD_DIR/$BINARY_NAME-linux-amd64" "$MAIN_PATH"

    # Linux arm64
    echo "Building for Linux (arm64)..."
    GOOS=linux GOARCH=arm64 go build $LDFLAGS -o "$BUILD_DIR/$BINARY_NAME-linux-arm64" "$MAIN_PATH"

    # macOS amd64
    echo "Building for macOS (amd64)..."
    GOOS=darwin GOARCH=amd64 go build $LDFLAGS -o "$BUILD_DIR/$BINARY_NAME-darwin-amd64" "$MAIN_PATH"

    # macOS arm64
    echo "Building for macOS (arm64)..."
    GOOS=darwin GOARCH=arm64 go build $LDFLAGS -o "$BUILD_DIR/$BINARY_NAME-darwin-arm64" "$MAIN_PATH"

    echo "All builds complete!"
fi

echo ""
echo "Done!"
