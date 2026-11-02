#!/bin/bash
# S3 Bucket Tester - Build Script
# Builds the s3tester binary; pass --all to build every supported platform
# non-interactively.

BINARY_NAME="s3tester"
VERSION="1.2.0"
BUILD_DIR="build"
MAIN_PATH="./cmd/s3tester"
VERSION_PKG="github.com/s3-bucket-tester/s3tester/pkg/config"
LDFLAGS="-s -w -X ${VERSION_PKG}.version=${VERSION}"

echo "S3 Bucket Tester - Build Script"
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

# Build for current platform. GOOS must be exported (or prefixed on the
# command) so it reaches the go tool.
GOOS="$(echo "$OS" | tr '[:upper:]' '[:lower:]')"
echo "Building $BINARY_NAME for $OS ($GOARCH)..."
GOOS="$GOOS" GOARCH="$GOARCH" go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME" "$MAIN_PATH"
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi
echo "Build complete: $BUILD_DIR/$BINARY_NAME"
echo ""

# Build for all platforms when asked via --all, or interactively on a TTY
BUILD_ALL=false
if [ "$1" = "--all" ]; then
    BUILD_ALL=true
elif [ -t 0 ]; then
    read -p "Build for all platforms (Windows, Linux, macOS)? (y/n): " ANSWER
    if [ "$ANSWER" = "y" ] || [ "$ANSWER" = "Y" ]; then
        BUILD_ALL=true
    fi
fi

if [ "$BUILD_ALL" = true ]; then
    echo ""
    echo "Building for all platforms..."

    # Windows amd64
    echo "Building for Windows (amd64)..."
    GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-windows-amd64.exe" "$MAIN_PATH" || exit 1

    # Linux amd64
    echo "Building for Linux (amd64)..."
    GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-linux-amd64" "$MAIN_PATH" || exit 1

    # Linux arm64
    echo "Building for Linux (arm64)..."
    GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-linux-arm64" "$MAIN_PATH" || exit 1

    # macOS amd64
    echo "Building for macOS (amd64)..."
    GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-darwin-amd64" "$MAIN_PATH" || exit 1

    # macOS arm64
    echo "Building for macOS (arm64)..."
    GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-darwin-arm64" "$MAIN_PATH" || exit 1

    echo "All builds complete!"
fi

echo ""
echo "Done!"
