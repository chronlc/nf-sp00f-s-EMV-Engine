#!/bin/bash

# EMVPort Android Library Build Script
# Builds the Android EMV library with NDK components

set -e  # Exit on any error

EMV_PROJECT_ROOT="/home/user/DEVCoDE/EMV PORT"
ANDROID_EMV_DIR="$EMV_PROJECT_ROOT/Android EMV"
WORK_DIR="$EMV_PROJECT_ROOT/Work"
BUILD_LOG="$WORK_DIR/build_logs/build_$(date +%Y%m%d_%H%M%S).log"

echo "🔧 EMVPort Android Build Script"
echo "================================"

# Create build log
mkdir -p "$WORK_DIR/build_logs"
exec > >(tee -a "$BUILD_LOG") 2>&1

echo "📝 Build log: $BUILD_LOG"
echo "🕐 Start time: $(date)"
echo ""

# Check prerequisites
echo "🔍 Checking prerequisites..."

if ! command -v gradle &> /dev/null; then
    echo "❌ Gradle not found. Please install Gradle."
    exit 1
fi

# Set environment paths
export JAVA_HOME="/opt/openjdk-bin-17"
export ANDROID_SDK_ROOT="/home/user/Android/Sdk" 
export ANDROID_HOME="$ANDROID_SDK_ROOT"
export PATH="$JAVA_HOME/bin:$ANDROID_SDK_ROOT/tools:$ANDROID_SDK_ROOT/platform-tools:$PATH"

echo "🔧 Environment Configuration:"
echo "   JAVA_HOME: $JAVA_HOME"
echo "   ANDROID_SDK_ROOT: $ANDROID_SDK_ROOT"

if [ ! -d "$ANDROID_SDK_ROOT" ]; then
    echo "❌ Android SDK not found at $ANDROID_SDK_ROOT"
    echo "   Please verify Android SDK installation."
    exit 1
fi

if [ ! -d "$ANDROID_SDK_ROOT/ndk" ]; then
    echo "❌ Android NDK not found in $ANDROID_SDK_ROOT/ndk"
    echo "   Please install Android NDK through SDK Manager."
    exit 1
fi

if [ ! -d "$JAVA_HOME" ]; then
    echo "❌ OpenJDK not found at $JAVA_HOME"
    echo "   Please verify OpenJDK 17 installation."
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Copy Proxmark EMV source files to Android project
echo "📂 Preparing Proxmark EMV source files..."

PROXMARK_SRC="$EMV_PROJECT_ROOT/Proxmark EMV"
ANDROID_CPP_DIR="$ANDROID_EMV_DIR/src/main/cpp/proxmark_port"

if [ ! -d "$ANDROID_CPP_DIR" ]; then
    echo "❌ Android C++ directory not found: $ANDROID_CPP_DIR"
    exit 1
fi

# Copy source files (will need modification for Android compatibility)
echo "   Copying C/H files..."
find "$PROXMARK_SRC" -name "*.c" -o -name "*.h" | while read file; do
    rel_path=$(realpath --relative-to="$PROXMARK_SRC" "$file")
    dest_dir="$ANDROID_CPP_DIR/$(dirname "$rel_path")"
    mkdir -p "$dest_dir"
    cp "$file" "$dest_dir/"
    echo "   Copied: $rel_path"
done

echo "✅ Source files prepared"
echo ""

# Build the Android library
echo "🔨 Building Android EMV library..."

cd "$ANDROID_EMV_DIR"

echo "   Cleaning previous build..."
./gradlew clean

echo "   Building debug version..."
if ./gradlew assembleDebug; then
    echo "✅ Debug build successful"
else
    echo "❌ Debug build failed"
    exit 1
fi

echo "   Building release version..."  
if ./gradlew assembleRelease; then
    echo "✅ Release build successful"
else
    echo "❌ Release build failed"
    exit 1
fi

# Check build outputs
echo ""
echo "📦 Build outputs:"
find . -name "*.aar" -o -name "*.so" | while read file; do
    echo "   📄 $(basename "$file"): $(realpath "$file")"
    ls -lh "$file"
done

echo ""
echo "✅ Build completed successfully!"
echo "🕐 End time: $(date)"
echo "📝 Full log: $BUILD_LOG"