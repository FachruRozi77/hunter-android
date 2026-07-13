# ---------------------------------------------------------------------------
# Makefile for hunter-android (ARM/AArch64 port)
#
# Two ways to build:
#
#   1) Native, on-device (Termux on an Android phone, or any ARM64 Linux box)
#        make
#      This just uses whatever g++/clang++ is already on your $PATH. This is
#      almost certainly what you want if you're running this from Termux.
#
#   2) Cross-compile from a desktop machine using the Android NDK
#        make NDK=/path/to/android-ndk-rXX ABI=arm64-v8a API=24
#      This points the build at the NDK's prebuilt Clang toolchain instead
#      of the host compiler, and links against the NDK's OpenSSL (see notes
#      below - the NDK does not ship OpenSSL itself).
#
# Both paths produce ./hunter-android.
# ---------------------------------------------------------------------------

TARGET      := hunter-android

SRCS        := hunter-android.cpp \
               Int.cpp \
               IntGroup.cpp \
               IntMod.cpp \
               Point.cpp \
               Random.cpp \
               SECP256K1.cpp \
               Timer.cpp

OBJS        := $(SRCS:.cpp=.o)
DEPS        := $(SRCS:.cpp=.d)

CXXSTD      := -std=c++17
WARN        := -Wall -Wextra -Wno-unused-parameter
OPT         := -O3
DEFS        :=

# ---------------------------------------------------------------------------
# NDK cross-compile configuration (only used when NDK= is set on the command
# line or in the environment; ignored for native builds).
#
#   ABI  - arm64-v8a (64-bit ARM, what virtually every phone since ~2017
#          runs) or armeabi-v7a (32-bit ARM, older/budget devices). Default
#          is arm64-v8a since that's what "ARM-compatible" almost always
#          means today.
#   API  - minimum Android API level to target. 24 (Android 7.0) is a safe
#          modern default; raise it if you don't care about older devices.
# ---------------------------------------------------------------------------
NDK         ?=
ABI         ?= arm64-v8a
API         ?= 24

ifneq ($(NDK),)
  HOST_TAG  := linux-x86_64
  TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/$(HOST_TAG)

  ifeq ($(ABI),arm64-v8a)
    NDK_TARGET := aarch64-linux-android
  else ifeq ($(ABI),armeabi-v7a)
    NDK_TARGET := armv7a-linux-androideabi
  else
    $(error Unsupported ABI '$(ABI)'. Use arm64-v8a or armeabi-v7a.)
  endif

  CXX        := $(TOOLCHAIN)/bin/$(NDK_TARGET)$(API)-clang++
  AR         := $(TOOLCHAIN)/bin/llvm-ar
  STRIP      := $(TOOLCHAIN)/bin/llvm-strip
  SYSROOT    := $(TOOLCHAIN)/sysroot

  # The NDK does not bundle OpenSSL. Either:
  #   (a) build/install OpenSSL for the target ABI yourself and point
  #       OPENSSL_DIR at the install prefix (containing include/ and lib/),
  #       e.g.  make NDK=... OPENSSL_DIR=/path/to/openssl-android-arm64
  #   (b) use a prebuilt like https://github.com/KDAB/android_openssl
  #       or vcpkg's android triplet, and set OPENSSL_DIR to that.
  OPENSSL_DIR ?=
  ifeq ($(OPENSSL_DIR),)
    $(warning OPENSSL_DIR is not set - set it to a directory with \
      include/openssl/*.h and lib/libssl.a lib/libcrypto.a built for $(ABI), \
      or the link step below will fail to find OpenSSL.)
  else
    CXXFLAGS  += -I$(OPENSSL_DIR)/include
    LDFLAGS   += -L$(OPENSSL_DIR)/lib
  endif

  CXXFLAGS    += --sysroot=$(SYSROOT)
else
  # Native build: use whatever compiler is already on $PATH (Termux ships
  # clang++ by default; a desktop ARM64 Linux box would typically have g++).
  CXX         ?= $(if $(shell command -v clang++ 2>/dev/null),clang++,g++)
endif

CXXFLAGS    += $(CXXSTD) $(OPT) $(WARN) $(DEFS) -MMD -MP
LDLIBS      := -lssl -lcrypto -lpthread

.PHONY: all clean run debug release strip

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(DEPS)

# Convenience targets ---------------------------------------------------

debug: OPT := -O0 -g -fsanitize=address,undefined
debug: DEFS += -DDEBUG
debug: clean $(TARGET)

release: OPT := -O3 -flto
release: clean $(TARGET)

strip: $(TARGET)
ifneq ($(NDK),)
	$(STRIP) $(TARGET)
else
	strip $(TARGET)
endif

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)