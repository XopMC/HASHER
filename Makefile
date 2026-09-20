# HASHER portable build driver. GNU Make 4.x is required.

.DEFAULT_GOAL := release

VERSION ?= v1.0.0
CMAKE ?= cmake
CTEST ?= ctest
NINJA ?= ninja
LLVM_PROFDATA ?= llvm-profdata

ifeq ($(OS),Windows_NT)
HOST_SYSTEM := Windows
HOST_ARCH := $(if $(PROCESSOR_ARCHITEW6432),$(PROCESSOR_ARCHITEW6432),$(PROCESSOR_ARCHITECTURE))
ifeq ($(HOST_ARCH),ARM64)
AUTO_TARGET := win-arm64
else
AUTO_TARGET := win-x64
endif
else
HOST_SYSTEM := $(shell uname -s 2>/dev/null)
HOST_ARCH := $(shell uname -m 2>/dev/null)
ifneq ($(findstring com.termux,$(PREFIX)),)
AUTO_TARGET := android-arm64-termux
else ifeq ($(HOST_SYSTEM),Darwin)
AUTO_TARGET := macos-arm64
else ifeq ($(HOST_ARCH),x86_64)
AUTO_TARGET := linux-x64
else ifneq ($(filter aarch64 arm64,$(HOST_ARCH)),)
AUTO_TARGET := linux-arm64
else
AUTO_TARGET := unsupported
endif
endif

TARGET ?= $(AUTO_TARGET)
SUPPORTED_TARGETS := win-x64 win-arm64 linux-x64 linux-arm64 macos-arm64 android-arm64-termux
ifeq ($(filter $(TARGET),$(SUPPORTED_TARGETS)),)
$(error Unsupported TARGET '$(TARGET)'; supported: $(SUPPORTED_TARGETS))
endif

ifeq ($(OS),Windows_NT)
JOBS ?= $(if $(NUMBER_OF_PROCESSORS),$(NUMBER_OF_PROCESSORS),8)
else
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 8)
endif

ifeq ($(findstring win-,$(TARGET)),win-)
ifeq ($(origin CC),default)
CC := clang-cl
endif
ifeq ($(origin CXX),default)
CXX := clang-cl
endif
LINKER ?= lld-link
EXE := HASHER.exe
else
ifeq ($(origin CC),default)
CC := clang
endif
ifeq ($(origin CXX),default)
CXX := clang++
endif
LINKER ?=
EXE := HASHER
endif

ifeq ($(TARGET),win-x64)
RELEASE_PRESET := win-x64-clang-release
DEBUG_PRESET := win-x64-clang-debug
PGO_GENERATE_PRESET := win-x64-clang-pgo-generate
PGO_USE_PRESET := win-x64-clang-pgo-use
PROFILE_NAME := win-x64
ARCHIVE := HASHER-$(VERSION)-win-x64.zip
ARCHIVE_MODE := zip
else ifeq ($(TARGET),win-arm64)
RELEASE_PRESET := win-arm64-clang-release
DEBUG_PRESET := win-arm64-clang-release
PGO_GENERATE_PRESET := win-arm64-clang-pgo-generate
PGO_USE_PRESET := win-arm64-clang-pgo-use
PROFILE_NAME := win-arm64
ARCHIVE := HASHER-$(VERSION)-win-arm64.zip
ARCHIVE_MODE := zip
else ifeq ($(TARGET),linux-x64)
RELEASE_PRESET := linux-x64-clang-mold-release
DEBUG_PRESET := linux-x64-clang-mold-debug
PGO_GENERATE_PRESET := linux-x64-clang-mold-pgo-generate
PGO_USE_PRESET := linux-x64-clang-mold-pgo-use
PROFILE_NAME := linux-x64
ARCHIVE := HASHER-$(VERSION)-linux-x64.tar.gz
ARCHIVE_MODE := tgz
else ifeq ($(TARGET),linux-arm64)
RELEASE_PRESET := linux-arm64-clang-mold-release
DEBUG_PRESET := linux-arm64-clang-mold-release
PGO_GENERATE_PRESET := linux-arm64-clang-mold-pgo-generate
PGO_USE_PRESET := linux-arm64-clang-mold-pgo-use
PROFILE_NAME := linux-arm64
ARCHIVE := HASHER-$(VERSION)-linux-arm64.tar.gz
ARCHIVE_MODE := tgz
else ifeq ($(TARGET),macos-arm64)
RELEASE_PRESET := macos-arm64-clang-release
DEBUG_PRESET := macos-arm64-clang-release
PGO_GENERATE_PRESET := macos-arm64-clang-pgo-generate
PGO_USE_PRESET := macos-arm64-clang-pgo-use
PROFILE_NAME := macos-arm64
ARCHIVE := HASHER-$(VERSION)-macos-arm64.tar.gz
ARCHIVE_MODE := tgz
else
RELEASE_PRESET := android-arm64-termux-release
DEBUG_PRESET := android-arm64-termux-release
PGO_GENERATE_PRESET := android-arm64-termux-pgo-generate
PGO_USE_PRESET := android-arm64-termux-pgo-use
PROFILE_NAME := android-arm64
ARCHIVE := HASHER-$(VERSION)-android-arm64-termux.tar.gz
ARCHIVE_MODE := tgz
endif

WORK_DIR := tests/build/$(TARGET)-release
DEBUG_DIR := tests/build/$(TARGET)-debug
PGO_GENERATE_DIR := tests/build/$(TARGET)-pgo-generate
PGO_USE_DIR := tests/build/$(TARGET)-pgo-use
PROFILE_DIR := tests/profiles/$(PROFILE_NAME)-raw
PROFILE_FILE := tests/profiles/$(PROFILE_NAME).profdata
STAGE_DIR := build/$(TARGET)
RELEASE_DIR := dist/releases/$(VERSION)

ifeq ($(TARGET),android-arm64-termux)
WORK_DIR := tests/build/android-arm64-release
DEBUG_DIR := tests/build/android-arm64-debug
PGO_GENERATE_DIR := tests/build/android-arm64-pgo-generate
PGO_USE_DIR := tests/build/android-arm64-pgo-use
endif

ifeq ($(TARGET),win-arm64)
ifeq ($(AUTO_TARGET),win-x64)
CAN_RUN := 0
else
CAN_RUN := 1
endif
else
CAN_RUN := 1
endif

CMAKE_OVERRIDES := -DCMAKE_C_COMPILER="$(CC)" -DCMAKE_CXX_COMPILER="$(CXX)" -DCMAKE_MAKE_PROGRAM="$(NINJA)"
ifneq ($(strip $(LINKER)),)
CMAKE_OVERRIDES += -DCMAKE_LINKER="$(LINKER)"
endif

.PHONY: all help detect preflight configure-release build-release run-tests stage release release-standard debug test pgo package package-existing package-one package-all checksums clean

all: release

help:
	@echo "[!] ================= HASHER BUILD HELP ================="
	@echo "[!] make                         Auto-detect and build the fastest accepted release"
	@echo "[!] make detect                  Show selected platform and toolchain"
	@echo "[!] make debug                   Build Debug into tests/build"
	@echo "[!] make test                    Build and run the complete local CTest suite"
	@echo "[!] make pgo                     Generate, merge and consume a fresh local PGO profile"
	@echo "[!] make package VERSION=v1.0.0  Build and package the current platform"
	@echo "[!] make package-all             Package all six already staged binaries"
	@echo "[!] make clean                   Remove only the selected target's generated output"
	@echo "[!] Overrides: TARGET JOBS CC CXX CMAKE CTEST NINJA LLVM_PROFDATA"
	@echo "[!] Supported: $(SUPPORTED_TARGETS)"
	@echo "[!] ====================================================="

detect:
	@echo "[!] HOST_SYSTEM : $(HOST_SYSTEM)"
	@echo "[!] HOST_ARCH   : $(HOST_ARCH)"
	@echo "[!] TARGET      : $(TARGET)"
	@echo "[!] COMPILER    : $(CC) / $(CXX)"
	@echo "[!] LINKER      : $(if $(LINKER),$(LINKER),platform default)"
	@echo "[!] PRESET      : $(RELEASE_PRESET)"
	@echo "[!] JOBS        : $(JOBS)"
	@echo "[!] POLICY      : $(if $(filter android-arm64-termux,$(TARGET)),device-native PGO + O3,O3 + verified platform LTO policy)"

preflight:
	@$(CMAKE) --version
	@$(NINJA) --version
	@$(CC) --version

configure-release: preflight
	$(CMAKE) --preset $(RELEASE_PRESET) $(CMAKE_OVERRIDES)

build-release: configure-release
	$(CMAKE) --build --preset $(RELEASE_PRESET) --parallel $(JOBS)

run-tests:
ifeq ($(CAN_RUN),1)
	$(CMAKE) -E env CTEST_OUTPUT_ON_FAILURE=1 $(CTEST) --test-dir $(WORK_DIR) --parallel $(JOBS)
else
	@echo "[!] Runtime tests skipped: $(TARGET) is cross-built on $(AUTO_TARGET)."
endif

stage:
	$(CMAKE) -E remove_directory $(STAGE_DIR)
	$(CMAKE) -E make_directory $(STAGE_DIR)
	$(CMAKE) -E copy $(WORK_DIR)/$(EXE) $(STAGE_DIR)/$(EXE)

release-standard: detect build-release run-tests stage

ifeq ($(TARGET),android-arm64-termux)
release: pgo
else
release: release-standard
endif

debug: detect preflight
	$(CMAKE) --preset $(DEBUG_PRESET) -B $(DEBUG_DIR) $(CMAKE_OVERRIDES) -DCMAKE_BUILD_TYPE=Debug -DHASHER_ENABLE_LTO=OFF
	$(CMAKE) --build $(DEBUG_DIR) --parallel $(JOBS)

test: build-release run-tests

pgo: detect preflight
	$(CMAKE) -E remove_directory $(PROFILE_DIR)
	$(CMAKE) -E make_directory $(PROFILE_DIR)
	$(CMAKE) --preset $(PGO_GENERATE_PRESET) $(CMAKE_OVERRIDES)
	$(CMAKE) --build --preset $(PGO_GENERATE_PRESET) --parallel $(JOBS)
ifeq ($(CAN_RUN),1)
	$(CMAKE) -E env LLVM_PROFILE_FILE=$(PROFILE_DIR)/%m-%p.profraw CTEST_OUTPUT_ON_FAILURE=1 $(CTEST) --test-dir $(PGO_GENERATE_DIR) --parallel $(JOBS)
	$(LLVM_PROFDATA) merge -output=$(PROFILE_FILE) $(PROFILE_DIR)/*.profraw
	$(CMAKE) --preset $(PGO_USE_PRESET) $(CMAKE_OVERRIDES)
	$(CMAKE) --build --preset $(PGO_USE_PRESET) --parallel $(JOBS)
	$(CMAKE) -E env CTEST_OUTPUT_ON_FAILURE=1 $(CTEST) --test-dir $(PGO_USE_DIR) --parallel $(JOBS)
	$(CMAKE) -E remove_directory $(STAGE_DIR)
	$(CMAKE) -E make_directory $(STAGE_DIR)
	$(CMAKE) -E copy $(PGO_USE_DIR)/$(EXE) $(STAGE_DIR)/$(EXE)
else
	@echo "[!] PGO requires native execution; cross-built $(TARGET) cannot be profiled here."
	@exit 1
endif

package: release package-one

package-existing: package-one

package-one:
	$(CMAKE) -E make_directory $(RELEASE_DIR)
ifeq ($(ARCHIVE_MODE),zip)
	$(CMAKE) -E chdir $(STAGE_DIR) $(CMAKE) -E tar cf ../../$(RELEASE_DIR)/$(ARCHIVE) --format=zip -- $(EXE)
else
	$(CMAKE) -E chdir $(STAGE_DIR) $(CMAKE) -E tar czf ../../$(RELEASE_DIR)/$(ARCHIVE) -- $(EXE)
endif

package-all:
	@$(MAKE) --no-print-directory TARGET=win-x64 VERSION=$(VERSION) package-existing
	@$(MAKE) --no-print-directory TARGET=win-arm64 VERSION=$(VERSION) package-existing
	@$(MAKE) --no-print-directory TARGET=linux-x64 VERSION=$(VERSION) package-existing
	@$(MAKE) --no-print-directory TARGET=linux-arm64 VERSION=$(VERSION) package-existing
	@$(MAKE) --no-print-directory TARGET=macos-arm64 VERSION=$(VERSION) package-existing
	@$(MAKE) --no-print-directory TARGET=android-arm64-termux VERSION=$(VERSION) package-existing
	@$(MAKE) --no-print-directory VERSION=$(VERSION) checksums

checksums:
	$(CMAKE) -E chdir $(RELEASE_DIR) $(CMAKE) -E sha256sum HASHER-$(VERSION)-win-x64.zip HASHER-$(VERSION)-win-arm64.zip HASHER-$(VERSION)-linux-x64.tar.gz HASHER-$(VERSION)-linux-arm64.tar.gz HASHER-$(VERSION)-macos-arm64.tar.gz HASHER-$(VERSION)-android-arm64-termux.tar.gz > $(RELEASE_DIR)/SHA256SUMS.txt

clean:
	$(CMAKE) -E remove_directory $(WORK_DIR)
	$(CMAKE) -E remove_directory $(DEBUG_DIR)
	$(CMAKE) -E remove_directory $(PGO_GENERATE_DIR)
	$(CMAKE) -E remove_directory $(PGO_USE_DIR)
	$(CMAKE) -E remove_directory $(STAGE_DIR)
