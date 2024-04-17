TOOLCHAIN="+stable-x86_64-unknown-linux-gnu"
RUSTFLAGS+=""
MUSL="x86_64-unknown-linux-musl"
RELEASEPATH="target/x86_64-unknown-linux-musl/debug/ring"

ifdef DADK_CURRENT_BUILD_DIR
# 如果是在dadk中编译，那么安装到dadk的安装目录中
	INSTALL_DIR = $(DADK_CURRENT_BUILD_DIR)
else
# 如果是在本地编译，那么安装到当前目录下的install目录中
	INSTALL_DIR = ./
endif

ifeq ($(ARCH), x86_64)
	export RUST_TARGET=x86_64-unknown-linux-gnu
else ifeq ($(ARCH), riscv64)
	export RUST_TARGET=riscv64gc-unknown-linux-gnu
else 
# 默认为x86_86，用于本地编译
	export RUST_TARGET=x86_64-unknown-linux-gnu
endif

build:
	RUSTFLAGS=$(RUSTFLAGS) cargo $(TOOLCHAIN) build --target $(MUSL)

clean:
	RUSTFLAGS=$(RUSTFLAGS) cargo $(TOOLCHAIN) clean --target $(MUSL)

.PHONY: install
install:
	RUSTFLAGS=$(RUSTFLAGS) cargo $(TOOLCHAIN) build --target $(MUSL)
	mv $(RELEASEPATH) $(INSTALL_DIR)
