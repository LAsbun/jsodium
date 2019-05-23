[![Build Status](https://travis-ci.org/naphaso/jsodium.svg?branch=master)](https://travis-ci.org/naphaso/jsodium)

# jsodium
Java libsodium bindings

## How to package.

- 先安装gcc.

- mac
  cd native; && sh build_mac.sh.
- linux
  cd native; && sh build_linux.sh.


ps:
  在哪个平台上运行就到那个操作系统，编译打包。
  **不同版本的操作系统支持的GLIBC_版本不一致**，会导致运行失败.。