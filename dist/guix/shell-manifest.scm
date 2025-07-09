;; SPDX-License-Identifier: BSD-2-Clause
(use-modules (gnu packages))
(specifications->manifest
 (list "rust"
       "rust:cargo"
       "rust:rust-src"
       "clang"
       "clang-toolchain@18.1.8"
       "clang-runtime@18.1.8"
       "curl"
       "wget"
       "pkg-config"
       "zlib"
       "rust-analyzer"
       "cargo-nextest"
       ;;"rust-taplo"
       ;; Blocked by:
       ;; - no llvm-tools packaged with rust
       ;; - some tests can't find git ? will probably need to patch the test support in
       ;;   to the final gexp destination for git in the test layer
       ;;rust-cargo-llvm-cov
       ;;"rust-cargo-hakari"
       "git"
       "nss-certs"
       "cmake@3.25.1"
       "ninja"
       "make"
       "coreutils"
       "sed"
       "protobuf"
       "gdb-multiarch"
       "python"
       "docker"
       "docker-cli"
       "podman"
       "podman-compose"
       "bash"
       "direnv"
       "just"
       "which"
       "grep"
       "findutils"
       )
 )
