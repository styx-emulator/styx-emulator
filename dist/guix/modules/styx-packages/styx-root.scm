;; SPDX-License-Identifier: BSD-2-Clause
(define-module (styx-packages styx-root)
  #:use-module (guix)
  #:use-module (guix build-system cargo)
  #:use-module (guix git-download)
  #:use-module ((guix build cargo-build-system) #:prefix cargo-build-system:)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages rust-apps)
  #:use-module (gnu packages rust)
  #:use-module (gnu packages crates-io)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages protobuf)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages curl)
  #:use-module (gnu packages cmake)
  #:use-module (gnu packages ninja)
  #:use-module (gnu packages wget)
  #:use-module (gnu packages base)
  #:use-module (gnu packages python)
  #:use-module (gnu packages libffi)
  #:use-module (gnu packages xml)
  #:use-module (gnu packages certs)
  #:use-module (gnu packages gdb)
  #:use-module (gnu packages compression)
  #:use-module (gnu packages version-control)
  #:use-module (gnu packages containers)
  #:use-module (gnu packages docker)
  #:use-module (srfi srfi-1)
  #:use-module (styx-deps cargo-nextest)
  #:use-module (styx-deps taplo)
  #:use-module (styx-deps cargo-hakari)
  #:use-module (styx-deps cargo-llvm-cov)
  )
;;; Helper to check if the provided file is tracked under version control
;;;
;;; returns true if we are in a git checkout and the file is tracked,
;;; also unconditionally returns true when we are not in a git checkout
(define styx-vcs-file?
  (let (( vcs-file?
          ;; Return true if the given file is under version control.
          (or (git-predicate (string-append (current-source-directory) "/../.."))
              (const #t)))) ; also return true when this is not a git checkout
    ;; perform the search for local files that should get processed in the guix store
    (local-file "../.." "styx-checkout"
                #:recursive? #t
                #:select? vcs-file?)))

(define-public styx-emulator-base
  (package
   (name "styx-emulator")
   (version "0.1")
   (source styx-vcs-file?)
   (build-system cargo-build-system)
   (arguments
    '(#:phases (modify-phases %standard-phases
                              ;; TODO: allow `/data' to have binary data
                              (delete 'check-for-pregenerated-files)
                              )))
   (native-inputs
    (list rust
          clang-18
          clang-toolchain-18
          clang-runtime-18
          curl
          wget
          pkg-config
          zlib
          rust-cargo
          rust-analyzer
          rust-cargo-nextest
          rust-taplo
          ;; Blocked by:
          ;; - no llvm-tools packaged with rust
          ;; - some tests can't find git ? will probably need to patch the test support in
          ;;   to the final gexp destination for git in the test layer
          ;;rust-cargo-llvm-cov
          rust-cargo-hakari
          git
          nss-certs
          cmake
          ninja
          gnu-make
          coreutils
          sed
          protobuf
          gdb-multiarch
          python
          docker
          docker-cli
          podman
          podman-compose
          bash
          just
          which
          findutils
          ))
   (synopsis "Composable emulation for heterogeneous computing systems")
   (description
    "The STYX emulation framework is an emulation framework that allows
  users to compose created emulations into a complete system-of-systems
  digital-twin.")
   (home-page "https://github.com/styx-emulator")
   (license license:bsd-2)))

;; NOTE: we cannot yet actually build styx in a guix sandbox until
;; we have a cargo.lock dependency importer (or are allowed to publicly
;; release styx)
;; styx-emulator-base
