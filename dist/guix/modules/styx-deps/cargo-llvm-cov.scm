;; SPDX-License-Identifier: BSD-2-Clause
(define-module (styx-deps cargo-llvm-cov)
  #:use-module (guix)
  #:use-module (guix build-system cargo)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages crates-io)
  #:use-module (gnu packages version-control)
  #:use-module (guix git-download)
  )


(define rust-easy-ext-1
  (package
   (name "rust-easy-ext")
   (version "1.0.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "easy-ext" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1ji10705mkixg8x07ds0736h0f9qcij5f56ysznwmy04hmm6spfc"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/taiki-e/easy-ext")
   (synopsis
    "lightweight attribute macro for easily writing extension trait pattern.")
   (description
    "This package provides a lightweight attribute macro for easily writing extension
trait pattern.")
   (license (list license:asl2.0 license:expat))))

(define rust-ruzstd-0.7
  (package
   (name "rust-ruzstd")
   (version "0.7.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "ruzstd" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "08ffshmfmmcgijcg4w517clpsxwknga89inxjw4hgb1s2f797hwr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-rustc-std-workspace-alloc" ,rust-rustc-std-workspace-alloc-1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1)
                      ("rust-twox-hash" ,rust-twox-hash-1))))
   (home-page "https://github.com/KillingSpark/zstd-rs")
   (synopsis "decoder for the zstd compression format")
   (description
    "This package provides a decoder for the zstd compression format.")
   (license license:expat)))

(define rust-windows-x86-64-msvc-0.52
  (package
   (name "rust-windows-x86-64-msvc")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_x86_64_msvc" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1v7rb5cibyzx8vak29pdrk8nx9hycsjs4w0jgms08qk49jl6v7sq"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-x86-64-gnullvm-0.52
  (package
   (name "rust-windows-x86-64-gnullvm")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_x86_64_gnullvm" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "03gda7zjx1qh8k9nnlgb7m3w3s1xkysg55hkd1wjch8pqhyv5m94"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-x86-64-gnu-0.52
  (package
   (name "rust-windows-x86-64-gnu")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_x86_64_gnu" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0y0sifqcb56a56mvn7xjgs8g43p33mfqkd8wj1yhrgxzma05qyhl"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-i686-msvc-0.52
  (package
   (name "rust-windows-i686-msvc")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_i686_msvc" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0rkcqmp4zzmfvrrrx01260q3xkpzi6fzi2x2pgdcdry50ny4h294"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-i686-gnullvm-0.52
  (package
   (name "rust-windows-i686-gnullvm")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_i686_gnullvm" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0rpdx1537mw6slcpqa0rm3qixmsb79nbhqy5fsm3q2q9ik9m5vhf"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-i686-gnu-0.52
  (package
   (name "rust-windows-i686-gnu")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_i686_gnu" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "02zspglbykh1jh9pi7gn8g1f97jh1rrccni9ivmrfbl0mgamm6wf"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-aarch64-msvc-0.52
  (package
   (name "rust-windows-aarch64-msvc")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_aarch64_msvc" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0sfl0nysnz32yyfh773hpi49b1q700ah6y7sacmjbqjjn5xjmv09"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-aarch64-gnullvm-0.52
  (package
   (name "rust-windows-aarch64-gnullvm")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows_aarch64_gnullvm" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1lrcq38cr2arvmz19v32qaggvj8bh1640mdm9c2fr877h0hn591j"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import lib for Windows")
   (description "This package provides Import lib for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-targets-0.52
  (package
   (name "rust-windows-targets")
   (version "0.52.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows-targets" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0wwrx625nwlfp7k93r2rra568gad1mwd888h1jwnl0vfg5r4ywlv"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-windows-aarch64-gnullvm" ,rust-windows-aarch64-gnullvm-0.52)
                      ("rust-windows-aarch64-msvc" ,rust-windows-aarch64-msvc-0.52)
                      ("rust-windows-i686-gnu" ,rust-windows-i686-gnu-0.52)
                      ("rust-windows-i686-gnullvm" ,rust-windows-i686-gnullvm-0.52)
                      ("rust-windows-i686-msvc" ,rust-windows-i686-msvc-0.52)
                      ("rust-windows-x86-64-gnu" ,rust-windows-x86-64-gnu-0.52)
                      ("rust-windows-x86-64-gnullvm" ,rust-windows-x86-64-gnullvm-0.52)
                      ("rust-windows-x86-64-msvc" ,rust-windows-x86-64-msvc-0.52))))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Import libs for Windows")
   (description "This package provides Import libs for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-windows-sys-0.59
  (package
   (name "rust-windows-sys")
   (version "0.59.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "windows-sys" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0fw5672ziw8b3zpmnbp9pdv1famk74f1l9fcbc3zsrzdg56vqf0y"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-windows-targets" ,rust-windows-targets-0.52))))
   (home-page "https://github.com/microsoft/windows-rs")
   (synopsis "Rust for Windows")
   (description "This package provides Rust for Windows.")
   (license (list license:expat license:asl2.0))))

(define rust-opener-0.7
  (package
   (name "rust-opener")
   (version "0.7.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "opener" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "10bn0m6pfv9mvv9lky0l48fb6vflx9pkg8sir1aa73gh9mg2x0fh"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bstr" ,rust-bstr-1)
                      ("rust-dbus" ,rust-dbus-0.9)
                      ("rust-normpath" ,rust-normpath-1)
                      ("rust-url" ,rust-url-2)
                      ("rust-windows-sys" ,rust-windows-sys-0.59))))
   (home-page "https://github.com/Seeker14491/opener")
   (synopsis "Open a file or link using the system default program")
   (description
    "This package provides Open a file or link using the system default program.")
   (license (list license:expat license:asl2.0))))

(define rust-rustc-demangle-0.1
  (package
   (name "rust-rustc-demangle")
   (version "0.1.24")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "rustc-demangle" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "07zysaafgrkzy2rjgwqdj2a8qdpsm6zv6f5pgpk9x0lm40z9b6vi"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1))))
   (home-page "https://github.com/rust-lang/rustc-demangle")
   (synopsis "Rust compiler symbol demangling.")
   (description "This package provides Rust compiler symbol demangling.")
   (license (list license:expat license:asl2.0))))

(define rust-lcov2cobertura-1
  (package
   (name "rust-lcov2cobertura")
   (version "1.0.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "lcov2cobertura" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1ww9myklqmkia327n7342lmz6ljg2493rm1g81nf6w0904nhhn9h"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-anyhow" ,rust-anyhow-1)
                      ("rust-quick-xml" ,rust-quick-xml-0.31)
                      ("rust-regex" ,rust-regex-1)
                      ("rust-rustc-demangle" ,rust-rustc-demangle-0.1))))
   (home-page "https://github.com/mike-kfed/lcov2cobertura")
   (synopsis "convert LCOV info file to cobertura XML format")
   (description
    "This package provides convert LCOV info file to cobertura XML format.")
   (license license:asl2.0)))

(define rust-cargo-config2-0.1
  (package
   (name "rust-cargo-config2")
   (version "0.1.29")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cargo-config2" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "15cmkvxad1b33bvx2d1h7bnjlbvq1lpyi5jybk0jq9mrxi5ha90i"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-home" ,rust-home-0.5)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-derive" ,rust-serde-derive-1)
                      ("rust-toml-edit" ,rust-toml-edit-0.22))))
   (home-page "https://github.com/taiki-e/cargo-config2")
   (synopsis "Load and resolve Cargo configuration.")
   (description "This package provides Load and resolve Cargo configuration.")
   (license (list license:asl2.0 license:expat))))

(define-public rust-cargo-llvm-cov
  (package
   (name "rust-cargo-llvm-cov")
   (version "0.6.14")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cargo-llvm-cov" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "07x9ad6l8xxnypch3sm10454b8ll9whn1hcxpvh3ffvl9lxd1h1m"))))
   (native-inputs (list git)) ;; for tests
   (build-system cargo-build-system)
   (arguments
    `(#:cargo-inputs (("rust-anyhow" ,rust-anyhow-1)
                      ("rust-camino" ,rust-camino-1)
                      ("rust-cargo-config2" ,rust-cargo-config2-0.1)
                      ("rust-duct" ,rust-duct-0.13)
                      ("rust-fs-err" ,rust-fs-err-2)
                      ("rust-glob" ,rust-glob-0.3)
                      ("rust-home" ,rust-home-0.5)
                      ("rust-is-executable" ,rust-is-executable-1)
                      ("rust-lcov2cobertura" ,rust-lcov2cobertura-1)
                      ("rust-lexopt" ,rust-lexopt-0.3)
                      ("rust-opener" ,rust-opener-0.7)
                      ("rust-regex" ,rust-regex-1)
                      ("rust-rustc-demangle" ,rust-rustc-demangle-0.1)
                      ("rust-ruzstd" ,rust-ruzstd-0.7)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-derive" ,rust-serde-derive-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-shell-escape" ,rust-shell-escape-0.1)
                      ("rust-tar" ,rust-tar-0.4)
                      ("rust-termcolor" ,rust-termcolor-1)
                      ("rust-walkdir" ,rust-walkdir-2))
      #:cargo-development-inputs (("rust-easy-ext" ,rust-easy-ext-1)
                                  ("rust-rustversion" ,rust-rustversion-1)
                                  ("rust-tempfile" ,rust-tempfile-3))))
   (home-page "https://github.com/taiki-e/cargo-llvm-cov")
   (synopsis
    "Cargo subcommand to easily use LLVM source-based code coverage (-C instrument-coverage).")
   (description
    "This package provides Cargo subcommand to easily use LLVM source-based code coverage (-C
instrument-coverage).")
   (license (list license:asl2.0 license:expat))))
