;; SPDX-License-Identifier: BSD-2-Clause
(define-module (styx-deps cargo-nextest)
  #:use-module (guix)
  #:use-module (guix build-system cargo)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages crates-apple)
  #:use-module (gnu packages crates-crypto)
  #:use-module (gnu packages crates-graphics)
  #:use-module (gnu packages crates-gtk)
  #:use-module (gnu packages crates-io)
  #:use-module (gnu packages crates-tls)
  #:use-module (gnu packages crates-vcs)
  #:use-module (gnu packages crates-web)
  #:use-module (gnu packages crates-windows)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages compression)
  #:use-module (guix git-download)
  )

(define rust-swrite-0.1
  (package
   (name "rust-swrite")
   (version "0.1.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "swrite" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "00vsicglylq4qq6dc497jdgzfnxi5mh7padwxijnvh1d1giyqgvz"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/rusticstuff/swrite")
   (synopsis "Infallible alternatives to write! and writeln! for Strings")
   (description
    "This package provides Infallible alternatives to write! and writeln! for Strings.")
   (license (list license:expat license:asl2.0))))

(define rust-supports-color-3
  (package
   (name "rust-supports-color")
   (version "3.0.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "supports-color" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0xssmhv74f10024wy645200nfhzgprm0bb80r4k6kj91rxd30xc7"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-is-ci" ,rust-is-ci-1))))
   (home-page "https://github.com/zkat/supports-color")
   (synopsis
    "Detects whether a terminal supports color, and gives details about that support")
   (description
    "This package provides Detects whether a terminal supports color, and gives details about that support.")
   (license license:asl2.0)))

(define rust-win32job-2
  (package
   (name "rust-win32job")
   (version "2.0.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "win32job" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0g1blsb7ixrqjicykx82rvrymcydlsdgfwzb61x88iyrazsinasv"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-thiserror" ,rust-thiserror-1)
                      ("rust-windows" ,rust-windows-0.52))))
   (home-page "https://github.com/ohadravid/win32job-rs")
   (synopsis "safe API for Windows' job objects.")
   (description "This package provides a safe API for Windows job objects.")
   (license (list license:expat license:asl2.0))))

(define rust-unicode-normalization-0.1
  (package
   (name "rust-unicode-normalization")
   (version "0.1.24")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "unicode-normalization" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0mnrk809z3ix1wspcqy97ld5wxdb31f3xz6nsvg5qcv289ycjcsh"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-tinyvec" ,rust-tinyvec-1))))
   (home-page "https://github.com/unicode-rs/unicode-normalization")
   (synopsis "This crate provides functions for normalization of
Unicode strings, including Canonical and Compatible
Decomposition and Recomposition, as described in
Unicode Standard Annex #15.")
   (description
    "This crate provides functions for normalization of Unicode strings, including
Canonical and Compatible Decomposition and Recomposition, as described in
Unicode Standard Annex #15.")
   (license (list license:expat license:asl2.0))))

(define rust-unicode-ident-1
  (package
   (name "rust-unicode-ident")
   (version "1.0.13")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "unicode-ident" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1zm1xylzsdfvm2a5ib9li3g5pp7qnkv4amhspydvgbmd9k6mc6z9"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/dtolnay/unicode-ident")
   (synopsis
    "Determine whether characters have the XID_Start or XID_Continue properties according to Unicode Standard Annex #31")
   (description
    "This package provides Determine whether characters have the XID_Start or XID_Continue properties
according to Unicode Standard Annex #31.")
   (license (list license:expat license:asl2.0 license:unicode))))

(define rust-toml-edit-0.22
  (package
   (name "rust-toml-edit")
   (version "0.22.22")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "toml_edit" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1xf7sxfzmnc45f75x302qrn5aph52vc8w226v59yhrm211i8vr2a"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-indexmap" ,rust-indexmap-2)
                      ("rust-kstring" ,rust-kstring-2)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-spanned" ,rust-serde-spanned-0.6)
                      ("rust-toml-datetime" ,rust-toml-datetime-0.6)
                      ("rust-winnow" ,rust-winnow-0.6))))
   (home-page "https://github.com/toml-rs/toml")
   (synopsis "Yet another format-preserving TOML parser")
   (description
    "This package provides Yet another format-preserving TOML parser.")
   (license (list license:expat license:asl2.0))))

(define rust-toml-datetime-0.6
  (package
   (name "rust-toml-datetime")
   (version "0.6.8")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "toml_datetime" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0hgv7v9g35d7y9r2afic58jvlwnf73vgd1mz2k8gihlgrf73bmqd"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/toml-rs/toml")
   (synopsis "TOML-compatible datetime type")
   (description "This package provides a TOML-compatible datetime type.")
   (license (list license:expat license:asl2.0))))

(define rust-serde-spanned-0.6
  (package
   (name "rust-serde-spanned")
   (version "0.6.8")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "serde_spanned" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1q89g70azwi4ybilz5jb8prfpa575165lmrffd49vmcf76qpqq47"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/toml-rs/toml")
   (synopsis "Serde-compatible spanned Value")
   (description "This package provides Serde-compatible spanned Value.")
   (license (list license:expat license:asl2.0))))

(define rust-toml-0.8
  (package
   (name "rust-toml")
   (version "0.8.19")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "toml" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0knjd3mkxyb87qcs2dark3qkpadidap3frqfj5nqvhpxwfc1zvd1"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-indexmap" ,rust-indexmap-2)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-spanned" ,rust-serde-spanned-0.6)
                      ("rust-toml-datetime" ,rust-toml-datetime-0.6)
                      ("rust-toml-edit" ,rust-toml-edit-0.22))))
   (home-page "https://github.com/toml-rs/toml")
   (synopsis
    "native Rust encoder and decoder of TOML-formatted files and streams. Provides
implementations of the standard Serialize/Deserialize traits for TOML data to
facilitate deserializing and serializing Rust structures.")
   (description
    "This package provides a native Rust encoder and decoder of TOML-formatted files
and streams.  Provides implementations of the standard Serialize/Deserialize
traits for TOML data to facilitate deserializing and serializing Rust
structures.")
   (license (list license:expat license:asl2.0))))

(define rust-tokio-macros-2
  (package
   (name "rust-tokio-macros")
   (version "2.4.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tokio-macros" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0lnpg14h1v3fh2jvnc8cz7cjf0m7z1xgkwfpcyy632g829imjgb9"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://tokio.rs")
   (synopsis "Tokio's proc macros.")
   (description "This package provides Tokio's proc macros.")
   (license license:expat)))

(define rust-hermit-abi-0.3
  (package
   (name "rust-hermit-abi")
   (version "0.3.9")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "hermit-abi" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "092hxjbjnq5fmz66grd9plxd0sh6ssg5fhgwwwqbrzgzkjwdycfj"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-rustc-std-workspace-alloc" ,rust-rustc-std-workspace-alloc-1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1))))
   (home-page "https://github.com/hermit-os/hermit-rs")
   (synopsis "Hermit system calls definitions")
   (description "This package provides Hermit system calls definitions.")
   (license (list license:expat license:asl2.0))))

(define rust-mio-1
  (package
   (name "rust-mio")
   (version "1.0.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "mio" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1v1cnnn44awxbcfm4zlavwgkvbyg7gp5zzjm8mqf1apkrwflvq40"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-hermit-abi" ,rust-hermit-abi-0.3)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-wasi" ,rust-wasi-0.11)
                      ("rust-windows-sys" ,rust-windows-sys-0.52))))
   (home-page "https://github.com/tokio-rs/mio")
   (synopsis "Lightweight non-blocking I/O")
   (description "This package provides Lightweight non-blocking I/O.")
   (license license:expat)))

(define rust-tokio-1
  (package
   (name "rust-tokio")
   (version "1.41.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tokio" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1fwb4nm630hmy9cyl2ar6wxqckgvsakwhg1rhjza4is3a09k8pql"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-backtrace" ,rust-backtrace-0.3)
                      ("rust-bytes" ,rust-bytes-1)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-mio" ,rust-mio-1)
                      ("rust-parking-lot" ,rust-parking-lot-0.12)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2)
                      ("rust-signal-hook-registry" ,rust-signal-hook-registry-1)
                      ("rust-socket2" ,rust-socket2-0.5)
                      ("rust-tokio-macros" ,rust-tokio-macros-2)
                      ("rust-tracing" ,rust-tracing-0.1)
                      ("rust-windows-sys" ,rust-windows-sys-0.52))))
   (home-page "https://tokio.rs")
   (synopsis
    "An event-driven, non-blocking I/O platform for writing asynchronous I/O
backed applications.")
   (description
    "This package provides An event-driven, non-blocking I/O platform for writing asynchronous I/O backed
applications.")
   (license license:expat)))

(define rust-target-spec-miette-0.4
  (package
   (name "rust-target-spec-miette")
   (version "0.4.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "target-spec-miette" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0n5wnjsxglf93bk8dnm4dnsnjxg4d0xxnxymmax10v18llgdy4gy"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-guppy-workspace-hack" ,rust-guppy-workspace-hack-0.1)
                      ("rust-miette" ,rust-miette-7)
                      ("rust-target-spec" ,rust-target-spec-3))))
   (home-page "https://github.com/guppy-rs/guppy")
   (synopsis "Integrate target-spec errors with the miette library")
   (description
    "This package provides Integrate target-spec errors with the miette library.")
   (license (list license:expat license:asl2.0))))

(define rust-tar-0.4
  (package
   (name "rust-tar")
   (version "0.4.42")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tar" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0820y2jdzx77i1m7r5rxwv8ks1mb2ynnkxn6axmy1dgd786w9xjg"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-filetime" ,rust-filetime-0.2)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-xattr" ,rust-xattr-1))))
   (home-page "https://github.com/alexcrichton/tar-rs")
   (synopsis
    "Rust implementation of a TAR file reader and writer. This library does not
currently handle compression, but it is abstract over all I/O readers and
writers. Additionally, great lengths are taken to ensure that the entire
contents are never required to be entirely resident in memory all at once.")
   (description
    "This package provides a Rust implementation of a TAR file reader and writer.
This library does not currently handle compression, but it is abstract over all
I/O readers and writers.  Additionally, great lengths are taken to ensure that
the entire contents are never required to be entirely resident in memory all at
once.")
   (license (list license:expat license:asl2.0))))

(define rust-serde-path-to-error-0.1
  (package
   (name "rust-serde-path-to-error")
   (version "0.1.16")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "serde_path_to_error" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "19hlz2359l37ifirskpcds7sxg0gzpqvfilibs7whdys0128i6dg"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-itoa" ,rust-itoa-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/dtolnay/path-to-error")
   (synopsis "Path to the element that failed to deserialize")
   (description
    "This package provides Path to the element that failed to deserialize.")
   (license (list license:expat license:asl2.0))))

(define rust-serde-ignored-0.1
  (package
   (name "rust-serde-ignored")
   (version "0.1.10")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "serde_ignored" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1psdv0ahmxgw4l3dg341j5q2k09d7glj93v01mm14lhvdniikqx8"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/dtolnay/serde-ignored")
   (synopsis "Find out about keys that are ignored when deserializing data")
   (description
    "This package provides Find out about keys that are ignored when deserializing data.")
   (license (list license:expat license:asl2.0))))

(define rust-zipsign-api-0.1
  (package
   (name "rust-zipsign-api")
   (version "0.1.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zipsign-api" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0z30vzhhhd1va9z7ksdw8x8f6y8jb200h2ryk85wvnx9mm3aa4v4"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-base64" ,rust-base64-0.22)
                      ("rust-ed25519-dalek" ,rust-ed25519-dalek-2)
                      ("rust-thiserror" ,rust-thiserror-1)
                      ("rust-zip" ,rust-zip-2))))
   (home-page "https://github.com/Kijewski/zipsign")
   (synopsis
    "Sign and verify `.zip` and `.tar.gz` files with an ed25519 signing key")
   (description
    "This package provides Sign and verify `.zip` and `.tar.gz` files with an ed25519 signing key.")
   (license (list license:asl2.0 license:expat))))

(define rust-zstd-safe-7
  (package
   (name "rust-zstd-safe")
   (version "7.2.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zstd-safe" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0nch85m5cr493y26yvndm6a8j6sd9mxpr2awrim3dslcnr6sp8sl"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-zstd-sys" ,rust-zstd-sys-2))))
   (home-page "https://github.com/gyscos/zstd-rs")
   (synopsis "Safe low-level bindings for the zstd compression library")
   (description
    "This package provides Safe low-level bindings for the zstd compression library.")
   (license (list license:expat license:asl2.0))))

(define rust-zstd-0.13
  (package
   (name "rust-zstd")
   (version "0.13.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zstd" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1ygkr6wspm9clbp7ykyl0rv69cfsf9q4lic9wcqiwn34lrwbgwpw"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-zstd-safe" ,rust-zstd-safe-7))))
   (home-page "https://github.com/gyscos/zstd-rs")
   (synopsis "Binding for the zstd compression library")
   (description
    "This package provides Binding for the zstd compression library.")
   (license license:expat)))

(define rust-lockfree-object-pool-0.1
  (package
   (name "rust-lockfree-object-pool")
   (version "0.1.6")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "lockfree-object-pool" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0bjm2g1g1avab86r02jb65iyd7hdi35khn1y81z4nba0511fyx4k"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/EVaillant/lockfree-object-pool")
   (synopsis
    "thread-safe object pool collection with automatic return and attach/detach semantics.")
   (description
    "This package provides a thread-safe object pool collection with automatic return
and attach/detach semantics.")
   (license license:boost1.0)))

(define rust-bumpalo-3
  (package
   (name "rust-bumpalo")
   (version "3.16.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "bumpalo" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0b015qb4knwanbdlp1x48pkb4pm57b8gidbhhhxr900q2wb6fabr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-allocator-api2" ,rust-allocator-api2-0.2)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/fitzgen/bumpalo")
   (synopsis "fast bump allocation arena for Rust.")
   (description
    "This package provides a fast bump allocation arena for Rust.")
   (license (list license:expat license:asl2.0))))

(define rust-zopfli-0.8
  (package
   (name "rust-zopfli")
   (version "0.8.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zopfli" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0ip9azz9ldk19m0m1hdppz3n5zcz0cywbg1vx59g4p5c3cwry0g5"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bumpalo" ,rust-bumpalo-3)
                      ("rust-crc32fast" ,rust-crc32fast-1)
                      ("rust-lockfree-object-pool" ,rust-lockfree-object-pool-0.1)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-simd-adler32" ,rust-simd-adler32-0.3))))
   (home-page "https://github.com/zopfli-rs/zopfli")
   (synopsis "Rust implementation of the Zopfli compression algorithm.")
   (description
    "This package provides a Rust implementation of the Zopfli compression algorithm.")
   (license license:asl2.0)))

(define rust-zeroize-1
  (package
   (name "rust-zeroize")
   (version "1.8.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zeroize" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1pjdrmjwmszpxfd7r860jx54cyk94qk59x13sc307cvr5256glyf"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1)
                      ("rust-zeroize-derive" ,rust-zeroize-derive-1))))
   (home-page "https://github.com/RustCrypto/utils/tree/master/zeroize")
   (synopsis "Securely clear secrets from memory with a simple trait built on
stable Rust primitives which guarantee memory is zeroed using an
operation will not be 'optimized away' by the compiler.
Uses a portable pure Rust implementation that works everywhere,
even WASM!")
   (description
    "This package provides Securely clear secrets from memory with a simple trait built on stable Rust
primitives which guarantee memory is zeroed using an operation will not be
optimized away by the compiler.  Uses a portable pure Rust implementation that
works everywhere, even WASM!")
   (license (list license:asl2.0 license:expat))))

(define rust-time-macros-0.2
  (package
   (name "rust-time-macros")
   (version "0.2.18")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "time-macros" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1kqwxvfh2jkpg38fy673d6danh1bhcmmbsmffww3mphgail2l99z"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-num-conv" ,rust-num-conv-0.1)
                      ("rust-time-core" ,rust-time-core-0.1))))
   (home-page "https://github.com/time-rs/time")
   (synopsis
    "Procedural macros for the time crate.
    This crate is an implementation detail and should not be relied upon directly.")
   (description
    "This package provides Procedural macros for the time crate.  This crate is an implementation detail
and should not be relied upon directly.")
   (license (list license:expat license:asl2.0))))

(define rust-time-0.3
  (package
   (name "rust-time")
   (version "0.3.36")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "time" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "11g8hdpahgrf1wwl2rpsg5nxq3aj7ri6xr672v4qcij6cgjqizax"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-deranged" ,rust-deranged-0.3)
                      ("rust-itoa" ,rust-itoa-1)
                      ("rust-js-sys" ,rust-js-sys-0.3)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-num-conv" ,rust-num-conv-0.1)
                      ("rust-num-threads" ,rust-num-threads-0.1)
                      ("rust-powerfmt" ,rust-powerfmt-0.2)
                      ("rust-quickcheck" ,rust-quickcheck-1)
                      ("rust-rand" ,rust-rand-0.8)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-time-core" ,rust-time-core-0.1)
                      ("rust-time-macros" ,rust-time-macros-0.2))))
   (home-page "https://time-rs.github.io")
   (synopsis
    "Date and time library. Fully interoperable with the standard library. Mostly compatible with #![no_std]")
   (description
    "This package provides Date and time library.  Fully interoperable with the standard library.  Mostly
compatible with #![no_std].")
   (license (list license:expat license:asl2.0))))

(define rust-memchr-2
  (package
   (name "rust-memchr")
   (version "2.7.4")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "memchr" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "18z32bhxrax0fnjikv475z7ii718hq457qwmaryixfxsl2qrmjkq"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1))))
   (home-page "https://github.com/BurntSushi/memchr")
   (synopsis
    "Provides extremely fast (uses SIMD on x86_64, aarch64 and wasm32) routines for
1, 2 or 3 byte search and single substring search.")
   (description
    "This package provides extremely fast (uses SIMD on x86_64, aarch64 and wasm32)
routines for 1, 2 or 3 byte search and single substring search.")
   (license (list license:unlicense license:expat))))

(define rust-lzma-rs-0.3
  (package
   (name "rust-lzma-rs")
   (version "0.3.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "lzma-rs" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0phif4pnjrn28zcxgz3a7z86hhx5gdajmkrndfw4vrkahd682zi9"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-byteorder" ,rust-byteorder-1)
                      ("rust-crc" ,rust-crc-3)
                      ("rust-env-logger" ,rust-env-logger-0.9)
                      ("rust-log" ,rust-log-0.4))))
   (home-page "https://github.com/gendx/lzma-rs")
   (synopsis "codec for LZMA, LZMA2 and XZ written in pure Rust")
   (description
    "This package provides a codec for LZMA, LZMA2 and XZ written in pure Rust.")
   (license license:expat)))

(define rust-libz-rs-sys-0.3
  (package
   (name "rust-libz-rs-sys")
   (version "0.3.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "libz-rs-sys" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0vsnvkff9i4qxnid1xl7wrmhz8alvqw9z5lnpimpzzgrxr4r56q0"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-zlib-rs" ,rust-zlib-rs-0.3))))
   (home-page "https://github.com/memorysafety/zlib-rs")
   (synopsis "memory-safe zlib implementation written in rust")
   (description
    "This package provides a memory-safe zlib implementation written in rust.")
   (license license:zlib)))

(define rust-libz-ng-sys-1
  (package
   (name "rust-libz-ng-sys")
   (version "1.1.20")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "libz-ng-sys" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1m8mm1dxa7myvp6fwy7jdkyxza74isqci31frdx9g1a6lfap43wg"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-cmake" ,rust-cmake-0.1)
                      ("rust-libc" ,rust-libc-0.2))))
   (home-page "https://github.com/rust-lang/libz-sys")
   (synopsis
    "Low-level bindings to zlib-ng (libz-ng), a high-performance zlib library")
   (description
    "This package provides Low-level bindings to zlib-ng (libz-ng), a high-performance zlib library.")
   (license (list license:expat license:asl2.0))))

(define rust-flate2-1
  (package
   (name "rust-flate2")
   (version "1.0.34")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "flate2" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1w1nf2ap4q1sq1v6v951011wcvljk449ap7q7jnnjf8hvjs8kdd1"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-cloudflare-zlib-sys" ,rust-cloudflare-zlib-sys-0.3)
                      ("rust-crc32fast" ,rust-crc32fast-1)
                      ("rust-libz-ng-sys" ,rust-libz-ng-sys-1)
                      ("rust-libz-rs-sys" ,rust-libz-rs-sys-0.3)
                      ("rust-libz-sys" ,rust-libz-sys-1)
                      ("rust-miniz-oxide" ,rust-miniz-oxide-0.8))))
   (home-page "https://github.com/rust-lang/flate2-rs")
   (synopsis
    "DEFLATE compression and decompression exposed as Read/BufRead/Write streams.
Supports miniz_oxide and multiple zlib implementations. Supports zlib, gzip,
and raw deflate streams.")
   (description
    "This package provides DEFLATE compression and decompression exposed as Read/@code{BufRead/Write}
streams.  Supports miniz_oxide and multiple zlib implementations.  Supports
zlib, gzip, and raw deflate streams.")
   (license (list license:expat license:asl2.0))))

(define rust-displaydoc-0.2
  (package
   (name "rust-displaydoc")
   (version "0.2.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "displaydoc" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1q0alair462j21iiqwrr21iabkfnb13d6x5w95lkdg21q2xrqdlp"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/yaahc/displaydoc")
   (synopsis
    "derive macro for implementing the display Trait via a doc comment and string interpolation")
   (description
    "This package provides a derive macro for implementing the display Trait via a
doc comment and string interpolation.")
   (license (list license:expat license:asl2.0))))

(define rust-deflate64-0.1
  (package
   (name "rust-deflate64")
   (version "0.1.9")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "deflate64" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "06scix17pa7wzzfsnhkycpcc6s04shs49cdaxx2k1sl0226jnsfs"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/anatawa12/deflate64-rs#readme")
   (synopsis "Deflate64 implementation based on .NET's implementation")
   (description
    "This package provides Deflate64 implementation based on .NET's implementation.")
   (license license:expat)))

(define rust-crossbeam-utils-0.8
  (package
   (name "rust-crossbeam-utils")
   (version "0.8.20")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "crossbeam-utils" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "100fksq5mm1n7zj242cclkw6yf7a4a8ix3lvpfkhxvdhbda9kv12"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-loom" ,rust-loom-0.7))))
   (home-page
    "https://github.com/crossbeam-rs/crossbeam/tree/master/crossbeam-utils")
   (synopsis "Utilities for concurrent programming")
   (description "This package provides Utilities for concurrent programming.")
   (license (list license:expat license:asl2.0))))

(define rust-crc32fast-1
  (package
   (name "rust-crc32fast")
   (version "1.4.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "crc32fast" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1czp7vif73b8xslr3c9yxysmh9ws2r8824qda7j47ffs9pcnjxx9"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-cfg-if" ,rust-cfg-if-1))))
   (home-page "https://github.com/srijs/rust-crc32fast")
   (synopsis "Fast, SIMD-accelerated CRC32 (IEEE) checksum computation")
   (description
    "This package provides Fast, SIMD-accelerated CRC32 (IEEE) checksum computation.")
   (license (list license:expat license:asl2.0))))

(define rust-zip-2
  (package
   (name "rust-zip")
   (version "2.2.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zip" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "151lrzswjkhwzlr6dkmgbi4s51sa8dr496n6mwiswms0xa444pnw"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-aes" ,rust-aes-0.8)
                      ("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-bzip2" ,rust-bzip2-0.4)
                      ("rust-chrono" ,rust-chrono-0.4)
                      ("rust-constant-time-eq" ,rust-constant-time-eq-0.3)
                      ("rust-crc32fast" ,rust-crc32fast-1)
                      ("rust-crossbeam-utils" ,rust-crossbeam-utils-0.8)
                      ("rust-deflate64" ,rust-deflate64-0.1)
                      ("rust-displaydoc" ,rust-displaydoc-0.2)
                      ("rust-flate2" ,rust-flate2-1)
                      ("rust-hmac" ,rust-hmac-0.12)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-lzma-rs" ,rust-lzma-rs-0.3)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-pbkdf2" ,rust-pbkdf2-0.12)
                      ("rust-rand" ,rust-rand-0.8)
                      ("rust-sha1" ,rust-sha1-0.10)
                      ("rust-thiserror" ,rust-thiserror-1)
                      ("rust-time" ,rust-time-0.3)
                      ("rust-zeroize" ,rust-zeroize-1)
                      ("rust-zopfli" ,rust-zopfli-0.8)
                      ("rust-zstd" ,rust-zstd-0.13))))
   (home-page "https://github.com/zip-rs/zip2.git")
   (synopsis "Library to support the reading and writing of zip files.")
   (description
    "This package provides Library to support the reading and writing of zip files.")
   (license license:expat)))

(define rust-fastrand-2
  (package
   (name "rust-fastrand")
   (version "2.1.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "fastrand" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "19nyzdq3ha4g173364y2wijmd6jlyms8qx40daqkxsnl458jmh78"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-getrandom" ,rust-getrandom-0.2))))
   (home-page "https://github.com/smol-rs/fastrand")
   (synopsis "simple and fast random number generator")
   (description
    "This package provides a simple and fast random number generator.")
   (license (list license:asl2.0 license:expat))))

(define rust-self-replace-1
  (package
   (name "rust-self-replace")
   (version "1.5.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "self-replace" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1drganasvf5b0x6c9g60jkfhzjc9in3r6cznjfw0lhmbbrdq3v03"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-fastrand" ,rust-fastrand-2)
                      ("rust-tempfile" ,rust-tempfile-3)
                      ("rust-windows-sys" ,rust-windows-sys-0.52))))
   (home-page "https://github.com/mitsuhiko/self-replace")
   (synopsis
    "Utility crate that allows executables to replace or uninstall themselves")
   (description
    "This package provides Utility crate that allows executables to replace or uninstall themselves.")
   (license license:asl2.0)))

(define rust-quick-xml-0.23
  (package
   (name "rust-quick-xml")
   (version "0.23.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "quick-xml" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1slry2g2wrj38fnzj9ybzq9wjyknrfg25x5vzfpzn5b8kj2zrfhi"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-encoding-rs" ,rust-encoding-rs-0.8)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/tafia/quick-xml")
   (synopsis "High performance xml reader and writer")
   (description
    "This package provides High performance xml reader and writer.")
   (license license:expat)))

(define rust-self-update-0.41
  (package
   (name "rust-self-update")
   (version "0.41.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "self_update" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1rcdma359wic71km5n139rx61zn0fhz3k7r6aacc300k0rq3k6j6"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-either" ,rust-either-1)
                      ("rust-flate2" ,rust-flate2-1)
                      ("rust-hyper" ,rust-hyper-1)
                      ("rust-indicatif" ,rust-indicatif-0.17)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-quick-xml" ,rust-quick-xml-0.23)
                      ("rust-regex" ,rust-regex-1)
                      ("rust-reqwest" ,rust-reqwest-0.12)
                      ("rust-self-replace" ,rust-self-replace-1)
                      ("rust-semver" ,rust-semver-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-tar" ,rust-tar-0.4)
                      ("rust-tempfile" ,rust-tempfile-3)
                      ("rust-urlencoding" ,rust-urlencoding-2)
                      ("rust-zip" ,rust-zip-2)
                      ("rust-zipsign-api" ,rust-zipsign-api-0.1))))
   (home-page "https://github.com/jaemk/self_update")
   (synopsis "Self updates for standalone executables")
   (description
    "This package provides Self updates for standalone executables.")
   (license license:expat)))

(define rust-quick-xml-0.36
  (package
   (name "rust-quick-xml")
   (version "0.36.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "quick-xml" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1zj3sjcjk6sn544wb2wvhr1km5f9cy664vzclygfsnph9mxrlr7p"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-document-features" ,rust-document-features-0.2)
                      ("rust-encoding-rs" ,rust-encoding-rs-0.8)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-tokio" ,rust-tokio-1))))
   (home-page "https://github.com/tafia/quick-xml")
   (synopsis "High performance xml reader and writer")
   (description
    "This package provides High performance xml reader and writer.")
   (license license:expat)))

(define rust-quick-junit-0.5
  (package
   (name "rust-quick-junit")
   (version "0.5.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "quick-junit" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0h62n1y7v2ajd7wr82ilpqryvp0asqg9svgd3c9sxkv2l7wx5zv2"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-chrono" ,rust-chrono-0.4)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-newtype-uuid" ,rust-newtype-uuid-1)
                      ("rust-quick-xml" ,rust-quick-xml-0.36)
                      ("rust-strip-ansi-escapes" ,rust-strip-ansi-escapes-0.2)
                      ("rust-thiserror" ,rust-thiserror-1)
                      ("rust-uuid" ,rust-uuid-1))))
   (home-page "https://github.com/nextest-rs/quick-junit")
   (synopsis "Data model and serializer for JUnit/XUnit XML")
   (description
    "This package provides Data model and serializer for JUnit/XUnit XML.")
   (license (list license:asl2.0 license:expat))))

(define rust-pin-project-lite-0.2
  (package
   (name "rust-pin-project-lite")
   (version "0.2.14")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "pin-project-lite" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "00nx3f04agwjlsmd3mc5rx5haibj2v8q9b52b0kwn63wcv4nz9mx"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/taiki-e/pin-project-lite")
   (synopsis
    "lightweight version of pin-project written with declarative macros.")
   (description
    "This package provides a lightweight version of pin-project written with
declarative macros.")
   (license (list license:asl2.0 license:expat))))

(define rust-owo-colors-4
  (package
   (name "rust-owo-colors")
   (version "4.1.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "owo-colors" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0mms4sbisxm1w8v08qz85m90sv861xg4ahil85587kb9cmzpcdzv"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-supports-color" ,rust-supports-color-3)
                      ("rust-supports-color" ,rust-supports-color-2))))
   (home-page "https://github.com/jam1garner/owo-colors")
   (synopsis "Zero-allocation terminal colors that'll make people go owo")
   (description
    "This package provides Zero-allocation terminal colors that'll make people go owo.")
   (license license:expat)))

(define rust-portable-atomic-1
  (package
   (name "rust-portable-atomic")
   (version "1.9.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "portable-atomic" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1cmd87qj90panwsi350djb8lsxdryqkkxmimjcz7a1nsysini76c"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-critical-section" ,rust-critical-section-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/taiki-e/portable-atomic")
   (synopsis
    "Portable atomic types including support for 128-bit atomics, atomic float, etc.")
   (description
    "This package provides Portable atomic types including support for 128-bit atomics, atomic float, etc.")
   (license (list license:asl2.0 license:expat))))

(define rust-parking-lot-core-0.9
  (package
   (name "rust-parking-lot-core")
   (version "0.9.10")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "parking_lot_core" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1y3cf9ld9ijf7i4igwzffcn0xl16dxyn4c5bwgjck1dkgabiyh0y"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-backtrace" ,rust-backtrace-0.3)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-petgraph" ,rust-petgraph-0.6)
                      ("rust-redox-syscall" ,rust-redox-syscall-0.5)
                      ("rust-smallvec" ,rust-smallvec-1)
                      ("rust-thread-id" ,rust-thread-id-4)
                      ("rust-windows-targets" ,rust-windows-targets-0.52))))
   (home-page "https://github.com/Amanieu/parking_lot")
   (synopsis "An advanced API for creating custom synchronization primitives")
   (description
    "This package provides An advanced API for creating custom synchronization primitives.")
   (license (list license:expat license:asl2.0))))

(define rust-critical-section-1
  (package
   (name "rust-critical-section")
   (version "1.2.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "critical-section" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "02ylhcykxjc40xrfhk1lwc21jqgz4dbwv3jr49ymw733c51yl3kr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/rust-embedded/critical-section")
   (synopsis "Cross-platform critical section")
   (description "This package provides Cross-platform critical section.")
   (license (list license:expat license:asl2.0))))

(define rust-once-cell-1
  (package
   (name "rust-once-cell")
   (version "1.20.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "once_cell" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0xb7rw1aqr7pa4z3b00y7786gyf8awx2gca3md73afy76dzgwq8j"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-critical-section" ,rust-critical-section-1)
                      ("rust-parking-lot-core" ,rust-parking-lot-core-0.9)
                      ("rust-portable-atomic" ,rust-portable-atomic-1))))
   (home-page "https://github.com/matklad/once_cell")
   (synopsis "Single assignment cells and lazy values")
   (description
    "This package provides Single assignment cells and lazy values.")
   (license (list license:expat license:asl2.0))))

(define rust-nix-0.29
  (package
   (name "rust-nix")
   (version "0.29.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "nix" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0ikvn7s9r2lrfdm3mx1h7nbfjvcc6s9vxdzw7j5xfkd2qdnp9qki"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bitflags" ,rust-bitflags-2)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-cfg-aliases" ,rust-cfg-aliases-0.2)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-memoffset" ,rust-memoffset-0.9)
                      ("rust-pin-utils" ,rust-pin-utils-0.1))))
   (home-page "https://github.com/nix-rust/nix")
   (synopsis "Rust friendly bindings to *nix APIs")
   (description "This package provides Rust friendly bindings to *nix APIs.")
   (license license:expat)))

(define rust-zerocopy-derive-0.8
  (package
   (name "rust-zerocopy-derive")
   (version "0.8.7")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zerocopy-derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1sp63bdv13k19d1aimdscylakz5rnj0ncqh4ais81kckrkrm8prf"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/google/zerocopy")
   (synopsis "Custom derive for traits from the zerocopy crate")
   (description
    "This package provides Custom derive for traits from the zerocopy crate.")
   (license (list license:bsd-2 license:asl2.0 license:expat))))

(define rust-zerocopy-0.8
  (package
   (name "rust-zerocopy")
   (version "0.8.7")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zerocopy" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1xnnbcrxhmv2jdralxvszn11bvk8b91mdj7pg9n9m48g4bvsagdv"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-zerocopy-derive" ,rust-zerocopy-derive-0.8))))
   (home-page "https://github.com/google/zerocopy")
   (synopsis
    "Zerocopy makes zero-cost memory manipulation effortless. We write \"unsafe\" so you don't have to")
   (description
    "This package provides Zerocopy makes zero-cost memory manipulation effortless.  We write \"unsafe\" so
you don't have to.")
   (license (list license:bsd-2 license:asl2.0 license:expat))))

(define rust-uuid-macro-internal-1
  (package
   (name "rust-uuid-macro-internal")
   (version "1.11.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "uuid-macro-internal" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "024s8hxxjwgc218kfx9xs274dhnkv1ik9818kv7d0f1sw5zzb4bb"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/uuid-rs/uuid")
   (synopsis "Private implementation details of the uuid! macro")
   (description
    "This package provides Private implementation details of the uuid! macro.")
   (license (list license:asl2.0 license:expat))))

(define rust-uuid-1
  (package
   (name "rust-uuid")
   (version "1.11.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "uuid" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0sj4l28lif2wm4xrafdfgqjywjzv43wzp8nii9a4i539myhg1igq"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-atomic" ,rust-atomic-0.6)
                      ("rust-borsh" ,rust-borsh-1)
                      ("rust-borsh-derive" ,rust-borsh-derive-1)
                      ("rust-bytemuck" ,rust-bytemuck-1)
                      ("rust-getrandom" ,rust-getrandom-0.2)
                      ("rust-md-5" ,rust-md-5-0.10)
                      ("rust-rand" ,rust-rand-0.8)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-sha1-smol" ,rust-sha1-smol-1)
                      ("rust-slog" ,rust-slog-2)
                      ("rust-uuid-macro-internal" ,rust-uuid-macro-internal-1)
                      ("rust-wasm-bindgen" ,rust-wasm-bindgen-0.2)
                      ("rust-zerocopy" ,rust-zerocopy-0.8))))
   (home-page "https://github.com/uuid-rs/uuid")
   (synopsis "library to generate and parse UUIDs.")
   (description
    "This package provides a library to generate and parse UUIDs.")
   (license (list license:asl2.0 license:expat))))

(define rust-newtype-uuid-1
  (package
   (name "rust-newtype-uuid")
   (version "1.1.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "newtype-uuid" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1xa66461xwr0mgrvyxzbspdqaf545pffz2m4ck43dqil72a36jag"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-schemars" ,rust-schemars-0.8)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-uuid" ,rust-uuid-1))))
   (home-page "https://github.com/oxidecomputer/newtype-uuid")
   (synopsis "Newtype wrapper around UUIDs")
   (description "This package provides Newtype wrapper around UUIDs.")
   (license (list license:expat license:asl2.0))))

(define rust-mukti-metadata-0.2
  (package
   (name "rust-mukti-metadata")
   (version "0.2.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "mukti-metadata" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0vdw8h24x1b47a1mvc5hlv59l6xy2hclfsa5wg7dnqnkl0x1sr1p"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-semver" ,rust-semver-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-thiserror" ,rust-thiserror-1))))
   (home-page "https://github.com/nextest-rs/mukti")
   (synopsis "Metadata for mukti release manager")
   (description "This package provides Metadata for mukti release manager.")
   (license (list license:expat license:asl2.0))))

(define rust-humantime-serde-1
  (package
   (name "rust-humantime-serde")
   (version "1.1.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "humantime-serde" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0310ri4zb33qbwqv0n51xysfjpnwc6rgxscl5i09jgcjlmgdp8sp"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-humantime" ,rust-humantime-2)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/jean-airoldie/humantime-serde")
   (synopsis "Serde support for the `humantime` crate")
   (description
    "This package provides Serde support for the `humantime` crate.")
   (license (list license:expat license:asl2.0))))

(define rust-http-1
  (package
   (name "rust-http")
   (version "1.1.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "http" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0n426lmcxas6h75c2cp25m933pswlrfjz10v91vc62vib2sdvf91"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bytes" ,rust-bytes-1)
                      ("rust-fnv" ,rust-fnv-1)
                      ("rust-itoa" ,rust-itoa-1))))
   (home-page "https://github.com/hyperium/http")
   (synopsis "set of types for representing HTTP requests and responses.")
   (description
    "This package provides a set of types for representing HTTP requests and
responses.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-macro-0.3
  (package
   (name "rust-futures-macro")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-macro" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0l1n7kqzwwmgiznn0ywdc5i24z72zvh9q1dwps54mimppi7f6bhn"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis "The futures-rs procedural macro implementations.")
   (description
    "This package provides The futures-rs procedural macro implementations.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-io-0.3
  (package
   (name "rust-futures-io")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-io" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1ikmw1yfbgvsychmsihdkwa8a1knank2d9a8dk01mbjar9w1np4y"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis
    "The `AsyncRead`, `AsyncWrite`, `AsyncSeek`, and `AsyncBufRead` traits for the futures-rs library.")
   (description
    "This package provides The `@code{AsyncRead`}, `@code{AsyncWrite`}, `@code{AsyncSeek`}, and
`@code{AsyncBufRead`} traits for the futures-rs library.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-util-0.3
  (package
   (name "rust-futures-util")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-util" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "10aa1ar8bgkgbr4wzxlidkqkcxf77gffyj8j7768h831pcaq784z"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-futures" ,rust-futures-0.1)
                      ("rust-futures-channel" ,rust-futures-channel-0.3)
                      ("rust-futures-core" ,rust-futures-core-0.3)
                      ("rust-futures-io" ,rust-futures-io-0.3)
                      ("rust-futures-macro" ,rust-futures-macro-0.3)
                      ("rust-futures-sink" ,rust-futures-sink-0.3)
                      ("rust-futures-task" ,rust-futures-task-0.3)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2)
                      ("rust-pin-utils" ,rust-pin-utils-0.1)
                      ("rust-slab" ,rust-slab-0.4)
                      ("rust-tokio-io" ,rust-tokio-io-0.1))))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis
    "Common utilities and extension traits for the futures-rs library.")
   (description
    "This package provides Common utilities and extension traits for the futures-rs library.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-task-0.3
  (package
   (name "rust-futures-task")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-task" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "124rv4n90f5xwfsm9qw6y99755y021cmi5dhzh253s920z77s3zr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis "Tools for working with tasks.")
   (description "This package provides tools for working with tasks.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-executor-0.3
  (package
   (name "rust-futures-executor")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-executor" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "17vcci6mdfzx4gbk0wx64chr2f13wwwpvyf3xd5fb1gmjzcx2a0y"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-futures-core" ,rust-futures-core-0.3)
                      ("rust-futures-task" ,rust-futures-task-0.3)
                      ("rust-futures-util" ,rust-futures-util-0.3)
                      ("rust-num-cpus" ,rust-num-cpus-1))))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis
    "Executors for asynchronous tasks based on the futures-rs library.")
   (description
    "This package provides Executors for asynchronous tasks based on the futures-rs library.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-sink-0.3
  (package
   (name "rust-futures-sink")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-sink" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1xyly6naq6aqm52d5rh236snm08kw8zadydwqz8bip70s6vzlxg5"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis "The asynchronous `Sink` trait for the futures-rs library.")
   (description
    "This package provides The asynchronous `Sink` trait for the futures-rs library.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-core-0.3
  (package
   (name "rust-futures-core")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-core" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0gk6yrxgi5ihfanm2y431jadrll00n5ifhnpx090c2f2q1cr1wh5"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-portable-atomic" ,rust-portable-atomic-1))))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis "The core traits and types in for the `futures` library.")
   (description
    "This package provides The core traits and types in for the `futures` library.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-channel-0.3
  (package
   (name "rust-futures-channel")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures-channel" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "040vpqpqlbk099razq8lyn74m0f161zd0rp36hciqrwcg2zibzrd"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-futures-core" ,rust-futures-core-0.3)
                      ("rust-futures-sink" ,rust-futures-sink-0.3))))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis "Channels for asynchronous communication using futures-rs.")
   (description
    "This package provides Channels for asynchronous communication using futures-rs.")
   (license (list license:expat license:asl2.0))))

(define rust-futures-0.3
  (package
   (name "rust-futures")
   (version "0.3.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "futures" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0xh8ddbkm9jy8kc5gbvjp9a4b6rqqxvc8471yb2qaz5wm2qhgg35"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-futures-channel" ,rust-futures-channel-0.3)
                      ("rust-futures-core" ,rust-futures-core-0.3)
                      ("rust-futures-executor" ,rust-futures-executor-0.3)
                      ("rust-futures-io" ,rust-futures-io-0.3)
                      ("rust-futures-sink" ,rust-futures-sink-0.3)
                      ("rust-futures-task" ,rust-futures-task-0.3)
                      ("rust-futures-util" ,rust-futures-util-0.3))))
   (home-page "https://rust-lang.github.io/futures-rs")
   (synopsis
    "An implementation of futures and streams featuring zero allocations,
composability, and iterator-like interfaces.")
   (description
    "This package provides An implementation of futures and streams featuring zero allocations,
composability, and iterator-like interfaces.")
   (license (list license:expat license:asl2.0))))

(define rust-future-queue-0.3
  (package
   (name "rust-future-queue")
   (version "0.3.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "future-queue" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1rmjyqy5z87pwghvikmxn18mgdbr6k3w7zmx5qf12h8smrlamlf0"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-fnv" ,rust-fnv-1)
                      ("rust-futures-util" ,rust-futures-util-0.3)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2))))
   (home-page "https://github.com/nextest-rs/future-queue")
   (synopsis
    "Adapters to manage a queue of futures, where each future can have a different weight")
   (description
    "This package provides Adapters to manage a queue of futures, where each future can have a different
weight.")
   (license (list license:expat license:asl2.0))))

(define rust-dunce-1
  (package
   (name "rust-dunce")
   (version "1.0.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "dunce" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "04y8wwv3vvcqaqmqzssi6k0ii9gs6fpz96j5w9nky2ccsl23axwj"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://lib.rs/crates/dunce")
   (synopsis
    "Normalize Windows paths to the most compatible format, avoiding UNC where possible")
   (description
    "This package provides Normalize Windows paths to the most compatible format, avoiding UNC where
possible.")
   (license (list license:cc0 license:expat-0 license:asl2.0))))

(define rust-display-error-chain-0.2
  (package
   (name "rust-display-error-chain")
   (version "0.2.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "display-error-chain" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1xbcilzyfc8n60vjkmsf8v53kw855xw68jh69hpza6dwhrp19hhb"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/mexus/display-error-chain.git")
   (synopsis "Formats a standard error and its sources")
   (description
    "This package provides Formats a standard error and its sources.")
   (license (list license:asl2.0 license:expat))))

(define rust-tonic-web-0.12
  (package
   (name "rust-tonic-web")
   (version "0.12.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tonic-web" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0n2bhgs57kvqsk1z2fr1izcrrrbnfgda0pjargf3dmqsh0hdv6aj"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-base64" ,rust-base64-0.22)
                      ("rust-bytes" ,rust-bytes-1)
                      ("rust-http" ,rust-http-1)
                      ("rust-http-body" ,rust-http-body-1)
                      ("rust-http-body-util" ,rust-http-body-util-0.1)
                      ("rust-pin-project" ,rust-pin-project-1)
                      ("rust-tokio-stream" ,rust-tokio-stream-0.1)
                      ("rust-tonic" ,rust-tonic-0.12)
                      ("rust-tower-http" ,rust-tower-http-0.5)
                      ("rust-tower-layer" ,rust-tower-layer-0.3)
                      ("rust-tower-service" ,rust-tower-service-0.3)
                      ("rust-tracing" ,rust-tracing-0.1))))
   (home-page "https://github.com/hyperium/tonic")
   (synopsis "grpc-web protocol translation for tonic services.")
   (description
    "This package provides grpc-web protocol translation for tonic services.")
   (license license:expat)))

(define rust-tokio-stream-0.1
  (package
   (name "rust-tokio-stream")
   (version "0.1.16")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tokio-stream" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1wc65gprcsyzqlr0k091glswy96kph90i32gffi4ksyh03hnqkjg"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-futures-core" ,rust-futures-core-0.3)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2)
                      ("rust-tokio" ,rust-tokio-1)
                      ("rust-tokio-util" ,rust-tokio-util-0.7))))
   (home-page "https://tokio.rs")
   (synopsis "Utilities to work with `Stream` and `tokio`.")
   (description
    "This package provides Utilities to work with `Stream` and `tokio`.")
   (license license:expat)))

(define rust-libz-sys-1
  (package
   (name "rust-libz-sys")
   (version "1.1.20")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "libz-sys" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0wp4i6zl385ilmcqafv61jwsk1mpk6yb8gpws9nwza00x19n9lfj"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-cc" ,rust-cc-1)
                      ("rust-cmake" ,rust-cmake-0.1)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-pkg-config" ,rust-pkg-config-0.3)
                      ("rust-vcpkg" ,rust-vcpkg-0.2))))
   (home-page "https://github.com/rust-lang/libz-sys")
   (synopsis
    "Low-level bindings to the system libz library (also known as zlib)")
   (description
    "This package provides Low-level bindings to the system libz library (also known as zlib).")
   (license (list license:expat license:asl2.0))))

(define rust-zlib-rs-0.3
  (package
   (name "rust-zlib-rs")
   (version "0.3.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "zlib-rs" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "06kkjpqddvb5n8c24mmd3lmmcsy2yfwfsjyni8dggysayfd7r50b"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-libz-sys" ,rust-libz-sys-1)
                      ("rust-quickcheck" ,rust-quickcheck-1))))
   (home-page "https://github.com/memorysafety/zlib-rs")
   (synopsis "memory-safe zlib implementation written in rust")
   (description
    "This package provides a memory-safe zlib implementation written in rust.")
   (license license:zlib)))

(define rust-rustls-webpki-0.102
  (package
   (name "rust-rustls-webpki")
   (version "0.102.8")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "rustls-webpki" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1sdy8ks86b7jpabpnb2px2s7f1sq8v0nqf6fnlvwzm4vfk41pjk4"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-aws-lc-rs" ,rust-aws-lc-rs-1)
                      ("rust-ring" ,rust-ring-0.17)
                      ("rust-rustls-pki-types" ,rust-rustls-pki-types-1)
                      ("rust-untrusted" ,rust-untrusted-0.9))))
   (home-page "https://github.com/rustls/webpki")
   (synopsis "Web PKI X.509 Certificate Verification")
   (description
    "This package provides Web PKI X.509 Certificate Verification.")
   (license license:isc)))

(define rust-rustls-pki-types-1
  (package
   (name "rust-rustls-pki-types")
   (version "1.10.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "rustls-pki-types" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0jv78c32pgf1i0bn7rzf4xdr9qh5wsvigp6akc1yhzls7hdj1w8n"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-web-time" ,rust-web-time-1))))
   (home-page "https://github.com/rustls/pki-types")
   (synopsis "Shared types for the rustls PKI ecosystem")
   (description
    "This package provides Shared types for the rustls PKI ecosystem.")
   (license (list license:expat license:asl2.0))))

(define rust-brotli-decompressor-4
  (package
   (name "rust-brotli-decompressor")
   (version "4.0.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "brotli-decompressor" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0qn39c7n6wm40i2bm0d3q2qslmaavlh804iv0ccbba4m80pbsics"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-alloc-no-stdlib" ,rust-alloc-no-stdlib-2)
                      ("rust-alloc-stdlib" ,rust-alloc-stdlib-0.2))))
   (home-page "https://github.com/dropbox/rust-brotli-decompressor")
   (synopsis
    "brotli decompressor that with an interface avoiding the rust stdlib. This makes it suitable for embedded devices and kernels. It is designed with a pluggable allocator so that the standard lib's allocator may be employed. The default build also includes a stdlib allocator and stream interface. Disable this with --features=no-stdlib. Alternatively, --features=unsafe turns off array bounds checks and memory initialization but provides a safe interface for the caller.  Without adding the --features=unsafe argument, all included code is safe. For compression in addition to this library, download https://github.com/dropbox/rust-brotli")
   (description
    "This package provides a brotli decompressor that with an interface avoiding the
rust stdlib.  This makes it suitable for embedded devices and kernels.  It is
designed with a pluggable allocator so that the standard lib's allocator may be
employed.  The default build also includes a stdlib allocator and stream
interface.  Disable this with --features=no-stdlib.  Alternatively,
--features=unsafe turns off array bounds checks and memory initialization but
provides a safe interface for the caller.  Without adding the --features=unsafe
argument, all included code is safe.  For compression in addition to this
library, download https://github.com/dropbox/rust-brotli.")
   (license (list license:bsd-3 license:expat))))

(define rust-brotli-7
  (package
   (name "rust-brotli")
   (version "7.0.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "brotli" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1g99xay61mds9d23fnfj5gfbd6g11gihfgs3y1abljwldzqvi5yc"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-alloc-no-stdlib" ,rust-alloc-no-stdlib-2)
                      ("rust-alloc-stdlib" ,rust-alloc-stdlib-0.2)
                      ("rust-brotli-decompressor" ,rust-brotli-decompressor-4)
                      ("rust-sha2" ,rust-sha2-0.10))))
   (home-page "https://github.com/dropbox/rust-brotli")
   (synopsis
    "brotli compressor and decompressor that with an interface avoiding the rust stdlib. This makes it suitable for embedded devices and kernels. It is designed with a pluggable allocator so that the standard lib's allocator may be employed. The default build also includes a stdlib allocator and stream interface. Disable this with --features=no-stdlib. All included code is safe.")
   (description
    "This package provides a brotli compressor and decompressor that with an
interface avoiding the rust stdlib.  This makes it suitable for embedded devices
and kernels.  It is designed with a pluggable allocator so that the standard
lib's allocator may be employed.  The default build also includes a stdlib
allocator and stream interface.  Disable this with --features=no-stdlib.  All
included code is safe.")
   (license (list license:bsd-3 license:expat))))

(define rust-jobserver-0.1
  (package
   (name "rust-jobserver")
   (version "0.1.32")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "jobserver" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1l2k50qmj84x9mn39ivjz76alqmx72jhm12rw33zx9xnpv5xpla8"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-libc" ,rust-libc-0.2))))
   (home-page "https://github.com/rust-lang/jobserver-rs")
   (synopsis "An implementation of the GNU Make jobserver for Rust.")
   (description
    "This package provides An implementation of the GNU Make jobserver for Rust.")
   (license (list license:expat license:asl2.0))))

(define rust-cc-1
  (package
   (name "rust-cc")
   (version "1.1.31")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cc" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0vscf59yxf665s4fv9yn3l39gfw99mgp6wnbc76cyv80ahmrdry2"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-jobserver" ,rust-jobserver-0.1)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-shlex" ,rust-shlex-1))))
   (home-page "https://github.com/rust-lang/cc-rs")
   (synopsis
    "build-time dependency for Cargo build scripts to assist in invoking the native
C compiler to compile native C code into a static archive to be linked into Rust
code.")
   (description
    "This package provides a build-time dependency for Cargo build scripts to assist
in invoking the native C compiler to compile native C code into a static archive
to be linked into Rust code.")
   (license (list license:expat license:asl2.0))))

(define rust-aws-lc-sys-0.22
  (package
   (name "rust-aws-lc-sys")
   (version "0.22.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "aws-lc-sys" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0wirg7f308vldma4rx4l2xz0m72hp1bl088vlcibczhx25l42ynz"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bindgen" ,rust-bindgen-0.69)
                      ("rust-cc" ,rust-cc-1)
                      ("rust-cmake" ,rust-cmake-0.1)
                      ("rust-dunce" ,rust-dunce-1)
                      ("rust-fs-extra" ,rust-fs-extra-1)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-paste" ,rust-paste-1))))
   (home-page "https://github.com/aws/aws-lc-rs")
   (synopsis
    "AWS-LC is a general-purpose cryptographic library maintained by the AWS Cryptography team for AWS and their customers. It Ñs based on code from the Google BoringSSL project and the OpenSSL project")
   (description
    "This package provides AWS-LC is a general-purpose cryptographic library maintained by the AWS
Cryptography team for AWS and their customers.  It Ñs based on code from the
Google @code{BoringSSL} project and the @code{OpenSSL} project.")
   (license (list license:isc license:expat license:asl2.0
                  license:openssl))))

(define rust-aws-lc-rs-1
  (package
   (name "rust-aws-lc-rs")
   (version "1.10.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "aws-lc-rs" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "07gz0dx42rsn45rf964m56aiyrbq9fly146127dzs2fj8jx2vn6d"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-aws-lc-fips-sys" ,rust-aws-lc-fips-sys-0.12)
                      ("rust-aws-lc-sys" ,rust-aws-lc-sys-0.22)
                      ("rust-mirai-annotations" ,rust-mirai-annotations-1)
                      ("rust-paste" ,rust-paste-1)
                      ("rust-untrusted" ,rust-untrusted-0.7)
                      ("rust-zeroize" ,rust-zeroize-1))))
   (home-page "https://github.com/aws/aws-lc-rs")
   (synopsis
    "aws-lc-rs is a cryptographic library using AWS-LC for its cryptographic operations. This library strives to be API-compatible with the popular Rust library named ring")
   (description
    "This package provides aws-lc-rs is a cryptographic library using AWS-LC for its cryptographic
operations.  This library strives to be API-compatible with the popular Rust
library named ring.")
   (license (list license:isc license:expat license:asl2.0))))

(define rust-rustls-0.23
  (package
   (name "rust-rustls")
   (version "0.23.15")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "rustls" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "14vr5pfdvzfcqrmjzh1834a1nyi3kzv7j8s22gb77s64mkbl9fsz"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-aws-lc-rs" ,rust-aws-lc-rs-1)
                      ("rust-brotli" ,rust-brotli-7)
                      ("rust-brotli-decompressor" ,rust-brotli-decompressor-4)
                      ("rust-hashbrown" ,rust-hashbrown-0.15)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-ring" ,rust-ring-0.17)
                      ("rust-rustls-pki-types" ,rust-rustls-pki-types-1)
                      ("rust-rustls-webpki" ,rust-rustls-webpki-0.102)
                      ("rust-rustversion" ,rust-rustversion-1)
                      ("rust-subtle" ,rust-subtle-2)
                      ("rust-zeroize" ,rust-zeroize-1)
                      ("rust-zlib-rs" ,rust-zlib-rs-0.3))))
   (home-page "https://github.com/rustls/rustls")
   (synopsis "Rustls is a modern TLS library written in Rust")
   (description
    "This package provides Rustls is a modern TLS library written in Rust.")
   (license (list license:asl2.0 license:isc license:expat))))

(define rust-tokio-rustls-0.26
  (package
   (name "rust-tokio-rustls")
   (version "0.26.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tokio-rustls" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1m00czrmk8x7pdjnz10a3da3i1d0sdf9j9vfp5dnk5ss1q6w8yqc"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-rustls" ,rust-rustls-0.23)
                      ("rust-rustls-pki-types" ,rust-rustls-pki-types-1)
                      ("rust-tokio" ,rust-tokio-1))))
   (home-page "https://github.com/rustls/tokio-rustls")
   (synopsis "Asynchronous TLS/SSL streams for Tokio using Rustls")
   (description
    "This package provides Asynchronous TLS/SSL streams for Tokio using Rustls.")
   (license (list license:expat license:asl2.0))))

(define rust-rustls-native-certs-0.8
  (package
   (name "rust-rustls-native-certs")
   (version "0.8.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "rustls-native-certs" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "12izz1ahwj3yr9fkd39q1w535577z9wsapsahz6jcwxyyaj1ibzw"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-openssl-probe" ,rust-openssl-probe-0.1)
                      ("rust-rustls-pemfile" ,rust-rustls-pemfile-2)
                      ("rust-rustls-pki-types" ,rust-rustls-pki-types-1)
                      ("rust-schannel" ,rust-schannel-0.1)
                      ("rust-security-framework" ,rust-security-framework-2))))
   (home-page "https://github.com/rustls/rustls-native-certs")
   (synopsis
    "rustls-native-certs allows rustls to use the platform native certificate store")
   (description
    "This package provides rustls-native-certs allows rustls to use the platform native certificate store.")
   (license (list license:asl2.0 license:isc license:expat))))

(define rust-hyper-1
  (package
   (name "rust-hyper")
   (version "1.5.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "hyper" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "16pspkgizcnsr1qcpqvm5l45nfwk7244q9av56cqqwm40slg1gxv"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bytes" ,rust-bytes-1)
                      ("rust-futures-channel" ,rust-futures-channel-0.3)
                      ("rust-futures-util" ,rust-futures-util-0.3)
                      ("rust-h2" ,rust-h2-0.4)
                      ("rust-http" ,rust-http-1)
                      ("rust-http-body" ,rust-http-body-1)
                      ("rust-http-body-util" ,rust-http-body-util-0.1)
                      ("rust-httparse" ,rust-httparse-1)
                      ("rust-httpdate" ,rust-httpdate-1)
                      ("rust-itoa" ,rust-itoa-1)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2)
                      ("rust-smallvec" ,rust-smallvec-1)
                      ("rust-tokio" ,rust-tokio-1)
                      ("rust-tracing" ,rust-tracing-0.1)
                      ("rust-want" ,rust-want-0.3))))
   (home-page "https://hyper.rs")
   (synopsis "fast and correct HTTP library.")
   (description "This package provides a fast and correct HTTP library.")
   (license license:expat)))

(define rust-hyper-util-0.1
  (package
   (name "rust-hyper-util")
   (version "0.1.9")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "hyper-util" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "12yhradh0bpwa9jjyyq6shrrcx9fxbdkrq06xj7ccfhqkyq6waa1"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bytes" ,rust-bytes-1)
                      ("rust-futures-channel" ,rust-futures-channel-0.3)
                      ("rust-futures-util" ,rust-futures-util-0.3)
                      ("rust-http" ,rust-http-1)
                      ("rust-http-body" ,rust-http-body-1)
                      ("rust-hyper" ,rust-hyper-1)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2)
                      ("rust-socket2" ,rust-socket2-0.5)
                      ("rust-tokio" ,rust-tokio-1)
                      ("rust-tower-service" ,rust-tower-service-0.3)
                      ("rust-tracing" ,rust-tracing-0.1))))
   (home-page "https://hyper.rs")
   (synopsis "hyper utilities")
   (description "This package provides hyper utilities.")
   (license license:expat)))

(define rust-hyper-timeout-0.5
  (package
   (name "rust-hyper-timeout")
   (version "0.5.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "hyper-timeout" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "14rpyv9zz0ncadn9qgmnjz0hiqk3nav7hglkk1a6yfy8wmhsj0rj"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-hyper" ,rust-hyper-1)
                      ("rust-hyper-util" ,rust-hyper-util-0.1)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2)
                      ("rust-tokio" ,rust-tokio-1)
                      ("rust-tower-service" ,rust-tower-service-0.3))))
   (home-page "https://github.com/hjr3/hyper-timeout")
   (synopsis
    "connect, read and write timeout aware connector to be used with hyper Client.")
   (description
    "This package provides a connect, read and write timeout aware connector to be
used with hyper Client.")
   (license (list license:expat license:asl2.0))))

(define rust-tonic-0.12
  (package
   (name "rust-tonic")
   (version "0.12.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tonic" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0ljd1lfjpw0vrm5wbv15x6nq2i38llsanls5rkzmdn2n0wrmnz47"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-async-stream" ,rust-async-stream-0.3)
                      ("rust-async-trait" ,rust-async-trait-0.1)
                      ("rust-axum" ,rust-axum-0.7)
                      ("rust-base64" ,rust-base64-0.22)
                      ("rust-bytes" ,rust-bytes-1)
                      ("rust-flate2" ,rust-flate2-1)
                      ("rust-h2" ,rust-h2-0.4)
                      ("rust-http" ,rust-http-1)
                      ("rust-http-body" ,rust-http-body-1)
                      ("rust-http-body-util" ,rust-http-body-util-0.1)
                      ("rust-hyper" ,rust-hyper-1)
                      ("rust-hyper-timeout" ,rust-hyper-timeout-0.5)
                      ("rust-hyper-util" ,rust-hyper-util-0.1)
                      ("rust-percent-encoding" ,rust-percent-encoding-2)
                      ("rust-pin-project" ,rust-pin-project-1)
                      ("rust-prost" ,rust-prost-0.13)
                      ("rust-rustls-native-certs" ,rust-rustls-native-certs-0.8)
                      ("rust-rustls-pemfile" ,rust-rustls-pemfile-2)
                      ("rust-socket2" ,rust-socket2-0.5)
                      ("rust-tokio" ,rust-tokio-1)
                      ("rust-tokio-rustls" ,rust-tokio-rustls-0.26)
                      ("rust-tokio-stream" ,rust-tokio-stream-0.1)
                      ("rust-tower" ,rust-tower-0.4)
                      ("rust-tower-layer" ,rust-tower-layer-0.3)
                      ("rust-tower-service" ,rust-tower-service-0.3)
                      ("rust-tracing" ,rust-tracing-0.1)
                      ("rust-webpki-roots" ,rust-webpki-roots-0.26)
                      ("rust-zstd" ,rust-zstd-0.13))))
   (home-page "https://github.com/hyperium/tonic")
   (synopsis
    "gRPC over HTTP/2 implementation focused on high performance, interoperability, and flexibility.")
   (description
    "This package provides a @code{gRPC} over HTTP/2 implementation focused on high
performance, interoperability, and flexibility.")
   (license license:expat)))

(define rust-prost-types-0.13
  (package
   (name "rust-prost-types")
   (version "0.13.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "prost-types" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0w6n122pi7fsfvnwfcm9mil7q1105kg62yxrpn6znck2786slna7"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-prost" ,rust-prost-0.13))))
   (home-page "https://github.com/tokio-rs/prost")
   (synopsis "Prost definitions of Protocol Buffers well known types")
   (description
    "This package provides Prost definitions of Protocol Buffers well known types.")
   (license license:asl2.0)))

(define rust-prost-derive-0.13
  (package
   (name "rust-prost-derive")
   (version "0.13.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "prost-derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1i9wh2q5rly0lwsmxq5svwyk4adcb5j31gyhwjj682az1n2jymg9"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-anyhow" ,rust-anyhow-1)
                      ("rust-itertools" ,rust-itertools-0.10)
                      ("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/tokio-rs/prost")
   (synopsis
    "Generate encoding and decoding implementations for Prost annotated types")
   (description
    "This package provides Generate encoding and decoding implementations for Prost annotated types.")
   (license license:asl2.0)))

(define rust-prost-0.13
  (package
   (name "rust-prost")
   (version "0.13.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "prost" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0gx1kbvgnws59ggv1mda15bc00f6hlxp24s9k1zyhz841vcqf13v"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bytes" ,rust-bytes-1)
                      ("rust-prost-derive" ,rust-prost-derive-0.13))))
   (home-page "https://github.com/tokio-rs/prost")
   (synopsis "Protocol Buffers implementation for the Rust Language.")
   (description
    "This package provides a Protocol Buffers implementation for the Rust Language.")
   (license license:asl2.0)))

(define rust-console-api-0.8
  (package
   (name "rust-console-api")
   (version "0.8.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "console-api" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0c89bwfl70vrrfi4ps7g6ihl1lxaz9syzwz4qq9p54lzkjm19vc6"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-futures-core" ,rust-futures-core-0.3)
                      ("rust-prost" ,rust-prost-0.13)
                      ("rust-prost-types" ,rust-prost-types-0.13)
                      ("rust-tonic" ,rust-tonic-0.12)
                      ("rust-tracing-core" ,rust-tracing-core-0.1))))
   (home-page "https://github.com/tokio-rs/console/blob/main/console-api")
   (synopsis "Protobuf wire format bindings for the Tokio console.")
   (description
    "This package provides Protobuf wire format bindings for the Tokio console.")
   (license license:expat)))

(define rust-console-subscriber-0.4
  (package
   (name "rust-console-subscriber")
   (version "0.4.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "console-subscriber" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "00h3k0hxv25l7rlfqhmkisqpfmawp9qa77dzdsa36cvzlc8s3qz2"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-console-api" ,rust-console-api-0.8)
                      ("rust-crossbeam-channel" ,rust-crossbeam-channel-0.5)
                      ("rust-crossbeam-utils" ,rust-crossbeam-utils-0.8)
                      ("rust-futures-task" ,rust-futures-task-0.3)
                      ("rust-hdrhistogram" ,rust-hdrhistogram-7)
                      ("rust-humantime" ,rust-humantime-2)
                      ("rust-hyper-util" ,rust-hyper-util-0.1)
                      ("rust-parking-lot" ,rust-parking-lot-0.12)
                      ("rust-prost" ,rust-prost-0.13)
                      ("rust-prost-types" ,rust-prost-types-0.13)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-thread-local" ,rust-thread-local-1)
                      ("rust-tokio" ,rust-tokio-1)
                      ("rust-tokio-stream" ,rust-tokio-stream-0.1)
                      ("rust-tonic" ,rust-tonic-0.12)
                      ("rust-tonic-web" ,rust-tonic-web-0.12)
                      ("rust-tracing" ,rust-tracing-0.1)
                      ("rust-tracing-core" ,rust-tracing-core-0.1)
                      ("rust-tracing-subscriber" ,rust-tracing-subscriber-0.3))))
   (home-page
    "https://github.com/tokio-rs/console/blob/main/console-subscriber")
   (synopsis
    "`tracing-subscriber::Layer` for collecting Tokio console telemetry.")
   (description
    "This package provides a `tracing-subscriber::Layer` for collecting Tokio console
telemetry.")
   (license license:expat)))

(define rust-dlv-list-0.5
  (package
   (name "rust-dlv-list")
   (version "0.5.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "dlv-list" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0pqvrinxzdz7bpy4a3p450h8krns3bd0mc3w0qqvm03l2kskj824"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-const-random" ,rust-const-random-0.1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/sgodwincs/dlv-list-rs")
   (synopsis "Semi-doubly linked list implemented using a vector")
   (description
    "This package provides Semi-doubly linked list implemented using a vector.")
   (license (list license:expat license:asl2.0))))

(define rust-ordered-multimap-0.6
  (package
   (name "rust-ordered-multimap")
   (version "0.6.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "ordered-multimap" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "03k9jx3irxldq4hp462ld25fcr03xcycd2sc73jl9rwqivqarn2f"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-dlv-list" ,rust-dlv-list-0.5)
                      ("rust-hashbrown" ,rust-hashbrown-0.13)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/sgodwincs/ordered-multimap-rs")
   (synopsis "Insertion ordered multimap")
   (description "This package provides Insertion ordered multimap.")
   (license license:expat)))

(define rust-rust-ini-0.19
  (package
   (name "rust-rust-ini")
   (version "0.19.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "rust-ini" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "14ah70q8k450d6cdwn2vsl1rsdha09nax2n8y4z5a4ziq773naky"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-ordered-multimap" ,rust-ordered-multimap-0.6)
                      ("rust-unicase" ,rust-unicase-2))))
   (home-page "https://github.com/zonyitoo/rust-ini")
   (synopsis "An Ini configuration file parsing library in Rust")
   (description
    "This package provides An Ini configuration file parsing library in Rust.")
   (license license:expat)))

(define rust-config-0.14
  (package
   (name "rust-config")
   (version "0.14.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "config" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1gij86qh17j00mz2pdq23h2kjwswq8h9g4diy1a28g5mjw2v4a3k"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-async-trait" ,rust-async-trait-0.1)
                      ("rust-convert-case" ,rust-convert-case-0.6)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-json5" ,rust-json5-0.4)
                      ("rust-lazy-static" ,rust-lazy-static-1)
                      ("rust-nom" ,rust-nom-7)
                      ("rust-pathdiff" ,rust-pathdiff-0.2)
                      ("rust-ron" ,rust-ron-0.8)
                      ("rust-rust-ini" ,rust-rust-ini-0.19)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-toml" ,rust-toml-0.8)
                      ("rust-yaml-rust" ,rust-yaml-rust-0.4))))
   (home-page "https://github.com/mehcode/config-rs")
   (synopsis "Layered configuration system for Rust applications")
   (description
    "This package provides Layered configuration system for Rust applications.")
   (license (list license:expat license:asl2.0))))

(define rust-chrono-0.4
  (package
   (name "rust-chrono")
   (version "0.4.38")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "chrono" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "009l8vc5p8750vn02z30mblg4pv2qhkbfizhfwmzc6vpy5nr67x2"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-android-tzdata" ,rust-android-tzdata-0.1)
                      ("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-iana-time-zone" ,rust-iana-time-zone-0.1)
                      ("rust-js-sys" ,rust-js-sys-0.3)
                      ("rust-num-traits" ,rust-num-traits-0.2)
                      ("rust-pure-rust-locales" ,rust-pure-rust-locales-0.8)
                      ("rust-rkyv" ,rust-rkyv-0.7)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-wasm-bindgen" ,rust-wasm-bindgen-0.2)
                      ("rust-windows-targets" ,rust-windows-targets-0.52))))
   (home-page "https://github.com/chronotope/chrono")
   (synopsis "Date and time library for Rust")
   (description "This package provides Date and time library for Rust.")
   (license (list license:expat license:asl2.0))))

(define rust-camino-tempfile-1
  (package
   (name "rust-camino-tempfile")
   (version "1.1.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "camino-tempfile" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1hk3a8x7950qg9vfl9fjwxyjd659fq6wvchrz4kx9r41z9am146b"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-camino" ,rust-camino-1)
                      ("rust-tempfile" ,rust-tempfile-3))))
   (home-page "https://github.com/camino-rs/camino-tempfile")
   (synopsis
    "library for managing temporary files and directories, with UTF-8 paths.")
   (description
    "This package provides a library for managing temporary files and directories,
with UTF-8 paths.")
   (license (list license:expat license:asl2.0))))

(define rust-bytes-1
  (package
   (name "rust-bytes")
   (version "1.8.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "bytes" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1nnhpb7jlpj393qnjr1n9n6sgpl3w5ymrwl3pnjmrriam861bh4s"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/tokio-rs/bytes")
   (synopsis "Types and traits for working with bytes")
   (description
    "This package provides Types and traits for working with bytes.")
   (license license:expat)))

(define rust-bstr-1
  (package
   (name "rust-bstr")
   (version "1.10.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "bstr" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "036wwrchd5gq3q4k6w1j2bfl2bk2ff8c0dsa9y7w7aw7nf7knwj0"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-memchr" ,rust-memchr-2)
                      ("rust-regex-automata" ,rust-regex-automata-0.4)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/BurntSushi/bstr")
   (synopsis "string type that is not required to be valid UTF-8.")
   (description
    "This package provides a string type that is not required to be valid UTF-8.")
   (license (list license:expat license:asl2.0))))

(define rust-atomicwrites-0.4
  (package
   (name "rust-atomicwrites")
   (version "0.4.4")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "atomicwrites" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1qrkr9jz43y8g767c3249g4w4pzv43bk3hyza66y6pv43f6vpw9y"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-rustix" ,rust-rustix-0.38)
                      ("rust-tempfile" ,rust-tempfile-3)
                      ("rust-windows-sys" ,rust-windows-sys-0.52))))
   (home-page "https://github.com/untitaker/rust-atomicwrites")
   (synopsis "Atomic file-writes")
   (description "This package provides Atomic file-writes.")
   (license license:expat)))

(define rust-async-scoped-0.9
  (package
   (name "rust-async-scoped")
   (version "0.9.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "async-scoped" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0h47p4is1i5bvsy1i5mdlk521cdjznclxwgfab2gzvckln70fhj0"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-async-std" ,rust-async-std-1)
                      ("rust-futures" ,rust-futures-0.3)
                      ("rust-pin-project" ,rust-pin-project-1)
                      ("rust-tokio" ,rust-tokio-1))))
   (home-page "https://github.com/rmanoka/async-scoped")
   (synopsis
    "Spawn scoped (non 'static) asynchronous futures for async_std and tokio runtimes")
   (description
    "This package provides Spawn scoped (non static) asynchronous futures for async_std and tokio runtimes.")
   (license (list license:asl2.0 license:expat))))

(define rust-aho-corasick-1
  (package
   (name "rust-aho-corasick")
   (version "1.1.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "aho-corasick" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "05mrpkvdgp5d20y2p989f187ry9diliijgwrs254fs9s1m1x6q4f"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-log" ,rust-log-0.4)
                      ("rust-memchr" ,rust-memchr-2))))
   (home-page "https://github.com/BurntSushi/aho-corasick")
   (synopsis "Fast multiple substring searching")
   (description "This package provides Fast multiple substring searching.")
   (license (list license:unlicense license:expat))))

(define rust-nextest-runner-0.64
  (package
   (name "rust-nextest-runner")
   (version "0.64.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "nextest-runner" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0g9cv7i7asfs194y8x0adi9k9m7dm7gw55pni7nnn99vzzlgagg0"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-aho-corasick" ,rust-aho-corasick-1)
                      ("rust-async-scoped" ,rust-async-scoped-0.9)
                      ("rust-atomicwrites" ,rust-atomicwrites-0.4)
                      ("rust-bstr" ,rust-bstr-1)
                      ("rust-bytes" ,rust-bytes-1)
                      ("rust-camino" ,rust-camino-1)
                      ("rust-camino-tempfile" ,rust-camino-tempfile-1)
                      ("rust-cargo-metadata" ,rust-cargo-metadata-0.18)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-chrono" ,rust-chrono-0.4)
                      ("rust-config" ,rust-config-0.14)
                      ("rust-console-subscriber" ,rust-console-subscriber-0.4)
                      ("rust-debug-ignore" ,rust-debug-ignore-1)
                      ("rust-display-error-chain" ,rust-display-error-chain-0.2)
                      ("rust-duct" ,rust-duct-0.13)
                      ("rust-dunce" ,rust-dunce-1)
                      ("rust-future-queue" ,rust-future-queue-0.3)
                      ("rust-futures" ,rust-futures-0.3)
                      ("rust-guppy" ,rust-guppy-0.17)
                      ("rust-home" ,rust-home-0.5)
                      ("rust-http" ,rust-http-1)
                      ("rust-humantime-serde" ,rust-humantime-serde-1)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-indicatif" ,rust-indicatif-0.17)
                      ("rust-is-ci" ,rust-is-ci-1)
                      ("rust-itertools" ,rust-itertools-0.13)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-miette" ,rust-miette-7)
                      ("rust-mukti-metadata" ,rust-mukti-metadata-0.2)
                      ("rust-newtype-uuid" ,rust-newtype-uuid-1)
                      ("rust-nextest-filtering" ,rust-nextest-filtering-0.12)
                      ("rust-nextest-metadata" ,rust-nextest-metadata-0.12)
                      ("rust-nextest-workspace-hack" ,rust-nextest-workspace-hack-0.1)
                      ("rust-nix" ,rust-nix-0.29)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-owo-colors" ,rust-owo-colors-4)
                      ("rust-pin-project-lite" ,rust-pin-project-lite-0.2)
                      ("rust-quick-junit" ,rust-quick-junit-0.5)
                      ("rust-rand" ,rust-rand-0.8)
                      ("rust-regex" ,rust-regex-1)
                      ("rust-self-update" ,rust-self-update-0.41)
                      ("rust-semver" ,rust-semver-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-ignored" ,rust-serde-ignored-0.1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-serde-path-to-error" ,rust-serde-path-to-error-0.1)
                      ("rust-shell-words" ,rust-shell-words-1)
                      ("rust-smallvec" ,rust-smallvec-1)
                      ("rust-smol-str" ,rust-smol-str-0.3)
                      ("rust-strip-ansi-escapes" ,rust-strip-ansi-escapes-0.2)
                      ("rust-tar" ,rust-tar-0.4)
                      ("rust-target-spec" ,rust-target-spec-3)
                      ("rust-target-spec-miette" ,rust-target-spec-miette-0.4)
                      ("rust-thiserror" ,rust-thiserror-1)
                      ("rust-tokio" ,rust-tokio-1)
                      ("rust-toml" ,rust-toml-0.8)
                      ("rust-toml-edit" ,rust-toml-edit-0.22)
                      ("rust-unicode-ident" ,rust-unicode-ident-1)
                      ("rust-unicode-normalization" ,rust-unicode-normalization-0.1)
                      ("rust-win32job" ,rust-win32job-2)
                      ("rust-windows-sys" ,rust-windows-sys-0.59)
                      ("rust-xxhash-rust" ,rust-xxhash-rust-0.8)
                      ("rust-zstd" ,rust-zstd-0.13))))
   (home-page "https://github.com/nextest-rs/nextest")
   (synopsis "Core runner logic for cargo nextest")
   (description "This package provides Core runner logic for cargo nextest.")
   (license (list license:expat license:asl2.0))))

(define rust-xxhash-rust-0.8
  (package
   (name "rust-xxhash-rust")
   (version "0.8.12")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "xxhash-rust" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1139skyp136z8710r916kb1djp7f7flfly31zccqi5800isvyp3a"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/DoumanAsh/xxhash-rust")
   (synopsis "Implementation of xxhash")
   (description "This package provides Implementation of xxhash.")
   (license license:boost1.0)))

(define rust-winnow-0.6
  (package
   (name "rust-winnow")
   (version "0.6.20")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "winnow" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "16y4i8z9vh8hazjxg5mvmq0c5i35wlk8rxi5gkq6cn5vlb0zxh9n"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-anstream" ,rust-anstream-0.3)
                      ("rust-anstyle" ,rust-anstyle-1)
                      ("rust-is-terminal" ,rust-is-terminal-0.4)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-terminal-size" ,rust-terminal-size-0.4))))
   (home-page "https://github.com/winnow-rs/winnow")
   (synopsis "byte-oriented, zero-copy, parser combinators library")
   (description
    "This package provides a byte-oriented, zero-copy, parser combinators library.")
   (license license:expat)))

(define rust-thiserror-impl-1
  (package
   (name "rust-thiserror-impl")
   (version "1.0.65")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "thiserror-impl" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "00l6gyrx6qlm1d7if3dcfl2sl0mg8k21caknkpk7glnb481pfwdf"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/dtolnay/thiserror")
   (synopsis "Implementation detail of the `thiserror` crate")
   (description
    "This package provides Implementation detail of the `thiserror` crate.")
   (license (list license:expat license:asl2.0))))

(define rust-thiserror-1
  (package
   (name "rust-thiserror")
   (version "1.0.65")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "thiserror" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1mdkawq9l9p02zvq7y4py739rjk9wk2ha27mbsb3i6sdb7csn4ax"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-thiserror-impl" ,rust-thiserror-impl-1))))
   (home-page "https://github.com/dtolnay/thiserror")
   (synopsis "derive(Error)")
   (description "This package provides derive(Error).")
   (license (list license:expat license:asl2.0))))

(define rust-structmeta-derive-0.3
  (package
   (name "rust-structmeta-derive")
   (version "0.3.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "structmeta-derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1z12r4v2d3272hxqxclnr1kn2kp07qsy5aswm4ynrzwhlmjhnahm"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/frozenlib/structmeta")
   (synopsis "derive macro for structmeta crate")
   (description "This package provides derive macro for structmeta crate.")
   (license (list license:expat license:asl2.0))))

(define rust-structmeta-0.3
  (package
   (name "rust-structmeta")
   (version "0.3.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "structmeta" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0afk0s9paazsvyvsirxvbnqp3blhdck3fmfhdw7xf209skc7a59f"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-structmeta-derive" ,rust-structmeta-derive-0.3)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/frozenlib/structmeta")
   (synopsis "Parse Rust's attribute arguments by defining a struct")
   (description
    "This package provides Parse Rust's attribute arguments by defining a struct.")
   (license (list license:expat license:asl2.0))))

(define rust-quote-1
  (package
   (name "rust-quote")
   (version "1.0.37")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "quote" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1brklraw2g34bxy9y4q1nbrccn7bv36ylihv12c9vlcii55x7fdm"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1))))
   (home-page "https://github.com/dtolnay/quote")
   (synopsis "Quasi-quoting macro quote!(...)")
   (description "This package provides Quasi-quoting macro quote!(...).")
   (license (list license:expat license:asl2.0))))

(define rust-test-strategy-0.4
  (package
   (name "rust-test-strategy")
   (version "0.4.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "test-strategy" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "06z0slp3ckxfsynq3772jy1dlasv3pa2kmii90ccqm1zbvs1mx1b"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-structmeta" ,rust-structmeta-0.3)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/frozenlib/test-strategy")
   (synopsis
    "Procedural macro to easily write higher-order strategies in proptest")
   (description
    "This package provides Procedural macro to easily write higher-order strategies in proptest.")
   (license (list license:expat license:asl2.0))))

(define rust-regex-syntax-0.8
  (package
   (name "rust-regex-syntax")
   (version "0.8.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "regex-syntax" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0p41p3hj9ww7blnbwbj9h7rwxzxg0c1hvrdycgys8rxyhqqw859b"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-arbitrary" ,rust-arbitrary-1))))
   (home-page "https://github.com/rust-lang/regex/tree/master/regex-syntax")
   (synopsis "regular expression parser.")
   (description "This package provides a regular expression parser.")
   (license (list license:expat license:asl2.0))))

(define rust-regex-automata-0.4
  (package
   (name "rust-regex-automata")
   (version "0.4.8")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "regex-automata" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "18wd530ndrmygi6xnz3sp345qi0hy2kdbsa89182nwbl6br5i1rn"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-aho-corasick" ,rust-aho-corasick-1)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-regex-syntax" ,rust-regex-syntax-0.8))))
   (home-page "https://github.com/rust-lang/regex/tree/master/regex-automata")
   (synopsis "Automata construction and matching using regular expressions")
   (description
    "This package provides Automata construction and matching using regular expressions.")
   (license (list license:expat license:asl2.0))))

(define rust-regex-1
  (package
   (name "rust-regex")
   (version "1.11.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "regex" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1n5imk7yxam409ik5nagsjpwqvbg3f0g0mznd5drf549x1g0w81q"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-aho-corasick" ,rust-aho-corasick-1)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-regex-automata" ,rust-regex-automata-0.4)
                      ("rust-regex-syntax" ,rust-regex-syntax-0.8))))
   (home-page "https://github.com/rust-lang/regex")
   (synopsis
    "An implementation of regular expressions for Rust. This implementation uses
finite automata and guarantees linear time matching on all inputs.")
   (description
    "This package provides An implementation of regular expressions for Rust.  This implementation uses
finite automata and guarantees linear time matching on all inputs.")
   (license (list license:expat license:asl2.0))))

(define rust-recursion-0.5
  (package
   (name "rust-recursion")
   (version "0.5.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "recursion" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0wc8x5340scj9fl281nydgwrpzbbdffj764pw6zppkcchlk58w4z"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-futures" ,rust-futures-0.3)
                      ("rust-tokio" ,rust-tokio-1))))
   (home-page "https://github.com/inanna-malick/recursion")
   (synopsis "cache-aware stack safe recursion")
   (description "This package provides cache-aware stack safe recursion.")
   (license (list license:expat license:asl2.0))))

(define rust-smol-str-0.3
  (package
   (name "rust-smol-str")
   (version "0.3.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "smol_str" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "09fxkyzjw1c84b3g8igp1z4yyl3smb41a19h10qxn6dgqmiggsk6"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-borsh" ,rust-borsh-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/rust-analyzer/smol_str")
   (synopsis "small-string optimized string type with O(1) clone")
   (description
    "This package provides small-string optimized string type with O(1) clone.")
   (license (list license:expat license:asl2.0))))

(define rust-nextest-workspace-hack-0.1
  (package
   (name "rust-nextest-workspace-hack")
   (version "0.1.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "nextest-workspace-hack" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1cxjiwja0idhd8as3drl2wgk5y7f84k2rrk67pbxk7kkk1m881nr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "")
   (synopsis "workspace-hack package, managed by hakari")
   (description
    "This package provides workspace-hack package, managed by hakari.")
   (license license:cc0)))

(define rust-nextest-metadata-0.12
  (package
   (name "rust-nextest-metadata")
   (version "0.12.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "nextest-metadata" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1cx6cdzbgmf5imjcb6vpm6xpdx5nrl3w079m0vm7la0chj21yn7d"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-camino" ,rust-camino-1)
                      ("rust-nextest-workspace-hack" ,rust-nextest-workspace-hack-0.1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-smol-str" ,rust-smol-str-0.3)
                      ("rust-target-spec" ,rust-target-spec-3))))
   (home-page "https://github.com/nextest-rs/nextest")
   (synopsis "Structured access to nextest machine-readable output")
   (description
    "This package provides Structured access to nextest machine-readable output.")
   (license (list license:expat license:asl2.0))))

(define rust-nextest-filtering-0.12
  (package
   (name "rust-nextest-filtering")
   (version "0.12.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "nextest-filtering" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1fz7w2qsmh98c246x16l9j5xypsj1nbc715wszajjkjiv7hbibvy"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-globset" ,rust-globset-0.4)
                      ("rust-guppy" ,rust-guppy-0.17)
                      ("rust-miette" ,rust-miette-7)
                      ("rust-nextest-metadata" ,rust-nextest-metadata-0.12)
                      ("rust-nextest-workspace-hack" ,rust-nextest-workspace-hack-0.1)
                      ("rust-proptest" ,rust-proptest-1)
                      ("rust-recursion" ,rust-recursion-0.5)
                      ("rust-regex" ,rust-regex-1)
                      ("rust-regex-syntax" ,rust-regex-syntax-0.8)
                      ("rust-test-strategy" ,rust-test-strategy-0.4)
                      ("rust-thiserror" ,rust-thiserror-1)
                      ("rust-winnow" ,rust-winnow-0.6)
                      ("rust-xxhash-rust" ,rust-xxhash-rust-0.8))))
   (home-page "https://github.com/nextest-rs/nextest")
   (synopsis "Filtering DSL for cargo-nextest")
   (description "This package provides Filtering DSL for cargo-nextest.")
   (license (list license:expat license:asl2.0))))

(define rust-log-0.4
  (package
   (name "rust-log")
   (version "0.4.22")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "log" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "093vs0wkm1rgyykk7fjbqp2lwizbixac1w52gv109p5r4jh0p9x7"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1)
                      ("rust-sval" ,rust-sval-2)
                      ("rust-sval-ref" ,rust-sval-ref-2)
                      ("rust-value-bag" ,rust-value-bag-1))))
   (home-page "https://github.com/rust-lang/log")
   (synopsis "lightweight logging facade for Rust")
   (description
    "This package provides a lightweight logging facade for Rust.")
   (license (list license:expat license:asl2.0))))

(define rust-target-lexicon-0.12
  (package
   (name "rust-target-lexicon")
   (version "0.12.16")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "target-lexicon" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1cg3bnx1gdkdr5hac1hzxy64fhw4g7dqkd0n3dxy5lfngpr1mi31"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/bytecodealliance/target-lexicon")
   (synopsis "Targeting utilities for compilers and related tools")
   (description
    "This package provides Targeting utilities for compilers and related tools.")
   (license (list license:asl2.0 license:expat))))

(define rust-cfg-expr-0.17
  (package
   (name "rust-cfg-expr")
   (version "0.17.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cfg-expr" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "174y5f7035cx99d83hn1m97xd5xr83nd5fpkcxr3w8nkqihh12fh"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-smallvec" ,rust-smallvec-1)
                      ("rust-target-lexicon" ,rust-target-lexicon-0.12))))
   (home-page "https://github.com/EmbarkStudios/cfg-expr")
   (synopsis "parser and evaluator for Rust `cfg()` expressions.")
   (description
    "This package provides a parser and evaluator for Rust `cfg()` expressions.")
   (license (list license:expat license:asl2.0))))

(define rust-target-spec-3
  (package
   (name "rust-target-spec")
   (version "3.2.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "target-spec" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "02brqbahhwxr91fwp0928c4sq66j1jsnh4z6d8lxbivvpyml6msc"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-cfg-expr" ,rust-cfg-expr-0.17)
                      ("rust-guppy-workspace-hack" ,rust-guppy-workspace-hack-0.1)
                      ("rust-proptest" ,rust-proptest-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-target-lexicon" ,rust-target-lexicon-0.12)
                      ("rust-unicode-ident" ,rust-unicode-ident-1))))
   (home-page "https://github.com/guppy-rs/guppy")
   (synopsis "Evaluate Cargo.toml target specifications")
   (description
    "This package provides Evaluate Cargo.toml target specifications.")
   (license (list license:expat license:asl2.0))))

(define rust-smallvec-1
  (package
   (name "rust-smallvec")
   (version "1.13.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "smallvec" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0rsw5samawl3wsw6glrsb127rx6sh89a8wyikicw6dkdcjd1lpiw"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/servo/rust-smallvec")
   (synopsis
    "'Small vector' optimization: store up to a small number of items on the stack")
   (description
    "This package provides Small vector optimization: store up to a small number of items on the stack.")
   (license (list license:expat license:asl2.0))))

(define rust-serde-json-1
  (package
   (name "rust-serde-json")
   (version "1.0.132")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "serde_json" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "00yv8vyn1qiplziswm1vwam4a0xs1rfr162q75njc85kyjpvy9np"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-indexmap" ,rust-indexmap-2)
                      ("rust-itoa" ,rust-itoa-1)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-ryu" ,rust-ryu-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/serde-rs/json")
   (synopsis "JSON serialization file format")
   (description "This package provides a JSON serialization file format.")
   (license (list license:expat license:asl2.0))))

(define rust-proc-macro2-1
  (package
   (name "rust-proc-macro2")
   (version "1.0.89")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "proc-macro2" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0vlq56v41dsj69pnk7lil7fxvbfid50jnzdn3xnr31g05mkb0fgi"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-unicode-ident" ,rust-unicode-ident-1))))
   (home-page "https://github.com/dtolnay/proc-macro2")
   (synopsis
    "substitute implementation of the compiler's `proc_macro` API to decouple token-based libraries from the procedural macro use case.")
   (description
    "This package provides a substitute implementation of the compiler's `proc_macro`
API to decouple token-based libraries from the procedural macro use case.")
   (license (list license:expat license:asl2.0))))

(define rust-syn-2
  (package
   (name "rust-syn")
   (version "2.0.83")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "syn" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "18v03p3yv43y5y3sg23miqx8fwh2cncx7ws3gy0rydla2xfhys01"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-unicode-ident" ,rust-unicode-ident-1))))
   (home-page "https://github.com/dtolnay/syn")
   (synopsis "Parser for Rust source code")
   (description "This package provides Parser for Rust source code.")
   (license (list license:expat license:asl2.0))))

(define rust-serde-derive-1
  (package
   (name "rust-serde-derive")
   (version "1.0.213")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "serde_derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "198g92m9c8whvwrnrbxppwdm3pvbq7ddd35agkl5h2y514hav1by"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://serde.rs")
   (synopsis "Macros 1.1 implementation of #[derive(Serialize, Deserialize)]")
   (description
    "This package provides Macros 1.1 implementation of #[derive(Serialize, Deserialize)].")
   (license (list license:expat license:asl2.0))))

(define rust-serde-1
  (package
   (name "rust-serde")
   (version "1.0.213")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "serde" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1hcv1q7ziy27c2awc0lnhigjj6rli1863fr0szw6sip2ylzqk9ry"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde-derive" ,rust-serde-derive-1)
                      ("rust-serde-derive" ,rust-serde-derive-1))))
   (home-page "https://serde.rs")
   (synopsis "generic serialization/deserialization framework")
   (description
    "This package provides a generic serialization/deserialization framework.")
   (license (list license:expat license:asl2.0))))

(define rust-semver-1
  (package
   (name "rust-semver")
   (version "1.0.23")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "semver" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "12wqpxfflclbq4dv8sa6gchdh92ahhwn4ci1ls22wlby3h57wsb1"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/dtolnay/semver")
   (synopsis "Parser and evaluator for Cargo's flavor of Semantic Versioning")
   (description
    "This package provides Parser and evaluator for Cargo's flavor of Semantic Versioning.")
   (license (list license:expat license:asl2.0))))

(define rust-proptest-macro-0.1
  (package
   (name "rust-proptest-macro")
   (version "0.1.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "proptest-macro" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1dri79rqsf08vk5zhch0q4vls90pqxkfhqdpab8iw0g1zyvrxwip"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-convert-case" ,rust-convert-case-0.6)
                      ("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://proptest-rs.github.io/proptest/proptest/index.html")
   (synopsis "Procedural macros for the proptest crate")
   (description
    "This package provides Procedural macros for the proptest crate.")
   (license (list license:expat license:asl2.0))))

(define rust-proptest-1
  (package
   (name "rust-proptest")
   (version "1.5.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "proptest" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "13gm7mphs95cw4gbgk5qiczkmr68dvcwhp58gmiz33dq2ccm3hml"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-bit-set" ,rust-bit-set-0.5)
                      ("rust-bit-vec" ,rust-bit-vec-0.6)
                      ("rust-bitflags" ,rust-bitflags-2)
                      ("rust-lazy-static" ,rust-lazy-static-1)
                      ("rust-num-traits" ,rust-num-traits-0.2)
                      ("rust-proptest-macro" ,rust-proptest-macro-0.1)
                      ("rust-rand" ,rust-rand-0.8)
                      ("rust-rand-chacha" ,rust-rand-chacha-0.3)
                      ("rust-rand-xorshift" ,rust-rand-xorshift-0.3)
                      ("rust-regex-syntax" ,rust-regex-syntax-0.8)
                      ("rust-rusty-fork" ,rust-rusty-fork-0.3)
                      ("rust-tempfile" ,rust-tempfile-3)
                      ("rust-unarray" ,rust-unarray-0.1)
                      ("rust-x86" ,rust-x86-0.52))))
   (home-page "https://proptest-rs.github.io/proptest/proptest/index.html")
   (synopsis "Hypothesis-like property-based testing and shrinking.")
   (description
    "This package provides Hypothesis-like property-based testing and shrinking.")
   (license (list license:expat license:asl2.0))))

(define rust-petgraph-0.6
  (package
   (name "rust-petgraph")
   (version "0.6.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "petgraph" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1ns7mbxidnn2pqahbbjccxkrqkrll2i5rbxx43ns6rh6fn3cridl"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-fixedbitset" ,rust-fixedbitset-0.4)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-quickcheck" ,rust-quickcheck-0.8)
                      ("rust-rayon" ,rust-rayon-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-derive" ,rust-serde-derive-1))))
   (home-page "https://github.com/petgraph/petgraph")
   (synopsis
    "Graph data structure library. Provides graph types and graph algorithms")
   (description
    "This package provides Graph data structure library.  Provides graph types and graph algorithms.")
   (license (list license:expat license:asl2.0))))

(define rust-nested-0.1
  (package
   (name "rust-nested")
   (version "0.1.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "nested" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "17lwhdw0z8c4g00yfdasxh4zc5dq1ccylmbb0n1zw1wgcc7l4aya"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/tafia/nested")
   (synopsis
    "memory efficient container for nested collections (like `Vec<String>` or `Vec<Vec<T>>`)")
   (description
    "This package provides a memory efficient container for nested collections (like
`Vec<String>` or `Vec<Vec<T>>`).")
   (license license:expat)))

(define rust-itertools-0.13
  (package
   (name "rust-itertools")
   (version "0.13.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "itertools" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "11hiy3qzl643zcigknclh446qb9zlg4dpdzfkjaa9q9fqpgyfgj1"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-either" ,rust-either-1))))
   (home-page "https://github.com/rust-itertools/itertools")
   (synopsis
    "Extra iterator adaptors, iterator methods, free functions, and macros")
   (description
    "This package provides Extra iterator adaptors, iterator methods, free functions, and macros.")
   (license (list license:expat license:asl2.0))))

(define rust-indexmap-2
  (package
   (name "rust-indexmap")
   (version "2.6.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "indexmap" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1nmrwn8lbs19gkvhxaawffzbvrpyrb5y3drcrr645x957kz0fybh"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-arbitrary" ,rust-arbitrary-1)
                      ("rust-borsh" ,rust-borsh-1)
                      ("rust-equivalent" ,rust-equivalent-1)
                      ("rust-hashbrown" ,rust-hashbrown-0.15)
                      ("rust-quickcheck" ,rust-quickcheck-1)
                      ("rust-rayon" ,rust-rayon-1)
                      ("rust-rustc-rayon" ,rust-rustc-rayon-0.5)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/indexmap-rs/indexmap")
   (synopsis "hash table with consistent order and fast iteration.")
   (description
    "This package provides a hash table with consistent order and fast iteration.")
   (license (list license:asl2.0 license:expat))))

(define rust-guppy-workspace-hack-0.1
  (package
   (name "rust-guppy-workspace-hack")
   (version "0.1.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "guppy-workspace-hack" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "106pg6ifjq92rz5xbbv0aw4xchl1fkikpjry72p0nxczv620cqlj"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/facebookincubator/cargo-guppy")
   (synopsis "workspace-hack package, managed by hakari")
   (description
    "This package provides workspace-hack package, managed by hakari.")
   (license (list license:expat license:asl2.0))))

(define rust-snake-case-0.3
  (package
   (name "rust-snake-case")
   (version "0.3.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "snake_case" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1v4f132rk9wxiw8hb3kgnixirzr8kbfhg2lgsf4b85vbg02a0jfn"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/emilk/snake_case")
   (synopsis
    "SnakeCase is a String-like type that can only contain valid non-empty snake_case")
   (description
    "This package provides @code{SnakeCase} is a String-like type that can only contain valid non-empty
snake_case.")
   (license license:expat)))

(define rust-diffus-derive-0.10
  (package
   (name "rust-diffus-derive")
   (version "0.10.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "diffus-derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1a7sgbzhqa7gk3xhvkci91myc86gkwxs04vfxbl8f64y7l1jsfmr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-1))))
   (home-page "https://github.com/distil/diffus")
   (synopsis
    "Finds the difference between two instances of any data structure. Supports derive on structs and enums")
   (description
    "This package provides Finds the difference between two instances of any data structure.  Supports
derive on structs and enums.")
   (license license:asl2.0)))

(define rust-diffus-0.10
  (package
   (name "rust-diffus")
   (version "0.10.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "diffus" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0lsn5h1mfa8x7bfg9yqgr52p7drigpwgm5q8qh4r07dmfd5g43rw"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-diffus-derive" ,rust-diffus-derive-0.10)
                      ("rust-indexmap" ,rust-indexmap-1)
                      ("rust-itertools" ,rust-itertools-0.10)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-snake-case" ,rust-snake-case-0.3)
                      ("rust-uuid" ,rust-uuid-0.5))))
   (home-page "https://github.com/distil/diffus")
   (synopsis
    "Finds the difference between two instances of any data structure. Supports: collections, Strings, Maps etc. Uses LCS where applicable. Also supports derive via `diffus-derive`")
   (description
    "This package provides Finds the difference between two instances of any data structure.  Supports:
collections, Strings, Maps etc.  Uses LCS where applicable.  Also supports
derive via `diffus-derive`.")
   (license license:asl2.0)))

(define rust-guppy-summaries-0.7
  (package
   (name "rust-guppy-summaries")
   (version "0.7.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "guppy-summaries" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0ap7yqccwhd65xh0njbvaggpk81bgjiwy4a8fm43nlc7ynw3kl4b"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-camino" ,rust-camino-1)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-diffus" ,rust-diffus-0.10)
                      ("rust-guppy-workspace-hack" ,rust-guppy-workspace-hack-0.1)
                      ("rust-semver" ,rust-semver-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-toml" ,rust-toml-0.5))))
   (home-page "https://github.com/guppy-rs/guppy")
   (synopsis "Build summaries for Cargo, created by guppy")
   (description
    "This package provides Build summaries for Cargo, created by guppy.")
   (license (list license:expat license:asl2.0))))

(define rust-debug-ignore-1
  (package
   (name "rust-debug-ignore")
   (version "1.0.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "debug-ignore" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "08gwdny6124ggy4hyli92hdyiqc5j2z9lqhbw81k0mgljcfyvrzz"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/sunshowers-code/debug-ignore")
   (synopsis
    "newtype wrapper that causes a field to be skipped while printing out Debug output.")
   (description
    "This package provides a newtype wrapper that causes a field to be skipped while
printing out Debug output.")
   (license (list license:expat license:asl2.0))))

(define rust-guppy-0.17
  (package
   (name "rust-guppy")
   (version "0.17.8")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "guppy" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0qza4dq8xpvql32prxp2g97mvgzm861qnc0y32j18dprmkfg2ixz"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-ahash" ,rust-ahash-0.8)
                      ("rust-camino" ,rust-camino-1)
                      ("rust-cargo-metadata" ,rust-cargo-metadata-0.18)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-debug-ignore" ,rust-debug-ignore-1)
                      ("rust-fixedbitset" ,rust-fixedbitset-0.4)
                      ("rust-guppy-summaries" ,rust-guppy-summaries-0.7)
                      ("rust-guppy-workspace-hack" ,rust-guppy-workspace-hack-0.1)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-itertools" ,rust-itertools-0.13)
                      ("rust-nested" ,rust-nested-0.1)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-pathdiff" ,rust-pathdiff-0.2)
                      ("rust-petgraph" ,rust-petgraph-0.6)
                      ("rust-proptest" ,rust-proptest-1)
                      ("rust-proptest-derive" ,rust-proptest-derive-0.4)
                      ("rust-rayon" ,rust-rayon-1)
                      ("rust-semver" ,rust-semver-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-smallvec" ,rust-smallvec-1)
                      ("rust-static-assertions" ,rust-static-assertions-1)
                      ("rust-target-spec" ,rust-target-spec-3)
                      ("rust-toml" ,rust-toml-0.5))))
   (home-page "https://github.com/guppy-rs/guppy")
   (synopsis "Track and query Cargo dependency graphs")
   (description
    "This package provides Track and query Cargo dependency graphs.")
   (license (list license:expat license:asl2.0))))

(define rust-env-logger-0.11
  (package
   (name "rust-env-logger")
   (version "0.11.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "env_logger" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "13812wq68kybv2vj6rpnhbl7ammlhggcb7vq68bkichzp4cscgz1"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-anstream" ,rust-anstream-0.6)
                      ("rust-anstyle" ,rust-anstyle-1)
                      ("rust-env-filter" ,rust-env-filter-0.1)
                      ("rust-humantime" ,rust-humantime-2)
                      ("rust-log" ,rust-log-0.4))))
   (home-page "https://github.com/rust-cli/env_logger")
   (synopsis
    "logging implementation for `log` which is configured via an environment
variable.")
   (description
    "This package provides a logging implementation for `log` which is configured via
an environment variable.")
   (license (list license:expat license:asl2.0))))

(define rust-enable-ansi-support-0.2
  (package
   (name "rust-enable-ansi-support")
   (version "0.2.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "enable-ansi-support" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0q5wv5b9inh7kzc2464ch51ffk920f9yb0q9xvvlp9cs5apg6kxa"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-windows-sys" ,rust-windows-sys-0.42))))
   (home-page "https://github.com/sunshowers-code/enable-ansi-support")
   (synopsis "Enable ANSI escape code support on Windows 10")
   (description
    "This package provides Enable ANSI escape code support on Windows 10.")
   (license license:expat)))

(define rust-shared-child-1
  (package
   (name "rust-shared-child")
   (version "1.0.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "shared_child" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "035679h89ppqcfkjzgz9bb2hdlkw5wjv598l310xz8frmqw97yh9"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-libc" ,rust-libc-0.2)
                      ("rust-windows-sys" ,rust-windows-sys-0.59))))
   (home-page "https://github.com/oconnor663/shared_child.rs")
   (synopsis "a library for using child processes from multiple threads")
   (description
    "This package provides a library for using child processes from multiple threads.")
   (license license:expat)))

(define rust-duct-0.13
  (package
   (name "rust-duct")
   (version "0.13.7")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "duct" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "174jk13rlvfgypha4f3l27mzzyc0ci7zginh5hjn6jr2s4c5gaz4"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-libc" ,rust-libc-0.2)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-os-pipe" ,rust-os-pipe-1)
                      ("rust-shared-child" ,rust-shared-child-1))))
   (home-page "https://github.com/oconnor663/duct.rs")
   (synopsis "a library for running child processes")
   (description
    "This package provides a library for running child processes.")
   (license license:expat)))

(define rust-color-eyre-0.6
  (package
   (name "rust-color-eyre")
   (version "0.6.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "color-eyre" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1m9shifr9sdw0drszzyhvaq5jysrsiki44bl7m1gfdzj8rg6y52m"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-backtrace" ,rust-backtrace-0.3)
                      ("rust-color-spantrace" ,rust-color-spantrace-0.2)
                      ("rust-eyre" ,rust-eyre-0.6)
                      ("rust-indenter" ,rust-indenter-0.3)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-owo-colors" ,rust-owo-colors-3)
                      ("rust-tracing-error" ,rust-tracing-error-0.2)
                      ("rust-url" ,rust-url-2))))
   (home-page "https://github.com/eyre-rs/eyre")
   (synopsis
    "An error report handler for panics and eyre::Reports for colorful, consistent, and well formatted error reports for all kinds of errors")
   (description
    "This package provides An error report handler for panics and eyre::Reports for colorful, consistent,
and well formatted error reports for all kinds of errors.")
   (license (list license:expat license:asl2.0))))

(define rust-clap-derive-4
  (package
   (name "rust-clap-derive")
   (version "4.5.18")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "clap_derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1ardb26bvcpg72q9myr7yir3a8c83gx7vxk1cccabsd9n73s1ija"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-heck" ,rust-heck-0.5)
                      ("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2))))
   (home-page "https://github.com/clap-rs/clap")
   (synopsis "Parse command line argument by defining a struct, derive crate")
   (description
    "This package provides Parse command line argument by defining a struct, derive crate.")
   (license (list license:expat license:asl2.0))))

(define rust-unicode-width-0.2
  (package
   (name "rust-unicode-width")
   (version "0.2.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "unicode-width" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1zd0r5vs52ifxn25rs06gxrgz8cmh4xpra922k0xlmrchib1kj0z"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1)
                      ("rust-rustc-std-workspace-std" ,rust-rustc-std-workspace-std-1))))
   (home-page "https://github.com/unicode-rs/unicode-width")
   (synopsis "Determine displayed width of `char` and `str` types
according to Unicode Standard Annex #11 rules.")
   (description
    "This package provides Determine displayed width of `char` and `str` types according to Unicode
Standard Annex #11 rules.")
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

(define rust-terminal-size-0.4
  (package
   (name "rust-terminal-size")
   (version "0.4.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "terminal_size" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1vx6a5klj7sjkx59v78gh93j445s09y2fasiykwgsb04rbbrnnag"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-rustix" ,rust-rustix-0.38)
                      ("rust-windows-sys" ,rust-windows-sys-0.59))))
   (home-page "https://github.com/eminence/terminal-size")
   (synopsis "Gets the size of your Linux or Windows terminal")
   (description
    "This package provides Gets the size of your Linux or Windows terminal.")
   (license (list license:expat license:asl2.0))))

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

(define rust-adler2-2
  (package
   (name "rust-adler2")
   (version "2.0.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "adler2" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "09r6drylvgy8vv8k20lnbvwq8gp09h7smfn6h1rxsy15pgh629si"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1))))
   (home-page "https://github.com/oyvindln/adler2")
   (synopsis "simple clean-room implementation of the Adler-32 checksum")
   (description
    "This package provides a simple clean-room implementation of the Adler-32
checksum.")
   (license (list license:bsd-0 license:expat license:asl2.0))))

(define rust-miniz-oxide-0.8
  (package
   (name "rust-miniz-oxide")
   (version "0.8.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "miniz_oxide" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1wadxkg6a6z4lr7kskapj5d8pxlx7cp1ifw4daqnkzqjxych5n72"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-adler2" ,rust-adler2-2)
                      ("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-rustc-std-workspace-alloc" ,rust-rustc-std-workspace-alloc-1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1)
                      ("rust-simd-adler32" ,rust-simd-adler32-0.3))))
   (home-page "https://github.com/Frommi/miniz_oxide/tree/master/miniz_oxide")
   (synopsis
    "DEFLATE compression and decompression library rewritten in Rust based on miniz")
   (description
    "This package provides DEFLATE compression and decompression library rewritten in Rust based on miniz.")
   (license (list license:expat license:zlib license:asl2.0))))

(define rust-libc-0.2
  (package
   (name "rust-libc")
   (version "0.2.161")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "libc" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1lc5s3zd0491x9zxrv2kvclai1my1spz950pkkyry4vwh318k54f"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1))))
   (home-page "https://github.com/rust-lang/libc")
   (synopsis "Raw FFI bindings to platform libraries like libc.")
   (description
    "This package provides Raw FFI bindings to platform libraries like libc.")
   (license (list license:expat license:asl2.0))))

(define rust-ahash-0.8
  (package
   (name "rust-ahash")
   (version "0.8.11")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "ahash" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "04chdfkls5xmhp1d48gnjsmglbqibizs3bpbj6rsj604m10si7g8"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-atomic-polyfill" ,rust-atomic-polyfill-1)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-const-random" ,rust-const-random-0.1)
                      ("rust-getrandom" ,rust-getrandom-0.2)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-version-check" ,rust-version-check-0.9)
                      ("rust-zerocopy" ,rust-zerocopy-0.7))))
   (home-page "https://github.com/tkaitchuck/ahash")
   (synopsis
    "non-cryptographic hash function using AES-NI for high performance")
   (description
    "This package provides a non-cryptographic hash function using AES-NI for high
performance.")
   (license (list license:expat license:asl2.0))))

(define rust-wasmparser-0.218
  (package
   (name "rust-wasmparser")
   (version "0.218.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "wasmparser" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1p65jvj1i6bh180hd656z8yzkn3zx8vs3a6i5lmsgspczk3ld7mh"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-ahash" ,rust-ahash-0.8)
                      ("rust-bitflags" ,rust-bitflags-2)
                      ("rust-hashbrown" ,rust-hashbrown-0.14)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-semver" ,rust-semver-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page
    "https://github.com/bytecodealliance/wasm-tools/tree/main/crates/wasmparser")
   (synopsis
    "simple event-driven library for parsing WebAssembly binary files.")
   (description
    "This package provides a simple event-driven library for parsing
@code{WebAssembly} binary files.")
   (license (list license:asl2.0
                  license:expat))))

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

(define rust-foldhash-0.1
  (package
   (name "rust-foldhash")
   (version "0.1.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "foldhash" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "18in1a8mjcg43pfrdkhwzr0w988zb2bmb6sqwi07snjlkhvcc7pq"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/orlp/foldhash")
   (synopsis
    "fast, non-cryptographic, minimally DoS-resistant hashing algorithm.")
   (description
    "This package provides a fast, non-cryptographic, minimally @code{DoS-resistant}
hashing algorithm.")
   (license license:zlib)))

(define rust-cfg-aliases-0.2
  (package
   (name "rust-cfg-aliases")
   (version "0.2.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cfg_aliases" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "092pxdc1dbgjb6qvh83gk56rkic2n2ybm4yvy76cgynmzi3zwfk1"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/katharostech/cfg_aliases")
   (synopsis
    "tiny utility to help save you a lot of effort with long winded `#[cfg()]` checks.")
   (description
    "This package provides a tiny utility to help save you a lot of effort with long
winded `#[cfg()]` checks.")
   (license license:expat)))

(define rust-borsh-derive-1
  (package
   (name "rust-borsh-derive")
   (version "1.5.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "borsh-derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "02ych16fa7fqwhjww3m5mm6ndm5g9kv5p7v1r96wslsgfq2q1vy3"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-once-cell" ,rust-once-cell-1)
                      ("rust-proc-macro-crate" ,rust-proc-macro-crate-3)
                      ("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-syn" ,rust-syn-2)
                      ("rust-syn-derive" ,rust-syn-derive-0.1))))
   (home-page "http://borsh.io")
   (synopsis "Binary Object Representation Serializer for Hashing")
   (description
    "This package provides Binary Object Representation Serializer for Hashing.")
   (license license:asl2.0)))

(define rust-borsh-1
  (package
   (name "rust-borsh")
   (version "1.5.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "borsh" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1vgq96r3k9srkr9xww1pf63vdmslhnk4ciqaqzfjqqpgbpajwdm6"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-ascii" ,rust-ascii-1)
                      ("rust-borsh-derive" ,rust-borsh-derive-1)
                      ("rust-bson" ,rust-bson-2)
                      ("rust-bytes" ,rust-bytes-1)
                      ("rust-cfg-aliases" ,rust-cfg-aliases-0.2)
                      ("rust-hashbrown" ,rust-hashbrown-0.11))))
   (home-page "http://borsh.io")
   (synopsis "Binary Object Representation Serializer for Hashing")
   (description
    "This package provides Binary Object Representation Serializer for Hashing.")
   (license (list license:expat license:asl2.0))))

(define rust-hashbrown-0.15
  (package
   (name "rust-hashbrown")
   (version "0.15.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "hashbrown" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1yx4xq091s7i6mw6bn77k8cp4jrpcac149xr32rg8szqsj27y20y"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-allocator-api2" ,rust-allocator-api2-0.2)
                      ("rust-borsh" ,rust-borsh-1)
                      ("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-equivalent" ,rust-equivalent-1)
                      ("rust-foldhash" ,rust-foldhash-0.1)
                      ("rust-rayon" ,rust-rayon-1)
                      ("rust-rustc-std-workspace-alloc" ,rust-rustc-std-workspace-alloc-1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/rust-lang/hashbrown")
   (synopsis "Rust port of Google's SwissTable hash map")
   (description
    "This package provides a Rust port of Google's @code{SwissTable} hash map.")
   (license (list license:expat license:asl2.0))))

(define rust-object-0.36
  (package
   (name "rust-object")
   (version "0.36.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "object" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0gk8lhbs229c68lapq6w6qmnm4jkj48hrcw5ilfyswy514nhmpxf"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-crc32fast" ,rust-crc32fast-1)
                      ("rust-flate2" ,rust-flate2-1)
                      ("rust-hashbrown" ,rust-hashbrown-0.15)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-memchr" ,rust-memchr-2)
                      ("rust-rustc-std-workspace-alloc" ,rust-rustc-std-workspace-alloc-1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1)
                      ("rust-ruzstd" ,rust-ruzstd-0.7)
                      ("rust-wasmparser" ,rust-wasmparser-0.218))))
   (home-page "https://github.com/gimli-rs/object")
   (synopsis "unified interface for reading and writing object file formats.")
   (description
    "This package provides a unified interface for reading and writing object file
formats.")
   (license (list license:asl2.0 license:expat))))

(define rust-memmap2-0.9
  (package
   (name "rust-memmap2")
   (version "0.9.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "memmap2" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0krpvvkpg4i3l05cv3q2xk24a1vj5c86gbrli2wzhj1qkpnpwgzx"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-libc" ,rust-libc-0.2)
                      ("rust-stable-deref-trait" ,rust-stable-deref-trait-1))))
   (home-page "https://github.com/RazrFalcon/memmap2-rs")
   (synopsis "Cross-platform Rust API for memory-mapped file IO")
   (description
    "This package provides Cross-platform Rust API for memory-mapped file IO.")
   (license (list license:expat license:asl2.0))))

(define rust-gimli-0.31
  (package
   (name "rust-gimli")
   (version "0.31.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "gimli" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0gvqc0ramx8szv76jhfd4dms0zyamvlg4whhiz11j34hh3dqxqh7"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-fallible-iterator" ,rust-fallible-iterator-0.3)
                      ("rust-indexmap" ,rust-indexmap-2)
                      ("rust-rustc-std-workspace-alloc" ,rust-rustc-std-workspace-alloc-1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1)
                      ("rust-stable-deref-trait" ,rust-stable-deref-trait-1))))
   (home-page "https://github.com/gimli-rs/gimli")
   (synopsis "library for reading and writing the DWARF debugging format.")
   (description
    "This package provides a library for reading and writing the DWARF debugging
format.")
   (license (list license:expat license:asl2.0))))

(define rust-addr2line-0.24
  (package
   (name "rust-addr2line")
   (version "0.24.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "addr2line" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1hd1i57zxgz08j6h5qrhsnm2fi0bcqvsh389fw400xm3arz2ggnz"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-clap" ,rust-clap-4)
                      ("rust-compiler-builtins" ,rust-compiler-builtins-0.1)
                      ("rust-cpp-demangle" ,rust-cpp-demangle-0.4)
                      ("rust-fallible-iterator" ,rust-fallible-iterator-0.3)
                      ("rust-gimli" ,rust-gimli-0.31)
                      ("rust-memmap2" ,rust-memmap2-0.9)
                      ("rust-object" ,rust-object-0.36)
                      ("rust-rustc-demangle" ,rust-rustc-demangle-0.1)
                      ("rust-rustc-std-workspace-alloc" ,rust-rustc-std-workspace-alloc-1)
                      ("rust-rustc-std-workspace-core" ,rust-rustc-std-workspace-core-1)
                      ("rust-smallvec" ,rust-smallvec-1)
                      ("rust-typed-arena" ,rust-typed-arena-2))))
   (home-page "https://github.com/gimli-rs/addr2line")
   (synopsis
    "cross-platform symbolication library written in Rust, using `gimli`")
   (description
    "This package provides a cross-platform symbolication library written in Rust,
using `gimli`.")
   (license (list license:asl2.0 license:expat))))

(define rust-backtrace-0.3
  (package
   (name "rust-backtrace")
   (version "0.3.74")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "backtrace" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "06pfif7nwx66qf2zaanc2fcq7m64i91ki9imw9xd3bnz5hrwp0ld"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-addr2line" ,rust-addr2line-0.24)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-cpp-demangle" ,rust-cpp-demangle-0.4)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-miniz-oxide" ,rust-miniz-oxide-0.8)
                      ("rust-object" ,rust-object-0.36)
                      ("rust-rustc-demangle" ,rust-rustc-demangle-0.1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-windows-targets" ,rust-windows-targets-0.52))))
   (home-page "https://github.com/rust-lang/backtrace-rs")
   (synopsis
    "library to acquire a stack trace (backtrace) at runtime in a Rust program.")
   (description
    "This package provides a library to acquire a stack trace (backtrace) at runtime
in a Rust program.")
   (license (list license:expat license:asl2.0))))

(define rust-anstyle-1
  (package
   (name "rust-anstyle")
   (version "1.0.8")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "anstyle" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1cfmkza63xpn1kkz844mgjwm9miaiz4jkyczmwxzivcsypk1vv0v"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t))
   (home-page "https://github.com/rust-cli/anstyle")
   (synopsis "ANSI text styling")
   (description "This package provides ANSI text styling.")
   (license (list license:expat license:asl2.0))))

(define rust-clap-builder-4
  (package
   (name "rust-clap-builder")
   (version "4.5.20")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "clap_builder" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0m6w10l2f65h3ch0d53lql6p26xxrh20ffipra9ysjsfsjmq1g0r"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-anstream" ,rust-anstream-0.6)
                      ("rust-anstyle" ,rust-anstyle-1)
                      ("rust-backtrace" ,rust-backtrace-0.3)
                      ("rust-clap-lex" ,rust-clap-lex-0.7)
                      ("rust-strsim" ,rust-strsim-0.11)
                      ("rust-terminal-size" ,rust-terminal-size-0.4)
                      ("rust-unicase" ,rust-unicase-2)
                      ("rust-unicode-width" ,rust-unicode-width-0.2))))
   (home-page "https://github.com/clap-rs/clap")
   (synopsis
    "simple to use, efficient, and full-featured Command Line Argument Parser")
   (description
    "This package provides a simple to use, efficient, and full-featured Command Line
Argument Parser.")
   (license (list license:expat license:asl2.0))))

(define rust-clap-4
  (package
   (name "rust-clap")
   (version "4.5.20")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "clap" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1s37v23gcxkjy4800qgnkxkpliz68vslpr5sgn1xar56hmnkfzxr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-clap-builder" ,rust-clap-builder-4)
                      ("rust-clap-derive" ,rust-clap-derive-4))))
   (home-page "https://github.com/clap-rs/clap")
   (synopsis
    "simple to use, efficient, and full-featured Command Line Argument Parser")
   (description
    "This package provides a simple to use, efficient, and full-featured Command Line
Argument Parser.")
   (license (list license:expat license:asl2.0))))

(define rust-camino-1
  (package
   (name "rust-camino")
   (version "1.1.9")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "camino" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1lqszl12l1146jf8g01rvjmapif82mhzih870ln3x0dmcr4yr5lb"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proptest" ,rust-proptest-1)
                      ("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/camino-rs/camino")
   (synopsis "UTF-8 paths")
   (description "This package provides UTF-8 paths.")
   (license (list license:expat license:asl2.0))))

(define-public rust-cargo-nextest
  (package
   (name "rust-cargo-nextest")
   (version "0.9.81")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cargo-nextest" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1v6iavxczwcfk858xwj7ip560bd85ccn1bdxnsscclbb5156770w"))))
   (native-inputs (list pkg-config zstd (list zstd "lib")))
   (build-system cargo-build-system)
   (arguments
    `(#:cargo-inputs (("rust-camino" ,rust-camino-1)
                      ("rust-camino" ,rust-camino-1)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-clap" ,rust-clap-4)
                      ("rust-color-eyre" ,rust-color-eyre-0.6)
                      ("rust-dialoguer" ,rust-dialoguer-0.11)
                      ("rust-duct" ,rust-duct-0.13)
                      ("rust-enable-ansi-support" ,rust-enable-ansi-support-0.2)
                      ("rust-env-logger" ,rust-env-logger-0.11)
                      ("rust-guppy" ,rust-guppy-0.17)
                      ("rust-itertools" ,rust-itertools-0.13)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-miette" ,rust-miette-7)
                      ("rust-nextest-filtering" ,rust-nextest-filtering-0.12)
                      ("rust-nextest-metadata" ,rust-nextest-metadata-0.12)
                      ("rust-nextest-runner" ,rust-nextest-runner-0.64)
                      ("rust-nextest-workspace-hack" ,rust-nextest-workspace-hack-0.1)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-owo-colors" ,rust-owo-colors-4)
                      ("rust-pathdiff" ,rust-pathdiff-0.2)
                      ("rust-quick-junit" ,rust-quick-junit-0.5)
                      ("rust-semver" ,rust-semver-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-shell-words" ,rust-shell-words-1)
                      ("rust-supports-color" ,rust-supports-color-3)
                      ("rust-supports-unicode" ,rust-supports-unicode-3)
                      ("rust-swrite" ,rust-swrite-0.1)
                      ("rust-thiserror" ,rust-thiserror-1))
      #:cargo-development-inputs (("rust-camino-tempfile" ,rust-camino-tempfile-1))))
   (home-page "https://github.com/nextest-rs/nextest")
   (synopsis "next-generation test runner for Rust.")
   (description
    "This package provides a next-generation test runner for Rust.")
   (license (list license:asl2.0 license:expat))))
