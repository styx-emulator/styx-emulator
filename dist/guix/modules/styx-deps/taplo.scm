(define-module (styx-deps taplo)
  #:use-module (guix)
  #:use-module (guix build-system cargo)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages crates-io)
  #:use-module (guix git-download)
  )

(define rust-debugid-0.7
  (package
   (name "rust-debugid")
   (version "0.7.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "debugid" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0c370jsmnb0ahssda6f11l72ns1xpqrcmswa6y2zhknq66pqgvnn"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1)
                      ("rust-uuid" ,rust-uuid-0.8))))
   (home-page "https://sentry.io/")
   (synopsis "Common reusable types for implementing the sentry.io protocol")
   (description
    "This package provides Common reusable types for implementing the sentry.io protocol.")
   (license license:asl2.0)))

(define rust-symbolic-common-8
  (package
   (name "rust-symbolic-common")
   (version "8.8.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "symbolic-common" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0h7mcqwrhi0n6qb1h1vfz5m94dqhlqhr0spfk81mhbk4sl1gjlgm"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-debugid" ,rust-debugid-0.7)
                      ("rust-memmap2" ,rust-memmap2-0.5)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-stable-deref-trait" ,rust-stable-deref-trait-1)
                      ("rust-uuid" ,rust-uuid-0.8))))
   (home-page "https://github.com/getsentry/symbolic")
   (synopsis
    "Common types and utilities for symbolic, a library to symbolicate and process
stack traces from native applications, minidumps or minified JavaScript.")
   (description
    "This package provides Common types and utilities for symbolic, a library to symbolicate and process
stack traces from native applications, minidumps or minified @code{JavaScript}.")
   (license license:expat)))

(define rust-symbolic-demangle-8
  (package
   (name "rust-symbolic-demangle")
   (version "8.8.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "symbolic-demangle" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0l1p8j37n7xkg8b6fgipqkcvbxl0w0kcxfwbm82l3cbf9rxwlr25"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-cc" ,rust-cc-1)
                      ("rust-cpp-demangle" ,rust-cpp-demangle-0.3)
                      ("rust-msvc-demangler" ,rust-msvc-demangler-0.9)
                      ("rust-rustc-demangle" ,rust-rustc-demangle-0.1)
                      ("rust-symbolic-common" ,rust-symbolic-common-8))))
   (home-page "https://github.com/getsentry/symbolic")
   (synopsis
    "library to demangle symbols from various languages and compilers.")
   (description
    "This package provides a library to demangle symbols from various languages and
compilers.")
   (license license:expat)))

(define rust-pprof-0.9
  (package
   (name "rust-pprof")
   (version "0.9.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "pprof" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0p93ipri1a614j68vppq43x1f19spdl9zafyrvwbi9naxb04jwd9"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-backtrace" ,rust-backtrace-0.3)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-criterion" ,rust-criterion-0.3)
                      ("rust-findshlibs" ,rust-findshlibs-0.10)
                      ("rust-inferno" ,rust-inferno-0.11)
                      ("rust-libc" ,rust-libc-0.2)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-nix" ,rust-nix-0.24)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-parking-lot" ,rust-parking-lot-0.12)
                      ("rust-prost" ,rust-prost-0.10)
                      ("rust-prost-build" ,rust-prost-build-0.10)
                      ("rust-prost-derive" ,rust-prost-derive-0.10)
                      ("rust-protobuf" ,rust-protobuf-2)
                      ("rust-protobuf-codegen-pure" ,rust-protobuf-codegen-pure-2)
                      ("rust-smallvec" ,rust-smallvec-1)
                      ("rust-symbolic-demangle" ,rust-symbolic-demangle-8)
                      ("rust-tempfile" ,rust-tempfile-3)
                      ("rust-thiserror" ,rust-thiserror-1))))
   (home-page "https://github.com/tikv/pprof-rs")
   (synopsis "An internal perf tools for rust programs")
   (description
    "This package provides An internal perf tools for rust programs.")
   (license license:asl2.0)))

(define rust-rowan-0.15
  (package
   (name "rust-rowan")
   (version "0.15.16")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "rowan" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0gdf8whwfzv41dr6xp2rhvgy83ckgg7wa7bss8rfcipsac12nm0a"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-countme" ,rust-countme-3)
                      ("rust-hashbrown" ,rust-hashbrown-0.14)
                      ("rust-rustc-hash" ,rust-rustc-hash-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-text-size" ,rust-text-size-1))))
   (home-page "https://github.com/rust-analyzer/rowan")
   (synopsis "Library for generic lossless syntax trees")
   (description
    "This package provides Library for generic lossless syntax trees.")
   (license (list license:expat license:asl2.0))))

(define rust-logos-derive-0.12
  (package
   (name "rust-logos-derive")
   (version "0.12.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "logos-derive" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0v295x78vcskab88hshl530w9d1vn61cmlaic4d6dydsila4kn51"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-beef" ,rust-beef-0.5)
                      ("rust-fnv" ,rust-fnv-1)
                      ("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1)
                      ("rust-regex-syntax" ,rust-regex-syntax-0.6)
                      ("rust-syn" ,rust-syn-1))))
   (home-page "https://logos.maciej.codes/")
   (synopsis "Create ridiculously fast Lexers")
   (description "This package provides Create ridiculously fast Lexers.")
   (license (list license:expat license:asl2.0))))

(define rust-logos-0.12
  (package
   (name "rust-logos")
   (version "0.12.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "logos" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1w82qm3hck5cr6ax3j3yzrpf4zzbffahz126ahyqwyn6h8b072xz"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-logos-derive" ,rust-logos-derive-0.12))))
   (home-page "https://logos.maciej.codes/")
   (synopsis "Create ridiculously fast Lexers")
   (description "This package provides Create ridiculously fast Lexers.")
   (license (list license:expat license:asl2.0))))

(define-public rust-taplo
  (package
   (name "rust-taplo")
   (version "0.13.2")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "taplo" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0kfi882bprhzy3z4029klag62y5gmlfw3pr63qpz3ski86n42281"))))
   (build-system cargo-build-system)
   (arguments
    `(#:cargo-inputs (("rust-ahash" ,rust-ahash-0.8)
                      ("rust-arc-swap" ,rust-arc-swap-1)
                      ("rust-either" ,rust-either-1)
                      ("rust-globset" ,rust-globset-0.4)
                      ("rust-itertools" ,rust-itertools-0.10)
                      ("rust-logos" ,rust-logos-0.12)
                      ("rust-once-cell" ,rust-once-cell-1)
                      ("rust-rowan" ,rust-rowan-0.15)
                      ("rust-schemars" ,rust-schemars-0.8)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-json" ,rust-serde-json-1)
                      ("rust-thiserror" ,rust-thiserror-1)
                      ("rust-time" ,rust-time-0.3)
                      ("rust-tracing" ,rust-tracing-0.1))
      #:cargo-development-inputs (("rust-assert-json-diff" ,rust-assert-json-diff-2)
                                  ("rust-criterion" ,rust-criterion-0.3)
                                  ("rust-difference" ,rust-difference-2)
                                  ("rust-pprof" ,rust-pprof-0.9)
                                  ("rust-serde-json" ,rust-serde-json-1)
                                  ("rust-toml" ,rust-toml-0.7))))
   (home-page "https://taplo.tamasfe.dev")
   (synopsis "TOML parser, analyzer and formatter library")
   (description
    "This package provides a TOML parser, analyzer and formatter library.")
   (license license:expat)))
