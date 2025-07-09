(define-module (styx-deps cargo-hakari)
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
  #:use-module (gnu packages shells)
  #:use-module (guix git-download)
  )


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

(define rust-toml-edit-0.17
  (package
   (name "rust-toml-edit")
   (version "0.17.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "toml_edit" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1insqwmqj73mbrlnyq578sxq12qky9nn5agdp647xzay6iccak53"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-indexmap" ,rust-indexmap-1)
                      ("rust-itertools" ,rust-itertools-0.10)
                      ("rust-kstring" ,rust-kstring-2)
                      ("rust-nom8" ,rust-nom8-0.2)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-toml-datetime" ,rust-toml-datetime-0.5))))
   (home-page "https://github.com/toml-rs/toml")
   (synopsis "Yet another format-preserving TOML parser")
   (description
    "This package provides Yet another format-preserving TOML parser.")
   (license (list license:expat license:asl2.0))))

(define rust-tabular-0.2
  (package
   (name "rust-tabular")
   (version "0.2.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "tabular" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1ld3j7zx5ri87wf379n9mhdqgn6wibbfj3gr7nbs3027a4n8i8nr"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-strip-ansi-escapes" ,rust-strip-ansi-escapes-0.1)
                      ("rust-unicode-width" ,rust-unicode-width-0.1))))
   (home-page "https://github.com/tabular-rs/tabular-rs")
   (synopsis "Plain text tables, aligned automatically")
   (description
    "This package provides Plain text tables, aligned automatically.")
   (license (list license:expat license:asl2.0))))

(define rust-include-dir-macros-0.7
  (package
   (name "rust-include-dir-macros")
   (version "0.7.4")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "include_dir_macros" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0x8smnf6knd86g69p19z5lpfsaqp8w0nx14kdpkz1m8bxnkqbavw"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-proc-macro2" ,rust-proc-macro2-1)
                      ("rust-quote" ,rust-quote-1))))
   (home-page "https://github.com/Michael-F-Bryan/include_dir")
   (synopsis "The procedural macro used by include_dir")
   (description
    "This package provides The procedural macro used by include_dir.")
   (license license:expat)))

(define rust-include-dir-0.7
  (package
   (name "rust-include-dir")
   (version "0.7.4")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "include_dir" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1pfh3g45z88kwq93skng0n6g3r7zkhq9ldqs9y8rvr7i11s12gcj"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-glob" ,rust-glob-0.3)
                      ("rust-include-dir-macros" ,rust-include-dir-macros-0.7))))
   (home-page "https://github.com/Michael-F-Bryan/include_dir")
   (synopsis "Embed the contents of a directory in your binary")
   (description
    "This package provides Embed the contents of a directory in your binary.")
   (license license:expat)))

(define rust-diffy-0.4
  (package
   (name "rust-diffy")
   (version "0.4.0")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "diffy" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1jz6qi82gh16s9b861g3r9zpyag5n538m0gc8w2ffqvsbfb42c2x"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-nu-ansi-term" ,rust-nu-ansi-term-0.50))))
   (home-page "https://github.com/bmwill/diffy")
   (synopsis "Tools for finding and manipulating differences between files")
   (description
    "This package provides tools for finding and manipulating differences between
files.")
   (license (list license:expat license:asl2.0))))

(define rust-bimap-0.6
  (package
   (name "rust-bimap")
   (version "0.6.3")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "bimap" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "1xx4dns6hj0mf1sl47lh3r0z4jcvmhqhsr7qacjs69d3lqf5y313"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-serde" ,rust-serde-1))))
   (home-page "https://github.com/billyrieger/bimap-rs/")
   (synopsis "Bijective maps")
   (description "This package provides Bijective maps.")
   (license (list license:asl2.0 license:expat))))

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

(define rust-hakari-0.17
  (package
   (name "rust-hakari")
   (version "0.17.5")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "hakari" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0h671zvq1d3iillqasjgb01wdqgsk9615n44bxpvlrh0m3l4v2xi"))))
   (build-system cargo-build-system)
   (arguments
    `(#:skip-build? #t
      #:cargo-inputs (("rust-ahash" ,rust-ahash-0.8)
                      ("rust-atomicwrites" ,rust-atomicwrites-0.4)
                      ("rust-bimap" ,rust-bimap-0.6)
                      ("rust-camino" ,rust-camino-1)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-debug-ignore" ,rust-debug-ignore-1)
                      ("rust-diffy" ,rust-diffy-0.4)
                      ("rust-guppy" ,rust-guppy-0.17)
                      ("rust-guppy-workspace-hack" ,rust-guppy-workspace-hack-0.1)
                      ("rust-include-dir" ,rust-include-dir-0.7)
                      ("rust-indenter" ,rust-indenter-0.3)
                      ("rust-itertools" ,rust-itertools-0.13)
                      ("rust-owo-colors" ,rust-owo-colors-3)
                      ("rust-pathdiff" ,rust-pathdiff-0.2)
                      ("rust-proptest" ,rust-proptest-1)
                      ("rust-proptest-derive" ,rust-proptest-derive-0.4)
                      ("rust-rayon" ,rust-rayon-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-tabular" ,rust-tabular-0.2)
                      ("rust-target-spec" ,rust-target-spec-3)
                      ("rust-toml" ,rust-toml-0.5)
                      ("rust-toml-edit" ,rust-toml-edit-0.17)
                      ("rust-twox-hash" ,rust-twox-hash-1))))
   (home-page "https://github.com/guppy-rs/guppy")
   (synopsis
    "Manage workspace-hack packages that do feature unification inside workspaces")
   (description
    "This package provides Manage workspace-hack packages that do feature unification inside workspaces.")
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

(define-public rust-cargo-hakari
  (package
   (name "rust-cargo-hakari")
   (version "0.9.33")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cargo-hakari" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "0fdzc4fcnnqhj1bxv1lmym2kl9w8hmrfjnvza8rbpvnj8ywm9bds"))))
   (build-system cargo-build-system)
   (arguments
    `(#:cargo-inputs (("rust-camino" ,rust-camino-1)
                      ("rust-cfg-if" ,rust-cfg-if-1)
                      ("rust-clap" ,rust-clap-4)
                      ("rust-color-eyre" ,rust-color-eyre-0.6)
                      ("rust-dialoguer" ,rust-dialoguer-0.11)
                      ("rust-duct" ,rust-duct-0.13)
                      ("rust-enable-ansi-support" ,rust-enable-ansi-support-0.2)
                      ("rust-env-logger" ,rust-env-logger-0.11)
                      ("rust-guppy" ,rust-guppy-0.17)
                      ("rust-guppy-workspace-hack" ,rust-guppy-workspace-hack-0.1)
                      ("rust-hakari" ,rust-hakari-0.17)
                      ("rust-log" ,rust-log-0.4)
                      ("rust-owo-colors" ,rust-owo-colors-3)
                      ("rust-supports-color" ,rust-supports-color-1))
      #:cargo-development-inputs (("rust-tempfile" ,rust-tempfile-3))))
   (home-page "https://github.com/guppy-rs/guppy")
   (synopsis
    "Manage workspace-hack packages to speed up builds in large workspaces")
   (description
    "This package provides Manage workspace-hack packages to speed up builds in large workspaces.")
   (license (list license:expat license:asl2.0))))
