;; SPDX-License-Identifier: BSD-2-Clause
(define-module (styx-deps cargo-valgrind)
  #:use-module (guix)
  #:use-module (guix build-system cargo)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages crates-io)
  #:use-module (guix git-download)
  )

(define-public rust-cargo-valgrind
  (package
   (name "rust-cargo-valgrind")
   (version "2.2.1")
   (source
    (origin
     (method url-fetch)
     (uri (crate-uri "cargo-valgrind" version))
     (file-name (string-append name "-" version ".tar.gz"))
     (sha256
      (base32 "12y657120hkczs5rvyjzgiz8j2jc9cfpb3vi60fh3vp3cfpw35v0"))))
   (build-system cargo-build-system)
   (arguments
    `(#:cargo-inputs (("rust-bytesize" ,rust-bytesize-1)
                      ("rust-colored" ,rust-colored-1)
                      ("rust-serde" ,rust-serde-1)
                      ("rust-serde-xml-rs" ,rust-serde-xml-rs-0.5)
                      ("rust-textwrap" ,rust-textwrap-0.14))
      #:cargo-development-inputs (("rust-assert-cmd" ,rust-assert-cmd-2)
                                  ("rust-predicates" ,rust-predicates-2))))
   (home-page "https://github.com/jfrimmel/cargo-valgrind")
   (synopsis "cargo subcommand for running valgrind")
   (description
    "This package provides a cargo subcommand for running valgrind.")
   (license (list license:expat license:asl2.0))))
