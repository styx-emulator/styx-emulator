;; SPDX-License-Identifier: BSD-2-Clause
(define-module (styx-emulator-package deps guile)
  #:use-module (guix)
  #:use-module (guix git-download)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix build-system guile)
  #:use-module (gnu packages)
  #:use-module (gnu packages guile)
  #:use-module (gnu packages pkg-config))

(define-public guile-toml
  (package
   (name "guile-toml")
   (version "0.1-src")
   (source
    (git-download "https://git.solarpunk.moe/TakeV/guile-toml"))
   (arguments
    (list #:phases
          #~(modify-phases %standard-phases
                           (add-after 'unpack 'remove-guix
                                      (lambda _
                                        (begin
                                          (delete-file "guix.scm")
                                          (delete-file ".guix/modules/guix-toml.scm")))))))
   (build-system guile-build-system)
   (native-inputs
    (list pkg-config guile-3.0 guile-json-4))
   (propagated-inputs
    (list guile-json-4))
   (synopsis "")
   (description "")
   (home-page "")
   (license license:gpl3+)
   ))
