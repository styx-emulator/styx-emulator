# Upstream Issue Tracking

All issues should follow the same format

```text
- [local issue #]
  - upstream issues
    - [issue repo]#[issue number]
      - url: <url>
  - locations
    - [local-crate][more specific location if applicable]
  - description
    - description of upstream issue(s)
```

## Issue List

- #TBD
  - upstream issues
    - rust-lang-rust#32104
    - url: <https://github.com/rust-lang/rust/issues/32104>
  - locations
    - styx-kinetis21-processor
    - styx-powerquicci-processor
  - description
    - rustdoc cannot embed images, to display some cpu documentation
        we use this crate to embed the pictures base64 into the docs
