# src

All "core" `styx` crates belong here, and should depend on no other crates in the project
(except for crates in the `generated` folder).

## Notes

As dependency tree require, implement crates in the following manner:

| crate name | purpose |
|------------|---------|
| `<root-name>-type` | generic impls, traits, and consts/helpers applicable to the specific crate, houses the types that consumers need, |
| `<root-name>` | concrete implementation / "business logic implmementation", Provides the implementation |
| `<root-name>-client` | a client implementation that connects to a service connected to the main type of the package of the same name |
| `<root-name>-mock` | Mock impl of core types in the package, only to be used as a dev dependency for testing |

"Why the `*-mock` crates?": <https://github.com/rust-lang/cargo/issues/8379>

## Dependency Graph Invariants

(rules that must be followed)

- `<package-slug>-type` crates can only depend on upstream packages
- `<package-slug>-error(s)` crate(s) can only depend on `*-type` crates
- `<package-slug>-trait` crates can depend on `*-error` and `*-type` crates
- `<package-slug>` crates can depend on all of the above
- `<package-slug>-client` crates can depend on all of the above
- `<package-slug>-mock` crates can depend on all of the above
- `<package-slug>-service` crates can depend on all of the above

However, that are (naturally) exceptions:

- `styx-sync` is a leaf crate, anything can import it
- `styx-util` is a leaf crate, anything can import it
- `styx-macros` is a WIP, and we need to figure out a plan for it, so be ready for
  the occasional suprise
- `styx-arch-utils` is a crate that provides useful architecture-specific
  utility functionality (e.g. reset values and routines _not_ specific to a
  particular processor, etc.). It imports from the other core crates. This
  crate is only to be used by processors.

Not every crate requires all of the additional slugs (obviously), otherwise
we'd be writing java. Jokes aside they really are not alwasy needed, but as the
needs arise, this document served to provide a mechanism of expansion.

## Using these crates

Basically eveything above this section is really only needed for doing dev in
"styx core." All `<package-slug>` crates should import everything "under" the
main crate (eg. the `*-type`, `*-trait`, and `*-error` crates when applicable).
If all the core crates do this, then all consumers will never have to experience
anything other than a nice clean import interface. There should be a best-effort
made to plop the imported typed into the proper namespace etc., a lot of times
plopping the inner crates straight into the root of the `<package-slug>` is not
the move.
