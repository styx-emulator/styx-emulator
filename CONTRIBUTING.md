# Contributing

Thanks for your interest in `styx`!

If you're ever unsure or get stuck trying to make something work feel free to
post a question to the repo's github `discussions`.

## Issues, Bug Reports, and Features

Before starting work on a feature, it'd be good to coordinate with the maintainers
to make sure that:

- What you want to do is possible
- What you want to do is not already done
- What you want to do should not wait for some other feature to land that would
  invalidate your work or make it have to be immediately re-written

additionally they can then provide a helpful hint or two to make sure you're
pointed in the right direction.

## Filing a bug report

Please file bug reports as you see them. If `styx` crashes and you can reproduce it,
please rerun with `RUST_BACKTRACE=full` and attach it, if you can link us where
in the code is crashing, even better!

## Issues or Feature Requests

If something is more clunky than you would like, or is missing functionality that you
would like, please let us know. Additionally if there is already an issue for it
please comment +1 on the issue so we can track interest in things and adjust priority.

### Project Issue Labeling and Organization

Once a feature is selected for implementation, define sub-tasks for the feature as checkboxes
in the issue description. Generally the feature should be scoped to be reviewable as one pull request.
If the feature is sufficiently large and warrants multiple self-contained pull requests, capture those
tasks as separate issues and apply an approriate Area (A-*) label to group the issues together.
Our system of labeling issues is inspired by [Bevy's](https://bevy.org/learn/contribute/reference/triage/) Triaging methods.

## Code Contributions

### General Contribution Workflow

Styx uses a `rebase` workflow. This is a middle ground between a proper merge based workflow,
and the usual insanity that ensues unless the maintenance team has the bandwidth to enforce
proper hygiene. The Styx team is currently small, so we use a `rebase` workflow.

The rough steps:

- Check for open Issues related to your intended contribution. Submit an issue to capture your idea or claim an issue that "Needs Help"
- If your new feature warrants a larger discussion, submit a `Request For Comment` in the [rfc repository](https://github.com/styx-emulator/rfcs)
- If all signs point to go, fork this repository.
- Add this repository as an upstream remote `git remote add upstream https://github.com/styx-emulator/styx-emulator.git`
- Create a branch off of the `main` (or your target) branch
- Commit your changes
- Get the latest changes `git fetch upstream`
- Rebase onto the target branch (eg. `main`) `git rebase upstream/main`
- See something like [this](https://www.atlassian.com/git/tutorials/rewriting-history/git-rebase) for help on the rebase process.
- When rebase is complete, push to your forked repository with `git push origin --force-with-lease`
  - **NOTE**: all the commits will be present when merged into the `main` branch, so please rebase your commits into a somewhat tidy set of commits following the conventional commit format discussed in `CONVENTIONS.md`
- Once you're ready for feedback, submit a pull request and request a review from a Maintainer!

If you're consistently working on Styx and would like to become a Comitter/Maintainer of the Repo (_nasty forkses_), [apply](#Becoming-a-Committer/Maintainer) to become part of the core Styx team!

**Some Advice**:

- An easy workflow is to commit for each small change with a message that tells you which commit to squash it into later, and `git rebase -i` to `fixup` those commits into a source commit later, this makes the git history significantly cleaner. A workflow like [this](https://andrewlock.net/smoother-rebases-with-auto-squashing-git-commits/) is a smooth path for development.
- Additionally, [jj](https://jj-vcs.github.io/jj/latest/) is a new tool whose ideal workflow is exactly compatible with the reccommended development workflow and is an honorable mention to try out at your leisure

### Incubation

In order to provide less friction getting **something** working and in the source
tree, we have an `./incubation` directory where various tools and utilities are
housed. Because a lot of the `styx-trace` data pipeline processing structure is in
flux the majority of those `incubation` members have to do with `styx-trace`.

If you have a cool idea, extra tool etc that doesn't currently have a place,
`incubation` is your friend.

### git hooks

#### pre-commit

By default you should have the `pre-commit` hooks setup (running `pip install pre-commit && pre-commit install`). This will locally check the main lint step in CI.

#### pre-push

If your organization has `pre-push` "safety" checks to ensure you don't push certain things, you can take advantage of our pre-packaged hook.

On a posix-ish system run `./util/etc/git/pre-push`, and it will install the git hook for you. The pre-push hook is controlled by the following environment variables:

- `STYX_DIRTY_WORDS`:
  - Settable by `.local.env`, automatically picked up by `direnv`
  - Comma delimited list
- `STYX_PRE_PUSH_BYPASS`:
  - Pushes code even when the pre-push check fails
  - If this var is set it will ignore any dirty word violations
- `STYX_PRE_PUSH_DEBUG`:
  - Extremely verbose logging of the pre-push checks
  - If this var is set it will emit debug logs

### Remote Development Containers

VSCode users can chose to develop within a development container based off of
the [CI Dockerfile](./util/docker/ci.Dockerfile) through the remote development
container system.  A container definition preconfigured for Styx is stored in
[.devcontainer.json](.devcontainer.json).  When the folder is opened in the
container, the proper dependencies will be installed, and Styx can be
interacted with via the VSCode terminal, or externally through normal
docker commands ex. `docker exec -it <container> /bin/bash`.  Styx is
mounted at `/workspaces/styx-emulator` within the container.

Note that using the remote development container will overwrite the local
`venv/` directory.

![image](https://code.visualstudio.com/assets/docs/devcontainers/create-dev-container/container-edit-loop.png)

#### To open Styx in the dev container

F1 -> Open Folder in Container (select Styx root director)

#### To reopen Styx locally

F1 -> Reopen Folder Locallly

See VSCode's
[docs](https://code.visualstudio.com/docs/devcontainers/create-dev-container)
for more in-depth information.

### Development Workflow

We use `rebase` commits with `ff-only`. Once a Pull Request has been submitted, a
maintainer needs to checkoff on it to run the CI. Feel free to push code **often**, and ping a
maintainer to kickstart a CI test when you're ready, note that you can run CI on
your local machine by building the CI container and running to top level scripts
that CI would run (eg. `pre-commit run -a`, `just test` etc.).

To have the branch in a state acceptable to CI, run the
[`pre-commit`](https://pre-commit.com/) checks first. After running `just setup`
you should have a virtualenv with `pre-commit` already installed, so after sourcing
the venv a la `source ./venv/bin/activate` you can `pre-commit install`,
which will run code formatters and linters on every commit.

Note that the `pre-commit` checks really only matter when it comes time to merge,
so if want to save state in a manner that will annoy `pre-commit` then you can
`pre-commit uninstall` etc. to not run the checks on that commit, then squash or
rebase your commits away.

The `pre-commit` hooks can be run manually with `pre-commit run -a`.

### Running Tests

The general test suite can be run by invoking `just test` from anywhere in the
source-tree, this will run `cargo nextest` on the codebase, and then run all
the doctests. You can always run `cargo test/nextest` etc. to only test the
local crate.

In addition to the above tests the CI will also run:

```bash
just asan
just miri
```

## Code Review / Guidelines

This is roughly the mental calulus that is performed while performing code reviews, it's useful to write it down so that contributors and maintiners are roughly on the same page.

### 1. Code Style

- **Adherence to Standards**: Verify if the code adheres to standard practices and the project's specific style, see [./CONVENTIONS.md](./CONVENTIONS.md) for more information.
- **Pre-commit Hooks**: Ensure pre-commit hooks are correctly set up and functioning to catch style issues, formatting discrepancies, and other potential problems before submission.
- **Readability**: Check if the code is readable and understandable, with consistent naming conventions and documentation.

### 2. Designing for Code Maintainability

- **Modularity**: Ensure the code is modular, with clear separation of concerns to facilitate easier updates and modifications (separation between struct / module / crate).
- **Reusability**: Look for opportunities to reduce duplication through reusable components or functions, the codebase is ever evolving and its too much for everyone to be on the same page all the time.
- **Refactoring**: Identify areas where the code could be refactored to improve clarity, reduce complexity, or enhance performance (though in general its better to get something working, then make a profiling harness for it and trim down the performance issues).

### 3. Requirements

- **Completeness**: Verify that the submitted code meets all the outlined requirements, goals, and non-goals.
- **Validation**: Ensure there's a mechanism in place to validate inputs and configurations against the requirements (tests, and tests with _real_ workloads and/or inputs).

### 4. Documentation and Comments

- **Updates**: Verify that any new APIs or changes to existing APIs are well-documented, including examples of requests and responses.
- **Clarity**: Ensure that comments and documentation clearly explain the purpose of the code, its logic, and any non-obvious behaviors or edge cases.
- **Up-to-Date**: Check that all comments and documentation are up-to-date with the current codebase, especially after changes or refactoring.

### 5. Testability

- **Unit Tests**: Confirm that there are comprehensive unit tests covering various cases, including edge cases and error conditions, feel free to add extra [kani](https://model-checking.github.io/kani/), [bolero](https://camshaft.github.io/bolero/) or [shuttle](https://github.com/awslabs/shuttle) harnesses at will.
- **Integration Tests**: Ensure there are integration tests that validate the interactions between components or systems.
- **Test Coverage**: Validate new features + api surface has realistic test coverage, and ensure that happy paths as well as edge cases are handled.

### 6. Error Handling

- **Graceful**: Verify that the code handles errors gracefully, providing meaningful error messages without exposing sensitive information.
- **Consistency**: Ensure error handling is consistent across the codebase, using standardized approaches for logging, exceptions, and user feedback, see [./CONVENTIONS.md](./CONVENTIONS.md) for more information.

### 7. Logging

- **Appropriate Level**: Check that logging is implemented at appropriate levels (debug, info, warning, error) to provide clear insights without overwhelming the logs.
- **Useful Context**: Ensure logs contain useful context for debugging, including identifiers, error messages, and relevant state information.

### 8. Performance

- **Efficiency**: Look for any inefficient code patterns that could impact performance, such as runtime hooks, excessive memory usage/resource contention, or unoptimized algorithms. If the default target runtime is getting modified, be sure to test the code on representative + _real_ workloads that would be affected by this change.
- **Profiling**: Recommend profiling critical sections of the code to identify and address performance bottlenecks. This is especially important in core changes or updates to an instruction execution backend.

### General Tips for Maintainers

- **Iterative Improvement**: Encourage iterative improvements rather than demanding perfection in a single review cycle, balancing thoroughness with the need to make progress. If quality is not up to standards but the functionality is there, make sure that gets communicated so it doesn't seem like the merge criteria keep changing. A positive "you did a good job implementing ___, now we just need to clean up the code + docs to get this merged in" goes a long way to validating contributions.
- **Communication**: Foster clear and constructive communication, providing specific examples and suggestions for improvement, if you have a hard time articulating your thoughts, that is something you are allowed to admit, and can request assistance with.
- **Empathy**: Remember that code reviews are not just about the code but also about the people writing it. Approach reviews with empathy and a focus on mentorship and growth, please remember to explain _why_ decisions are made and _how_ conclusions were reached.

## Becoming a Committer/Maintainer

Thanks for your interest in Styx! This repo and project infrastructure is managed by Kudu Dynamics LLC, a Leidos Company.
To apply to become a Committer/Maintainer, please email <info@styx-emulator.org>

### Maintainer List

- @yurboirene (active)
- @kudu-emilie (active)
