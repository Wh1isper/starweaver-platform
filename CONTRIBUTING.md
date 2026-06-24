# Contributing

This repository is in early service-boundary design. Keep changes focused and
prefer small, reviewable patches.

Before opening a pull request, run:

```bash
make ci
```

Use English for code, documentation, commit messages, and file names. Keep
architecture decisions in `spec/` and user-facing documentation in `docs/`.

Do not introduce service framework, storage, queue, or cloud dependencies until
the owning crate, operational boundary, and validation path are clear.
