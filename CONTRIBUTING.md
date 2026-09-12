# contributing

thanks for wanting to help out. here's how to get started.

## getting started

1. fork the repo
2. clone your fork
3. create a branch (`git checkout -b feat/my-feature`)
4. make your changes
5. commit and push
6. open a pull request

## development

requires [just](https://github.com/casey/just) and go 1.22+.

```bash
# build for current platform
just build

# run
just run

# clean
just clean
```

## code style

- keep it chill
- lowercase commit messages, no periods, short descriptions
- follow existing patterns in the codebase
- no comments unless they're genuinely necessary

## pull requests

- keep PRs focused on one thing
- describe what changed and why
- make sure it builds (`just build`)
- add tests if you're adding functionality

## issues

- check existing issues first
- include steps to reproduce
- include your os, go version, and prowl version

## license

by contributing, you agree your code is licensed under MIT.
