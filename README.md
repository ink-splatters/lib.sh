# lib.sh

Opinionated Apple-specific utils and aliases for bash and zsh. Fishes swim by!

## Status

`lib.sh` will never be released. You are strictly encouraged to read the LICENSE. By
using this software you are acknowledging and accepting the accompanying risks.

Consider the current `master` safe, with caution. Always know what you run!

## [Origins](ORIGINS.md)

## Installing

### macOS

```sh
#!/usr/bin/env bash

set -e

rc=~/$([[ "${SHELL##*.}" =~ .*bash$ ]] && echo .bashrc || echo .zshrc)

git clone https://github.com/ink-splatters/lib.sh "$HOME"/lib.sh

touch $rc

cat <<EOF >> $rc
source "$HOME"/lib.sh/lib.sh

alias fle='vi $rc'
alias fs='source $rc'
# alias flp='source ~/.profile'
# alias flbp='source ~/.bash_profile'
EOF

source $rc
```

#### Root shell

```shell
cat <<'EOF' >> /var/root/.profile
source /Users/<username>/lib.sh/lib.sh

alias fle='vi ~/.profile'
alias fs='source ~/.profile'
EOF
```

### RecoveryOS

As `RecoveryOS` was initially the first citizen:

`source` it and lib.sh will bootstrap itself properly, the way it survives between interactive shell sessions (it however doesn't
survive reboots).

As well as, aliases: `fle`, `flel` and `fs` described above become available automatically, upon `source`-ing lib.sh

## Misc

`pre-commit` is used for formatting purposes, as well as for bumping `lib.sh` version. Contributors are expected to run it before submitting a PR.

Before running, it should be initialized by executing the following in the project dir:

```shell
pre-commit install --install-hooks
```

`lib.sh` uses a lot of external cli tools. In order to get the best experience, you will want to inspect the code and install all the tools used.

## Contributions

Currently it's a whole mess craving for refactoring or rewriting. It's not that contributions are not welcome, but rather please
open an issue first.

_PR with the list of tools used in the form of markdown, is welcome :)_
