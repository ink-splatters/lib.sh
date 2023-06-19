## lib.sh

Opinionated POSIX shell utils and aliases, for Apple operating systems.

### [Origins](ORIGINS.md)

### Documentation

There is no explicit documentation, but it should not be hard to make sense of it by reading the code.

### Installing

#### macOS

##### User shell

Just `source` lib.sh from `.zshrc`

As `flel` is alias for editing `lib.sh` code itself, there are those two I use
along with it, to edit / reload `.zshrc`

```shell
cd ~
git clone https://github.com/ink-splatters/lib.sh
cat <<'EOF' >> ~/.zshrc

source "$HOME"/lib.sh/lib.sh

alias fle='vi ~/.zshrc`
alias fs='source ~/.zshrc'
EOF
```

##### Root shell

```shell
cat <<'EOF' >> /var/root/.profile
source /Users/<username>/lib.sh/lib.sh

alias fle='vi ~/.profile'
alias fs='source ~/.profile'
EOF
```

#### RecoveryOS

```
-bash-3.2# diskutil mount /Volumes/Data # or `diskutil apfs unlock Data` if applicabl
-bash-3.2# source /Volumes/Data/Users/<username>/lib.sh/lib.sh
```

it will bootstrap itself the way it survives between interactive shell sessions (it however doesn't
survive reboots).
As well as, aliases: `fle`, `flel` and `fs` described above become available automatically, upon `source`-ing lib.sh

#### Status

Never will be explicitly released. Contains code potentially able to destroy things in a very bad way, if used wrong / due to  potential bugs.
Users are encouraged to fork and test a _particular commit_, on systems they don't use for production workloads.

Otherwise - can be perceived as alpha quality. Works for author's purpose.

#### Contributions

##### My discretion

The project was not intented for public eyes initially, rather I could not keep it with myself and just had to share with the community. Given it's part of my current
workflows, I leave my right to decline your PR without a reason. Thus, open an issue first, please.

##### pre-commit

`pre-commit` is used for formatting purposes, as well as for bumping `lib.sh` version. Contributors are expected to run it before submitting a PR.

Before running, it should be initialized by executing the following in the project dir:

```shell
pre-commit install --install-hooks
```
