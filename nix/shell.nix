{ pkgs, pre-commit-check, ... }:
with pkgs;
mkShell.override { stdenv = stdenvNoCC; } {

  name = "shell";
  src = ../.;

  shellHook = pre-commit-check.shellHook + ''
    export PS1="\n\[\033[01;36m\]‹lib.shell› \\$ \[\033[00m\]"
    echo -e "\nto install pre-commit hooks:\n\x1b[1;37mnix develop .#install-hooks\x1b[00m"
  '';
}
