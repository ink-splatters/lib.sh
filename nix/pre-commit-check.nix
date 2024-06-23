{
  pkgs,
  git-hooks,
  system,
  ...
}:
git-hooks.lib.${system}.run {
  src = ../.;

  hooks = {
    deadnix.enable = true;
    markdownlint.enable = true;
    nil.enable = true;
    nixfmt = {
      package = pkgs.nixfmt-rfc-style;
      enable = true;
    };
    statix.enable = true;
    shellcheck.enable = true;
    shfmt.enable = true;
  };

  tools = pkgs;
}
