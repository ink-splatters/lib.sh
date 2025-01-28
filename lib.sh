LIBSH_VERSION=20250128_94d3926
export LIBSH_VERSION
cat <<EOF
		       lib.sh v$LIBSH_VERSION
Initializing...

EOF

# TODO:
# - shellcheck
# - shellharden

# crucial for the things like `for f in ./**/*.ext ; do...`
shopt -s globstar
set -o pipefail

# helpers

_alias() {
    local name="$1"
    shift
    args=("$@")
    alias $name="${args[*]}"
}
_salias() {
    local name="$1"
    shift
    args=("$@")
    alias $name="sudo ${args[*]}"
}

_exec() {
    # doesn't work in RecoveryOS because there is bash-3.2
    # mapfile -t x < <(echo "$@")
    echo -- "$@"
    "$@"
}

_sexec() {
    echo -- "sudo $@"
    sudo "$@"
}

_require() {
    for f in "$@"; do
        if ! command -v "$f" 1>/dev/null; then
            echo ERROR: "$f" is not in PATH
            return 1
        fi
    done
}

# loops over arguments after --
# prepends arguments before -- every call
_foreach() {

    local cmd_rdy=0
    local cmd=()

    for x in "$@"; do
        if [ "$x" == "--" ]; then
            cmd_rdy=1
            continue
        elif [ "$cmd_rdy" = 0 ]; then
            cmd+=("$x")
        else
            ${cmd[*]} "$x"
        fi
    done

}

_curl_get() {
    if command -v xh >/dev/null 2>&1; then
        xh "$@"
    else
        curl "$@"
    fi
}

# self
getself() {
    local exp='local self="${BASH_SOURCE[0]:-${(%):-%x}}"'
    eval "$(echo $exp)"

    if [[ $(echo "$self" | grep -Eo '^[/]') == "" ]]; then
        >&2 echo -- failed getting self using BASH_SOURCE ';' using pwd...
        local self="$(pwd)/$self"
    fi

    echo "$self"
}

getselfdir() {
    local selfdir="$(dirname "$(getself)")"
    echo "$selfdir"
}

getdatadir() {
    local data="$(echo "$(getself)" | sed -E 's/(^\/Volumes\/[^/]+)\/.+$/\1/g')"
    echo "$data"
}

gethome() {
    if [ $# -lt 1 ]; then
        cat <<'EOF'
Usage: gethome <uid>
EOF
        return 1
    fi

    if [ "$__OSINSTALL_ENVIRONMENT" == 1 ]; then
        local _dscl=(dscl -plist -f "$(getdatadir)"/private/var/db/dslocal/nodes/Default localonly)
        local users=/Local/Target/Users
    else
        local _dscl=(dscl -plist .)
        local users=/Users
    fi
    local uid=$1

    local user=$(${_dscl[@]} -search $users UniqueID "$uid" | grep -Eo '^[a-z0-9_]+')
    /usr/libexec/PlistBuddy -c "print :dsAttrTypeStandard\:NFSHomeDirectory:0" /dev/stdin <<<$(
        ${_dscl[@]} -read "$users/$user" NFSHomeDirectory
    )
}

# sudo / system

_salias s
_salias si -i
_salias enx vi /etc/nix/nix.conf
alias xx='exit'
alias q=xx

# tr & clipboard

alias td='tr -d'
alias tdn="tr -d '\n'"
alias tn=tdn
alias c=pbcopy
alias p=pbpaste

function cr() {
    local in
    cat $in
    echo
}

# xattrs and related
alias x=xargs

alias xn='x -n'
alias x1='x -n1'
alias x2='x -n2'
alias xi='x -I@'
alias xj='x -J%'
alias xni='xi -n'
alias xnj='xj -n'
alias x1i='x1 -I@'
alias x1j='x1 -J'
alias x2i='x2 -I@'
alias x2j='x2 -J'

alias xpp="xargs -n1 -I@ -R -1 sh -c 'echo @ ; echo ; /usr/libexec/PlistBuddy -c print @'"
alias xfetch="ls | xargs -n1 -I@ -R -1 sh -c 'pushd @ ; git fetch -vp ; popd'"

# uuid retrieval and generation
alias uuid=uuidgen
alias ugen="uuid | tn"
alias u0='printf "%s" 00000000-0000-0000-0000-000000000000'

# case
alias upper='tr "[[:lower:]]" "[[:upper:]]"'
alias up=upper

alias lower='tr "[[:upper:]]" "[[:lower:]]"'
alias low=lower

# status / system info
alias mf=macchina
alias bf=bunnyfetch
alias info=mf  # big info
alias sinfo=bf # small info

# generation using /dev/random

rand() {
    if [[ $# == 0 ]]; then
        cat <<EOF
the util takes <count> bytes from /dev/random and outputs lower-case hex values

usage: rand <count> [-f] [-n]

<count>         byte count
-f, --force     if count > 64, the flag is required
-n, --newline   if specified, '\n' is added after the output

example: to get 256 bit nonce use: $(rand 32)

EOF
        return 1
    fi

    local f=0
    local n=0

    local count=$1
    shift
    ((count == 0)) \
        && echo "ERROR: invalid value: $count" \
        && return 1

    while [[ $1 != "" ]]; do
        case $1 in
            -f | --force)
                f=1
                ;;

            -n | --newline)
                n=1
                ;;

        esac
        shift
    done

    ((count > 64)) && ((f != 1)) \
        && echo 'for count > 64 use -f' \
        && return 1

    dd if=/dev/random bs=1 count=$count 2>/dev/null | xxd -p | tn

    ((n == 1)) && echo
}

function randpass() {
    if [[ $1 == "--help" || $1 == "-h" ]]; then
        cat <<EOF
generates random password
usage: randpass [length]
default length is 16

<count>		symbol count
EOF
        exit 1
    fi

    if ! command -v python >/dev/null 2>&1; then
        echo ERROR: python not found
        exit 1
    fi

    local length="${1:-16}"

    cat <<EOF | python
import string
import secrets

def choice( abc: str, len: int):
	return (secrets.choice(abc) for x in range(len) )

def choicel( abc: str, len: int) -> list[str]:
	return list(choice(abc,len))

print(''.join(
	choice(
		choicel( string.ascii_letters, $((length / 2)) ) +
		choicel( string.punctuation, $((length / 2)) ),
		$((length))

	)

))


EOF

}

# system process management

alias pg='pgrep -i'

_salias k kill
_salias kall killall

alias k9='k -9'
alias kstop='k -SIGSTOP'
alias kcont='k -SIGCONT'

pk() { pg "$1" | x kill -9; }

alias t=btop

_salias bw bandwhich --show-dns

_salias sc sysctl
alias sw='sc -w'

_salias santa santactl

# opendirectory
_salias ds dsconfigad
_salias dsc dscacheutil
_salias sctl sysadminctl

# networking

_salias n nextdns
alias na='n activate'
alias nd='n deactivate'
alias ni='n install'
alias nl='nslookup'
alias nr='n restart'
alias ns='n status'
alias nun='n uninstall'
alias ncw='n config wizard'
alias m=mullvad

alias mc='m connect ; m status'
alias mdis='m disconnect ; m status'
alias mr='echo Reconnecting... ; m reconnect ; m status'
alias mvpn='m lockdown-mode set'
alias isnet='nl google.com && ping google.com'
alias pig=isnet

_salias ap /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
_salias apd /usr/libexec/airportd

# use always native ifconfig for the purpose of lib.sh!
_salias ifc /sbin/ifconfig

_salias utm /Applications/UTM.app/Contents/MacOS/utmctl

alias won="apd setpower on"
alias woff="apd setpower off"
alias wup="ifc en0 up"
alias wdown="ifc en0 down"
alias wassoc="apd assoc --ssid"

_salias rt route

# draft
rewifi() {
    set +e
    set -x

    mvpn off || true
    mdis || true
    nd || true
    nun || true
    sleep 1

    rt -n flush
    dsc -flushcache
    kall -m HUP mDNSResponder

    sleep 1

    na || true
    nia || true
    mc || true
    sleep 1
    mc || true
    nr || true
    sleep 1

    mvpn on || true

    set +x
    set -e

    echo Done
}

wchan() {
    if [ $1 != "" ]; then
        wdown
        echo -setting channel to: $1
        ap -c=$1
        sleep 1
    else
        ap -c
    fi
}
alias wscan='ap -s'
alias wi='ap -I'
alias winfo=wi
_salias ng ngrep
alias ng0='ng -d en0'

if0() {

    local interface=en0

    if [ "$1" != "" ]; then
        interface="$1"
    fi

    ifc $interface | grep ether | grep -Eo ' [0-9a-f:]+' | tr -d ' \t'

}

randmac() {

    if (($# > 1)); then
        cat <<'EOF'
Temporary changes network interface mac address. This does not survice a reboot.

usage: randmac [<interface>]

[<interface>]   optionally specified interace for the mac address to be set on
EOF
        return 1
    fi

    local interface=en0

    if [ "$1" != "" ]; then
        interface="$1"
    fi

    ap -z
    local mac=$(rand 6 | sed -E 's/([0-9a-f]{2})/:\1/g' | sed 's/^://g')

    echo -- "generated value: $mac; attempting to set..."
    ifc $interface ether "$mac"
    (($? == 0)) && mac && echo done.
}

alias ms='m status'

# mullvad status with increasing verbosity

# TODO: get local network status

_status_dns() {
    printf "\t"
    m dns get | grep Custom
}

_status_always_req() {

    printf "\t"
    m lockdown-mode get

}
_mss() {

    echo
    printf "Mullvad status:\n\t"
    ms
}

mss() {
    _mss
    _status_dns
    _status_always_req
}

msss() {
    _mss
    _status_always_req

    local dns="$(m dns get)"
    printf "\tDNS:\n"

    echo "$dns" | sed 's/ DNS//g' | sed 's/^/\t\t/g'

    printf "\tRelay info:\n\t\t%s\n" "$(m relay get | sed -E 's/^[^:]+: //g')"
}

function nets() {
    _exec networksetup "$@"

}
function dhinfo() {
    networksetup -getinfo "Wi-Fi" | rg --color=never '(^[^:]+$)|(^[^:]+:.+$)' --replace '$1    $2'
}

function netsocks() {
    nets -setsocksfirewallproxy "Wi-Fi" "$1" "$2"
}

alias dhi=dhinfo
alias ifc0=dhi

alias br=broot

alias pkg=pkgutil
alias pkgs='pkg --pkgs'
_salias pkgf pkgutil --forget
alias pkgd=pkgf
alias upkg=pkgf

# python

# pixi
alias px=pixi

alias pxlocenvcacheon='pixi config set experimental.use-environment-activation-cache true --local'
alias pxh='px help'

alias pxn='px init'
alias pxa='px a'
alias pxr='px rm'
alias pxi='px i'
alias pxx='px r'  # Run
alias pxxt='px x' # Run a command in a temporary environment
alias pxsh='px s' # Shell
alias pxl='px ls'
alias pxcgd='px clean cache -y' # a-la nix alias
alias pxtree='px t'             # tree

alias pxc='px config'
alias pxce='pxc edit'
alias pxcl='pxc list'
alias pxca='pxc append'
alias pxcp='pxc prepend'
alias pxcs='pxc set'
alias pxcu='pxc unset'

alias pxp='px project'
alias pxch='pxp channel'
alias pxcha='pxpch a'
alias pxcha='pxpch a'
alias pxchr='pxpch rm'
alias pxchl='pxpch ls'

alias pxd='pxp description'
alias pxdg='pxd get'
alias pxds='pxd set'

alias pxv='pxp version'
alias pxvg='pxv get'
alias pxver=pxvg
alias pxvs='pxv set'

alias pxe='pxp environment'
alias pxea='pxe a'
alias pxer='pxe rm'
alias pxel='pxe ls'

alias pxt='px task'
alias pxta='pxt a'
alias pxtr='pxt rm'
alias pxtl='pxt ls'
alias pxth='pxt help'

alias pxg='px g' # global
alias pxge='pxg edit'
alias pxga='pxg a'
alias pxgi='pxg i'
alias pxgr='pxg uninstall'
alias pxgrm='pxg rm'
alias pxgl='pxg ls'
alias pxgs='pxg s'  # sync
alias pxgex='pxg e' # expose
alias pxgu='pxg update'
alias pxgh='pxg help'

alias hch=hatch
alias ach=hch
alias tch=hch
alias pd=pdm

alias mm=mamba
alias um=micromamba
alias uma='um activate'
alias umd='um deactivate'
alias umc='um env create -n'
alias uml='um env list'
alias umll='um list'
alias umu='um update'
alias umua='umu -a'

umca() {
    umc "$1"
    uma "$1"
}

alias umi='um install'
alias umr='um remove'
alias umrm='um env remove -n'
alias ums='um search'

# venv / uv
alias _venv='python -m venv'
alias venv='uv venv -p $(which python)'

function venvwith() {
    local py="$(fd -u python"$1"\$ -t x ~/.rye)"

    if ! command -v "$py" >/dev/null 2>&1; then
        echo "not found (internal error)"
        return 1
    fi
    uv venv -p "$py"
}

alias _pip="python -m pip"
alias pip="uv pip"

# pip
#
alias pipi='pip install'
alias pipu='pipi -U'
alias pipe='pipi -e'
alias pipl='pip list'
alias pipr='pip uninstall'
alias piped='pipe .' #pipe + dot
alias pipuall="uv pip list --format=freeze | rg -o '^[^=]+' | x uv pip install -U"
#alias pi=pip
#alias px=pipx

function vc() {
    local name="${1:-.venv}"

    venv "$name"
}

function va() {
    local name="${1:-.venv}"

    source "$name"/bin/activate
}

alias vd='deactivate'

# editing / viewing

alias _vi=/usr/bin/vi

if [[ $EDITOR == "" ]]; then
    export EDITOR=vim
fi
alias vi="$EDITOR"
alias v=vi
alias virc='vi ~/.vimrc'
alias vrc=virc
alias ba=bat
alias batlog='bat --paging=never -l log'
alias blog=batlog
alias bathelp='bat -l help -p'
alias bhelp=bathelp
alias batdiff='bat -l diff'
alias bdiff=batdiff
alias ca=cat
alias lstream='log stream --color=always'
alias lshow='log show --color=always'

export MANPAGER="sh -c 'col -bx | bat -l man -p'"

_help() {
    "$@" -h | bhelp

}
_longhelp() {
    "$@" --help | bhelp

}

alias ?=_help
alias ??=_longhelp

alias e=echo

eseq() {
    echo $(seq $1)
}

# protonmail
alias pm='protonmail-bridge'

# kitty

# +kitten
alias kk='kitty +kitten'

#  themes
alias themes="kitty +kitten themes"
alias theme=themes # semtantic sugar in order to do like: `theme '3024 Day'`
alias th=theme
alias kt=theme

kcolors() {
    # prints kitty theme using pastel
    # https://www.grailbox.com/2021/12/displaying-your-kitty-theme-colors/

    local line

    while read line; do

        echo "$line" | grep -o "#[a-f0-9]\{6\}" | pastel color
    done <"${1:-/dev/stdin}"
}
alias kc=kcolors
alias kcc='kcolors ~/.config/kitty/current-theme.conf'

#  ssh
alias kssh='kitty +kitten ssh'
alias ks=kssh

#  diff
#    diff two files or dirs

alias kdiff='git difftool --no-symlinks --dir-diff'
alias kd=kdiff
alias kdtwo='kitty +kitten diff'

alias kdt=kdtwo
alias kd2=kdt

# TODO
# notify
# notify() {
#    terminal-notifier -title "Kitty" -message "Done with task! Exit status: $?" -activate net.kovidgoyal.kitty
# }

# launchctl & processes

function users() {

    local ulist=($(ps -ef | rg -o '^[\t ]+([\d]+)' | sort -u))
    if [ "$1" = "-u" ]; then
        echo "${ulist[*]}" | x -n1
    else
        local pat="pat=$(ps -ef | rg -o '^[\t ]+([\d]+)' | sort -u | x | rg '([^ ]+) ' --replace ' $1$|')"
        dscl . -list /Users UniqueID | rg "$pat"
    fi
}

alias lc='launchctl'
alias lcbo='lc bootout'
alias lcd='lc disable'
alias lce='lc enable'
alias lcbs='lc bootstrap'
alias lcbss='lcbs system'
alias lcbsu='lcbs user/501'
alias lcbsg='lcbs gui/501'
alias lck='lc kill'
alias lcks='lc kickstart -k'
alias lcds='lc dumpstate'

lcpd() {
    lc print-disabled "$1" | grep disabled | grep -Eo 'com.apple.[^"]+' | sort -u
}

alias lcpds='lcpd system'
alias lcpdu='lcpd user/501'

# plists
_pb=/usr/libexec/PlistBuddy
alias pb=$_pb
# ergonomics shortcut
function pl() {

    if ! command $_pb "$@" && [ $# -gt 0 ]; then
        cat <<'EOF'

lib.sh: pl is a new shortcut for PlistBuddy.
plutil should be called by its name
EOF
    fi

    $_pb $@

}
alias pp='pb -c print'

alias plc='/usr/bin/plutil -convert'
alias xml1='plc xml1'
alias bin1='plc binary1'

# file system

alias r='rsync -avhHS --delete'
alias rr='rsync -avhHS --delete --existing --ignore-existing'
alias rd='rsync -d --delete --existing --ignore-existing'

tree() {
    broot -c :pt "$@"
}

_salias lsregister /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister
alias lsreg=lsregister

# ls / eza
#
_alias ll ls -l
_alias la ll -a
_alias laa la -O@e
_alias l1 ls -1
_alias l1a l1 -a

_alias la1 l1a
_alias la2 laa

_alias ee eza
_alias el ee -l
_alias ea el -a
_alias eaa ea -@o

_alias e1 ee -1
_alias e1a e1 -a
_alias ea1 e1a

_alias ea2 eaa
_alias ea3 ea2 -F

alias dustpr='dust -prR'

alias statx='stat -f "%HT"'

# search

alias f='fd -uuu'
alias f1="f -d 1"
alias f2="f -d 2"
alias f2e="f --exact-depth 2"

function files() {
    local pattern=()

    for ext in "$@"; do
        pattern+=(-e "$ext")
    done

    fd "${pattern[@]}"
}

alias imgs="files jpeg jfif jpg jxl png tiff webp heic heif"
alias allimgs="imgs bmp icns ico tga"
alias xs="f -t x"
alias dmgs="files dmg"
alias zips="files zip"
alias zstds="files zst tz"
alias archives="files z dmg zip zst tz xz bz2 tar tgz tbz2 tz gzip"

function _f() {

    local n="$1"
    shift
    find . -name '*'"$n"'*' "$@"
}

function _fi() {

    local n="$1"
    shift
    find . -iname '*'"$n"'*' "$@"
}

function ff() {

    for f in "$@"; do
        _f "$f"
    done
}

function fif() {

    for f in "$@"; do
        _fi "$f"
    done
}

function fr() {

    for f in "$@"; do
        _f "$f" -exec rm -rf {} \;
    done
}

function fir() {

    for f in "$@"; do
        _fi "$f" -exec rm -rf {} \;
    done
}

alias _editto='ditto --rsrc --noqtn --extattr --preserveHFSCompression --persistRootless'
alias ecp='_editto --acl'
alias ecpnoacl='_editto --noacl'
alias editto=ecp
alias edittonoacl=ecpnoacl

_fdrm() {
    local nameflag="$1"
    local what="$2"
    shift 2

    find "$@" "$nameflag" "$what" -exec rm -rf {} \;

}

fdrm() {
    local what="$1"
    shift
    _fdrm -name "$what" "$@"
}

fdirm() {
    local what="$1"
    shift
    _fdrm -iname "$what" "$@"
}

cleandirs() {
    for d in "$@"; do rm -rf "$d"/* "$d"/.*; done

}
alias cld=cleandirs

alias o=open

# attrs

alias xd='xattr -d'
xdrecs() {
    local path="$1"
    local pdf="purgeable-drecs-fixed"

    if [[ $(ls -la@ | head -3 | grep -Eo "$pdf") == "" ]]; then
        echo ERROR: "$path" has no $pdf flag to clear
        return 1
    fi

    local flags="$(ls -laO | head -2 | grep -Eo 'uchg|schg' | xargs | sed 's/ /,/g')"
    local noflags="$(echo $flags | sed -E 's/([a-z]+)/no\1/g')"

    if [[ $noflags != "" ]]; then
        set -x
        sudo chflags "$noflags" "$path"
        set +x
    fi

    set -x
    sudo xattr -d $pdf "$path"
    set +x

    if [[ $flags != "" ]]; then
        set -x
        sudo chflags "$flags" "$path"
        set +x
    fi

    echo
    echo "Done."
}

alias xdr=xdrecs

alias xsd='xattr -rsd'

_x() {

    local args="$1"
    local attr="$2"
    shift 2

    xattr $args $attr "$@" | grep -Eo ' com.+' | sort -u
}

xv() {
    local attr="$1"
    shift
    _x -rv $attr "$@"
}

xsv() {
    local attr="$1"
    shift
    _x -rsv $attr "$@"
}

# TODO:
# print xattrs using abbreviations, e.g.
# xsp q # echo com.apple.quarantine
# xsp q m # echo com.apple.{quarantine,macl}

# as it shadows legitimate app:
alias csv="$HOME"/.nix-profile/bin/xsv

# fs lockers

_salias _chflags /usr/bin/chflags

# Despite not to be inferred from names exactly, all the routines lock file system objects from
# further changes by both System and User.

# There are destructive and non-destructive versions of the routines.

# 1. destructive

# before locking, erases directories'  contents and lock those from further changes by both system or user.
# "softer" versions are still destructive!

fdirs() {
    for d in "$@"; do
        _chflags -R nouchg,noschg "$d" 2>/dev/null
        rm -rf "$d"
        mkdir -p "$d"
        _chflags uchg,schg "$d"
    done

}
# - "softer" version
# same but preserve original folders and its ownership, permissions, unrelated BSD flags and  xattrs
sfdirs() {
    for d in "$@"; do
        _chflags -R nouchg,noschg "$d" 2>/dev/null

        if [ ! -d "$d" ]; then mkdir "$d"; fi

        cleandirs 1>/dev/null "$d"
        _chflags uchg,schg "$d"
    done
}
alias sfd=sfdirs

ffiles() {
    for f in "$@"; do
        _chflags nouchg,noschg "$f" 2>/dev/null
        rm -f "$f"
        touch "$f"
        _chflags uchg,schg "$f"
    done
}
# - "softer" version
# same but preserve original files and its ownership, permissions, unrelated BSD flags and  xattrs
sffiles() {
    for f in "$@"; do
        _chflags nouchg,noschg "$f" 2>/dev/null
        truncate -s 0 "$f"
        _chflags uchg,schg "$f"
    done
}

alias sff=sffiles

# 2. non-destructive

alias lock='_chflags uchg,schg'
alias unlock='_chflags nouchg,noschg'

# recursive version
alias unlockr='_chflags -R nouchg,noschg'

# index

alias md=mdutil
alias mdx='mdutil -X'
alias mdoff='mdutil -i off -d'
alias mdoffa='md-off -a'
alias mdon='mdutil -i on -E'

if [ -n "${commands[fzf - share]}" ]; then
    source "$(fzf-share)/key-bindings.bash"
    source "$(fzf-share)/completion.bash"
fi

alias mkd=mkdir
alias mkp='mk -p'
alias rgu='rg -uuu'
alias rgi='rg -iuuu'

# TODO: mind that c is for pbcopy
# c() {
# 	if [[ $# -gt 1 ]] ; then echo error ; return ; fi
#	uutils-coreutils "$1"
# }

# new nix cli

# setting NIX_PATH this way allows to refer to `nixpkgs` inside
# as it would be channel (without actual `nixpkgs` channel set up)
# details: https://github.com/NixOS/nix/issues/7026#issue-1369924326
export NIX_PATH=nixpkgs=flake:nixpkgs

alias nx='nix --option extra-access-tokens "$GH_PAT"'

_nxv='--verbose --show-trace --print-build-logs'
_nxi='--impure'
_nxafc='--accept-flake-config'

alias enxc='vi ~/.config/nix/nix.conf'

alias nxconf='nx show-config'
alias nxc=nxconf
alias nxsh='nx shell'
alias nxs='nix-search'

alias nxb='nx build'
alias nxbi="nxb $_nxi"
alias nxba="nxb $_nxafc"
alias nxbia="nxbi $_nxafc"

alias nxbv="nxb $_nxv"
alias nxbvi="nxbv $_nxi"
alias nxbva="nxbv $_nxafc"
alias nxbvia="nxbvi $_nxafc"

alias nxd='nx develop'
alias nxda="nxd $_nxafc"
alias nxdi="nxd $_nxi"
alias nxdia="nxdi $_nxafc"

alias nxdv="nxd $_nxv"
alias nxdva="nxdv $_nxafc"
alias nxdvi="nxdv $_nxi"
alias nxdvia="nxdvi $_nxafc"

alias nxdrv='nx derivation'
nxdrvshow() {
    nxdrv show "$1" | jq
}

nxdrvpaths() {
    if [ ! $# ]; then
        cat <<EOF
Prints nix store "requisites" paths for specified derivation(s).
Useful when one needs to do fine-grained filtering (like for pushing to binary cache).

Usage: $0 <derivation...>
EOF
        return 1
    fi

    local outputs
    mapfile -t outputs < <(nix derivation show $* | jq -r '.[].outputs | .. | objects | select(has("path")) | .path')

    nix-store --query --requisites ${outputs[*]} | rg -v "$(echo "${outputs[@]}" | tr ' ' '|')"
}

alias nxds='nxdrv show | jq'
alias nxfmt='nx fmt'
alias nxf='nx flake'
alias nxfc='nxf check'
alias nxfl='nxf lock'
alias nxfm='nxf metadata'
alias nxfs='nxf show'
alias nxfu='nxf update'
alias nxfuc='nxfu --commit-lock-file'
alias nxrun='nx run'
alias nxfr=nxrun
alias nxi='nxp install'
alias nxia='nxi --accept-flake-config'
alias nxii='nxi --impure'
alias nxiia='nxii --accept-flake-config'
alias nxl='nxp list'
alias nxm=nxfm
alias nxmeta=nxfmeta
alias nxp='nx profile'
alias nxpl=nxl
alias nxpi=nxi
alias nxr='nxp remove'
alias nxpr=nxr

alias nxrepl='nx repl'

alias nxre='nx registry'
alias nxrea='nxre add'
alias nxrep='nxre pin'
alias nxrerm='nxre remove'

nxrepkgs() {

    nxrepl --file <(
        cat <<'EOF'
import <nixpkgs> {
  overlays = [
    (_:
      (prev:
	let
	  b = builtins;

	  inherit (prev.lib) lists;
	  l = lists;

	in rec {
	  inherit b l;
	  n = b.attrNames;
	  v = b.attrValues;
      }))
  ];
}
EOF
    )

}

alias nxreflake='nxrepl --expr "builtins.getFlake \"$PWD\""'

alias nxrel='nxre list'
alias nxreu='nxrel --refresh'
alias nxrelu=nxreu
alias nxu='nxp upgrade'
alias nxw='nxp wipe-history'

alias nxhash='nx hash'
alias nxh='nxhash'

nxhrand() {
    _require nix
    # branching to support Lix
    if [[ "$(nix --version)" =~ Lix ]]; then
        nxh to-sri --type sha256 $(rand 32) | tn
    else
        nxh convert --hash-algo sha256 $(rand 32) | tn
    fi
}
alias nxhr=nxhrand

alias xpkgs="xargs -n1 | sed -E 's/^/nixpkgs\./g'"

_i() { echo "$@" | xpkgs | xargs nix-env -iA; }
alias i=_i

alias ncg='nix-collect-garbage'
alias ncgd='ncg -d'

alias nso='nix store optimise'
alias nsmka='nix store make-content-addressed'
alias nsls='nix store ls'

nxrev() {
    local repo="${1:-nixpkgs}"
    local tag="${2:-nixpkgs-unstable}"

    nxfm "$repo/$tag" --json | jq -r '.locked.rev'
}
alias nixpkgs-unstable=nxrev
#alias rev-nixpkgs-unstable='nxrev nixpkgs-unstable'

alias nxtree='nix-tree'

# deprecated
# TODO: remove
#alias nu-legacy='nix-env --upgrade' # broken allegedly by nixpkgs' 8a5b9ee
#
## creates upggradeable list of packages as --attr parameters to nix-env --upgrade
#_nuattrs() {
#
#    nix-shell -p ripgrep --run sh < <(
#        cat <<'EOF'
#nix-env -q | rg -o '^([a-zA-Z-]+)[.-](?:[\d.-]+)*' --replace '--attr nixpkgs.$1' | sed -e 's/-i/I/g;s/-min/Min/g;s/nss-//g;s/-(wrapped|unstable)//g'
#EOF
#    )
#    return 0
#}
#
#_nu() {
#    _nuattrs $@ | xargs nix-env --upgrade
#
#}
#
#alias nu-attrs=_nuattrs
#alias nu='nix-env --upgrade'
#
#alias ncu='nix-channel --update'
#
#alias u='nix-env -e'
#alias q='nix-env -q'

# direnv / nix-direnv
alias renv=nix-direnv-reload

# filesystem

#  time machine snapshots

alias tm=tmutil
alias ts='tmutil localsnapshot'

tu() {
    local _del="tmutil deletelocalsnapshots"

    mount | grep -E '^/dev' | sed -E 's/\/dev.+on (.+) \(.*$/\1/g' | xargs -n1 $_del
    echo Unmounted volumes were unaffected.
}

# General APFS snapshots

# https://github.com/ahl/apfs
alias snap=snapUtil

# diskutil general

alias d='diskutil'
alias l='diskutil list'
alias di='d info'
alias dm='d mount'
dmm() {
    dm -mountPoint "$1" "$2"
}

alias dum='d umount'
alias dud='d umountDisk'
alias dr='d rename'
alias muw='mount -uw'
_salias eo diskutil enableOwnership

# apfs
_salias apfs.util /System/Library/Filesystems/apfs.fs/Contents/Resources/apfs.util
msnap() {
    if [[ $# < 3 || $1 == "-h" || $1 == "--help" ]]; then
        cat <<EOF
mount apfs snapshot

usage: ms <snapshot name> <device node> <mount point> [ ... mount options ]
EOF

        return 1
    fi

    local s=$1
    local d=$2
    local m="$3"
    shift 3

    local mopt=(-s $s "$@")

    if [ ! -d "$m" ]; then
        mkdir -p "$m"
        echo "-- mount point: $m created ( didn't exist )"
    fi

    mount_apfs ${mopt[*]} "$@" $d "$m"
}

msnaps() {
    local vol="${1:-disk3s1}"
    local mp="${2:-/tmp/s}"

    if [[ ! $vol =~ ^/dev ]]; then
        vol="/dev/$vol"
    fi

    local snap="$(als "$vol" | grep -Eo 'com.+')"

    msnap "$snap" "$vol" "$mp"

}

alias a='d apfs'
alias au='a unlock'
function aunom() {

    au "$1" -nomount
}
alias al='a lock'
alias alu='a listUsers'

ausr() { a listUsers "$1" | grep -Eo '[0-9A-F-]{36}' | head -1; }

alias alvg='a listVolumeGroups'
alias adelvg='a deleteVolumeGroup'
alias als='a listSnapshots'
alias adels='a deleteSnapshot'

xadels() {
    adels "$1" -xid "$2"
}

alias aav='a addVolume'

aavv() {
    local disk="$1"
    local name="$2"

    aav "$disk" APFS "$name"
}

alias adel='a deleteVolume'

aev() { a encryptVolume "$1" -user disk; }
adv() { a decryptVolume "$1" -user $(ausr "$1"); }

function aav() {
    if [[ $# -lt 2 ]]; then
        echo not enough args
        return
    fi
    a addVolume "$1" APFS "$2"
}

restore() {
    local _sudo=

    if ((EUID != 0)); then
        _sudo=sudo
    fi

    local src="$1"
    local tgt="$2"
    shift 2

    $_sudo asr restore -s "$src" -t "$tgt" -noprompt -noverify "$@"
}

srestore() {
    local src="$1"
    local tgt="$2"

    local snap="$3"

    shift 2

    if [ "$snap" = "" ]; then
        snap="$(als "$src" | grep -Eo 'com.+')"
    else
        shift
    fi

    restore "$src" "$tgt" --toSnapshot "$snap" "$@"
}

function duuid() {

    d info $1 | grep Volume\ UUID | grep -Eo '[0-9A-F-]{36}' | tn
}

function dname() {
    d info $1 | grep Volume\ Name | sed -E 's/^.*Volume Name:[ \t]+//g' | tn
}

# github

alias ghr='gh repo'
alias ghrf='ghr fork'
alias ghrsd='ghr set-default'

ghs() {
    if [[ $1 == "-h" || $1 == "--help" ]]; then
        cat <<'EOF'

performs GitHub fork synchronization with the source repo,
using github-cli (must be installed and authenticated).
also requires ripgrep and jq

usage: ghs [target remote]
EOF
        return 1
    fi

    if [ ! -d "$(pwd)"/.git ]; then
        echo ERROR: not a git repository
        return 1
    fi

    _require gh jq rg || return 1

    local remote="${1:-origin}"

    if [[ $(git remote | rg '^'$remote'$') == "" ]]; then
        echo ERROR: remote "$remote" does not exist
        return 1
    fi

    if ! command gh auth token >/dev/null 2>&1; then gh auth login; fi

    local target=$(git remote get-url $remote | sed 's/.git$//g' | rg -o 'github\.com.([-./\w]+)' --replace '$1')
    local source=$(gh api repos/$target | jq .source.full_name | tr -d '"')

    if [ "$source" == "null" ]; then
        echo "ERROR: the repo: $target is not a fork. Cannot sync"
        return 1
    fi
    echo From: "$source"
    echo To: "$target"
    gh repo sync $target --source $source
}

ghallrepos() {
    local user="${1:-ink-splatters}"
    gh api -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" /users/"$user"/repos --jq '.[].name' -X GET --paginate
}

refresharchive() {
    if [[ $1 == "-h" || $1 == "--help" ]]; then
        cat <<'EOF'

- searches for .tz (tar zstd) archives in the current directory
- unpacks them, for forks - syncs with sources (using GitHub cli)
- hard-resets to HEAD
- fetches changes
- pulls --ff-only
- cleans everything but .git folder
- rearchives back to .tz

requires fd.

usage: refresharchive [--no-gix]

--no-gix - do not use gitoxide for fetch, even if available

EOF
        return 1
    fi

    _require fd || return 1

    local git=git

    if [[ $1 != "--no-gix" ]] && command -v gix >/dev/null 2>&1; then
        git=gix
    fi

    for f in $(fd '.tar.zst|.tz'); do
        xzsta "$f"
        pushd "${f%.*}"
        ghs
        $git fetch
        git reset --hard HEAD
        git pull --ff-only
        fd -u -d 1 --exclude '.git' -x rm -rf
        popd
        zsta "${f%.*}"
    done
}
alias updatearchive=refresharchive

# git

alias g=git
alias gx=gix
alias gxc='gx clone'
alias gxc1='gxc --depth=1'
alias gxf='gx fetch'

#  working copy
alias gcl='g clone'
alias gxc='gx clone'
_shallow() {
    local cmd="$1"
    local depth="$2"
    shift 2
    "$cmd" --depth=$depth
}

alias gcs="_shallow g"
alias gxs="_shallow gx"

alias gco='g checkout'
alias gcob='gco -b'
alias gs='g status'

alias gadd='g add'
alias ga='gadd'
alias gmv='g mv'
alias grm='g rm'

alias grmr='grm -r'
alias grmrf='grm -rf'

alias grmcached='grm --cached'
alias grmrcached='grmcached -r'
alias grmrfcached='grmcached -rf'

# stash
alias gstash='g stash'
alias gst='g stash'
function gstp() { gst pop; }

#  branches

alias gb='g branch'
alias gba='gb -a'
alias gbd='gb -D'

# tags
alias gt='g tag'
alias gtd='gt -d'
alias gtl=gt

# remote tags
# TODO
#  gh api -H "Authorization: Bearer $GH_PAT" repos/NixOS/nixpkgs/tags  --paginate  | jq -r '.[] | select(.name | test("^[0-9]{2}\\.[0-9]{2}$")) | .name'

# commits

alias gc='g commit'
alias gca='gc -a'
alias gcam='gca -m'
# find dangling entities
alias glostfound='g fsck --lost-found'
_glfhash() {
    local what="$1"

    glostfound | rg "$what" | rg -o '[\da-f]{40}'
}

alias glfcommits='_glfhash commit'
alias glfblobs='_glfhash blob'

# print commits provided as list of hashes via stdin
alias gdump='x | git -P show'

alias gresign1='gc --amend --no-edit -n -S'

gresign() {
    if [ $# != 1 ]; then
        cat <<EOF
resigns commits till specified one

usage:
    gresign <commit>
EOF
        return 1
    fi

    git rebase --exec 'git commit --amend --no-edit -n -S' -i "$1"

}

# pull / fetch / merge / rebase
alias gf='g fetch -vp'
alias gp='g pull'
alias gpr='gp --rebase'
alias gpff='gp --ff-only'
alias gff=gpff
alias gr='g rebase'
alias gm='g merge'
alias gms='gm --squash'
alias gsq=gms
alias gchp='g cherry-pick'
alias gch=gchp

# interactive rebase

alias gri='gr -i'
grin() {
    local sp="$1"
    gri HEAD~"${sp:-1}"
}
alias gri1=grin
alias gri2='grin 2'
alias gri3='grin 3'
alias gri4='grin 4'
alias gr1=grin
alias gr2='grin 2'
alias gr3='grin 3'
alias gr4='grin 4'

#  lfs
alias glfs='g lfs'
alias gl=glfs

alias gltrack='gl track'
alias glt=gltrack

gluntrack() {
    gl untrack "$@"
    g rm --cached -r "$@"
    ga --renormalize "$@"
}
# stop using git-lfs
alias glmigrateref="gl migrate export"
alias glunroll="glmigrateref --everything"

alias glu=glu
alias glcl='gl clone'
alias glc=glcl

alias glf='gl fetch'

#    lfs fetch recent / all
alias glfrec='glf --recent'
alias glfall='glf --all'

#   locks
#   see https://www.atlassian.com/git/tutorials/git-lfs#installing-git-lfs
gltlockable() {

    glt "$1" --lockable \
        && cat <<EOF
IMPORTANT: ensure the desired pattern is in .gitattributes first:

echo "$1" filter=lfs diff=lfs merge=lfs -text lockable >> .gitattributes
gltl "$1"
EOF

}

alias gllock='gl lock'
alias glunlock='gl unlock'
alias glul=glunlock

alias _glprune='gl prune'

#     safety belt if 'git config --global lfs.pruneverifyremotealways true' not set
alias glprune='_glprune --verify-remote'

#  faster `git pull` for lfs
#   needs configuration of git plfs as per: https://www.atlassian.com/git/tutorials/git-lfs#installing-git-lfs
function gplfs() {
    g plfs || cat <<'EOF'
--
BOOM! lib.sh here. Ain't got a clue? Make sure alias.plfs is configured, otherwise run:

git config --global alias.plfs "\!git -c filter.lfs.smudge= -c filter.lfs.required=false pull && git lfs pull"
EOF

}

alias glp=gplfs

# logs
#   note: gl prefix is shared with git lfs aliases
alias glog='g log'
alias gll=glog
alias g1='glog -1'
alias g2='glog -2'
alias g3='glog -3'
alias g4='glog -4'
alias g8='glog -8'

# visualise git branches
alias gl1='g lg1'
alias gl2='g lg2'
alias glg='g lg'

# patches and diffs

alias gdiff='g diff'
alias gd=gdiff

function gdn() {

    local sp="$1"
    gd HEAD~${sp:-1}
}

alias gd1=gdn
alias gd2='gdn 2'
alias gd3='gdn 3'
alias gd4='gdn 4'

alias gdaapply='gd apply --whitespace=fix'
alias gdastat='gda --stat --apply' # --apply by some reason means 'dry run'

alias glogdiff='glog --all -p'
alias glogd=glogdiff

#  git lfs related, see: https://www.atlassian.com/git/tutorials/git-lfs#fetching-history
#   -S should follow git lfs sha-256 oid
alias gldiffs='glog --all -p -S'

#  pushes
#   best used with push.autoSetupRemote = true
alias gpush='g push'
alias gpusht='gpush --tags'

gpushdel() {
    if [ ! $# ]; then
        cat <<'EOF'
Usage: gpushd <branch|tag> [origin]
EOF
        return 1
    fi

    gpush ${2:-origin} --delete $1
}
alias gpusht=gtpush

#  remotes
alias gre='g remote'
alias grl=gre

function gra() {

    if [ $# -lt 2 ]; then
        cat <<'EOF'
Usage: gra <origin> <url>
EOF
        return 1
    fi

    gr add ${1:-origin} $2
}

alias gra='gre add'
alias grrm='gre remove'
alias grr=grrm
alias grd=grr
alias grmv='gre rename'

function grgu() {

    gre get-url ${1:-origin}

}
alias grg=grgu

grsu() {
    if [[ ! $# ]]; then
        cat <<'EOF'
Usage: grsu <url> [origin]
EOF
        return 1
    fi

    gre set-url ${2:-origin} $1
}

alias grs=grsu

# restore
alias gres='g restore'
alias grest='gres --staged'

# reset
alias grh='g reset --hard'
alias grhh='grh HEAD'

# submodules
alias gsa='g submodule add'
alias gsu='g submodule update --init --recursive'

# revlist
alias grevlist='g rev-list'
alias gallrevs='grevlist --all'
alias grevs=gallrevs

ggrep() {
    g grep "$1" $(grevs)
}

# gitui
alias gui='gitui'
alias gi=gui

# sleep fraction of second
function fsleep() {
    /usr/bin/perl -e "select(undef, undef, undef, $1)"
}

# rust
alias ru=rustup
alias car=cargo

# hdiutil

alias h=hdiutil
alias _ha='h attach'
alias _hnv='_ha -noverify'
alias _hnvo='_hnv -owners on'
alias hm=_hnvo
alias hmro='hm -readonly'
alias ha='hm -nomount'
alias has='ha -shadow'
alias hms='hm -shadow'
alias hd='h detach'
alias hi='h info'

# nerdctl
alias nctl='colima nerdctl'

# xcode
alias simctl='xcrun simctl'

# gcloud
alias gcl=gcloud

# cachix
alias cpush='cachix push'

cpushinputs() {
    nix flake archive --json | jq -r '.path,(.inputs|to_entries[].value.path)' | cpush "$@"
}

alias cpushi=cpushinputs
alias cpushidarwin='cpushi aarch64-darwin'

cpushruntime() {
    if [ $# -lt 1 ]; then
        cat <<EOF
Pushing runtime closure to cachix.

Usage:
    $0 <cache_name>
    $0 <package_name [package_name...] -- <cache_name> [cachix opts]
EOF
        return 1
    fi

    local grp1=()
    local grp2=()

    if [ $# = 1 ]; then
        grp2+=("$1")
    else
        local cur=()
        while [[ $# -gt 0 ]]; do
            if [[ $1 == "--" ]]; then
                grp1=("${cur[@]}")
                cur=()
                shift
            else
                cur+=("$1")
                shift
            fi
        done
        grp2=("${cur[@]}")
    fi

    nix build ${grp1[*]} --json \
        | jq -r '.[].outputs | to_entries[].value' \
        | cachix push ${grp2[*]}
}

alias cpushrt=cpushruntime

cpushrtdarwin() {

    cpushrt "$@" -- aarch64-darwin -m zstd -l 16
}

alias cpin='cachix pin'
alias cpindarwin='cpin aarch64-darwin'

# nomino - superfast renamer - is dangerous to use because of --dry-run (--test)
# is switched OFF by default which results in potentially dangerous mass renames.
# the wrapper, besides being a safequard, shows rename map, nicely highlighted with `jq`

# jq call is POSIX - incompliant
# hence this nasty wrapping
unset -f nomino
function nomino() {
    /usr/bin/env bash -c "jq < <('$(which nomino)' --test $@ -g /dev/fd/1)"
}

alias nom=nomino
# actually call nomino to perform unsafe action
alias nominate="$_nomino"

# jq-view
function j() {

    local fn="$1"
    shift
    cat "$fn" | jq "$@"

}

# cattpuccin
# ctp is cli binary
alias ctpal='inkcat macchiato,mocha,frappe,latte'
alias ctpl='cat ~/.local/share/catppuccin-cli/repos.json  | jq'

# zstd
alias zz='zstd -z'
alias zd='zstd -d'

zst() {
    if [[ $# -lt 2 ]]; then
        cat <<EOF
Usage: zst <output> [ tar -c - additional arguments ] <files...>

example: zst output.tar.zst -v *
EOF
        return 1
    fi

    local out="$1"
    shift

    tar -c -f - "$@" | zstd -z -o "$out"
}

zsta() {
    local name="${1%\/}"

    echo "Will archive $name to $name.tz and remove unarchived coppy if succeeded..."
    zst "$name".tz "$name" && rm -rf "$name" && echo && echo Done || echo Error: $?
}

alias xzs='zstd -d'

xzst() {
    if [[ $# -lt 1 ]]; then
        cat <<EOF
Usage: xzst <input> [tar -x additional arguments...]

example: mkdir ./archive ; xzst archive.tar.zst -v -C ./acrhive
EOF
        return 1
    fi

    local in="$1"
    shift

    zstd -d --memory=2048MB --stdout "$in" | tar -x "$@"
}

xzsta() {
    local name="$1"
    echo "Will unarchive $name to ${name%.*} and remove $name if succeeded..."

    xzst "$name" && rm -rf "$name" && echo && echo Done || echo Error: $?
}

del_working_tree() {
    local dest="$1"

    if [ ! -d "$dest"/.git ]; then
        echo "ERROR: $dest is not a git tree"
        return 1
    fi
    echo '1.5 sec to DESTRUCTIVE action'
    sleep 1.5
    echo 'BANG!'

    pushd "$dest" 1>/dev/null \
        && mv .git .. \
        && cld . \
        && mv ../.git . \
        && { popd 1>/dev/null || true; }

}

gitzsta() {
    del_working_tree "$1"

    if [ $? != 0 ]; then
        return $?
    fi

    zsta "$1"
}
alias unz=xzst
alias unza=xzsta

unzalong() {
    local long="${2:-31}"
    cat "$1" | zstd -d --long="$long" | tar xf -
}

# ipatool
alias ipa=ipatool
idownload() {
    ipa download -b $1 -o ~/Downloads
}
alias idown=idownload
alias ilogin='ipa auth login -e'
alias isearch='ipa search'
alias ipurchase='ipa purchase -b'

# sublime text
alias subl='~/.nix-profile/Applications/Sublime\ Text.app/Contents/MacOS/sublime_text &'
alias sub=subl

# opens macOS profiles pane
alias profpane='open "x-apple.systempreferences:com.apple.Profiles-Settings.extension"'

# littlesnitch

_lts=littlesnitch

_salias lts $_lts
_salias ltse $_lts export-model $_lts.json
_salias ltsr $_lts restore-model $_lts.json

#alias diff='diff --colors=always'

# meson

alias mx=meson
alias mxs='mx setup build'
alias mxre='mx setup --reconfigure build'
alias mxc='mx compile -C build'

# jc

j() {
    local cmd="$1"
    shift

    $cmd "$@" | jc --$cmd --pretty

}
_in() {
    local needle="$1"
    shift
    local haystack="$@"
    for x in ${haystack[@]}; do
        if [[ $x == "$needle" ]]; then
            return 0
        fi
    done

    return 1
}

everhex() {

    local values=(8 16 32)
    _in "$1" ${values[@]} \
        || {
            cat <<EOF
generates infinite sequence of hexademical values
usage: everhex [length]

args:
    length	value length, must be one of ${values[@]}
EOF
            return 1
        }

    od -t x -An /dev/random | tr -d " " | fold -w ${1:-8}
}

# atomicparsley
alias apars=atomicparsley

wttr() {
    local url="wttr.in"

    _curl_get "$url"/"$1"
}

# FLAC to ALAC
#
function flac2alac() {
    local _noart=0
    case $1 in
        --no-art | -noart | --no-cover | -nocover)
            _noart=1
            ;;
        -h | --help)
            cat <<'EOF'

flac2alac [ artwork ]
recursively converts FLAC to ALAC, starting from the current directory (.)

artwork:
    jpeg or png filename containing the artwork to be embedded in the
    resulting m4a; searched in every subdir

    default names being searched:
	cover.jpg
	cover.jpeg
	cover.png

EOF
            return 1
            ;;
    esac
    _require ffmpeg || return 1

    for f in ./**/*.flac; do
        echo converting "$f" to "${f%.*}.m4a"...
        ffmpeg -i "$f" -c:a alac -strict experimental -c:v copy "${f%.*}".m4a
    done

    _require atomicparsley && {
        if [ $_noart = 1 ]; then
            echo "not embedding artwork ($_noart)"
            return
        fi

        local _cnames=("$1" cover.jpg cover.jpeg cover.png)

        for f in ./**/*.m4a; do

            local _dn="$(dirname "$f")"
            for c in "${_cnames[@]}"; do
                if [ -f "$_dn/$c" ]; then
                    local _cover="$_dn/$c"
                    break
                fi
            done
            if [ -f "$_cover" ]; then
                echo embedding artwork: "$_cover" to: "${f%.*}.m4a"...
                echo

                atomicparsley "${f%.*}.m4a" --artwork "$_cover" --overWrite
            else
                echo not embedding artwork: "$_cover" does not exist
            fi
        done
    }
}

alias f2a=flac2alac
alias fmeta=metaflac
alias fmetatags='fmeta --show-all-tags'
alias fmetalist='fmeta --list'

# cue split

# to decode non-UTF-8 cuesheets -> `cconv`
# to find missing album art: https://bendodson.com/projects/itunes-artwork-finder/
flac2many() {
    if [ $# -lt 2 ]; then
        cat <<'EOF'
splits FLAC to many using cuesheet

Usage: flac2many <cue sheet> <flac to split> [--no-meta]

--no-meta: don't embed cue metadata

EOF
        return 1
    fi

    local cue="$1"
    local flac="$2"

    if [ "$3" != "" ]; then
        if [[ $3 =~ (--no-|-no)meta ]]; then
            local nometa=1
        else
            echo ERROR: unknown flag: "$3"
            return 1
        fi
    fi

    local tools=(flac shnsplit)

    if [ "$nometa" != 1 ]; then
        tools+=(cuetag fd)
    fi

    # cuetag is part of 'cuetools'
    _require ${tools[*]} || return 1

    shnsplit -t "%n. %t" -f "$cue" -o "flac flac -s -8 -o %f -" "$flac"

    if [ "$nometa" != 1 ]; then

        echo writing metadata...
        fd -d 1 '^[\d]+\.' -0 | x -0 cuetag "$cue"
        echo 'Done'
    else
        echo not writing metadata: --no-meta specified
    fi
    echo
}
alias f2m=flac2many

any2any() {
    if [[ $# -lt 2 || $1 == "-h" || $1 == "--help" ]]; then
        cat <<'EOF'
any2any <src files extensions> <dst codec> [ dst files extension ]

recursively converts source to destination.
if destination is not specified, flac is used.

e.g.:

any2any ape alac m4a
any2any m4a flac
any2any flac alac m4a

EOF
        return 1
    fi

    local src="$1"
    local dst_codec="$2"
    local dst_ext="${3:-$2}"

    _require ffmpeg || return 1

    for f in ./**/*.$src; do
        local title="${f%.*}"
        local dst="$title.$dst_ext"
        cat <<EOF

------------------------------------------------------------------------------------------
TITLE:	$title
FROM:	$src
TO:	$dst_ext$(if [ "$dst_codec" != "$dst_ext" ]; then echo " ($dst_codec)"; fi)
------------------------------------------------------------------------------------------

EOF
        ffmpeg -i "$f" -c:a "$dst_codec" -strict experimental -c:v copy "$dst"
    done

}

alias a2a=any2any

_wavpack() {
    if [ $# -lt 3 ]; then
        echo "ASSERT: insufficient arguments; expected at least 3, got $#." >&2
        return 1
    fi

    local cmd="$1"
    local src_ext="$2"
    local dst_ext="$3"
    shift 3

    if [ "$1" == "--help" ]; then
        cat <<'EOF'
wavpack conversion helper

Recursively converts audio files from source to destination format while
preserving metadata with utmost precision.

Usage:
    _wavpack <command> <source_ext> <destination_ext> [extra options]

Aliases:
    wav2wavpack (or w2wv): Converts WAV to WavPack
    wavpack2wav (or wv2w): Converts WavPack to WAV
EOF
        return 0
    fi

    _require "$cmd" || return 1

    for f in ./**/*."$src_ext"; do
        if [[ -f $f ]]; then
            local dst="${f%.*}.$dst_ext"
            echo "Converting $f to $dst..."
            "$cmd" "$f" -o "$dst" "$@"
        fi
    done
}

# Aliases
alias wav2wavpack='_wavpack wavpack wav wv -h -m'
alias w2wv=wav2wavpack

alias wavpack2wav='_wavpack wvunpack wv wav'
alias wv2w=wavpack2wav

wav2pcm() {
    if [[ $1 == "-h" || $1 == "--help" ]]; then
        cat <<'EOF'
recursively extracts raw pcm data from WAV files

WARNING: this is irreversible operation metadata-wise, meaning that
WAV files cannot be easily constructed from raw pcm, without manually
specifying PCM data type; also any other metadata is lost.

Usage:
    wav2pcm

Aliases:
    wav2raw
    w2raw
    w2p
    w2r
EOF
        return 1
    fi
    _require ffmpeg ffprobe || return 1

    local src_ext="wav"
    local dst_ext="raw"

    for f in ./**/*."$src_ext"; do
        if [[ -f $f ]]; then
            local fmt="$(ffprobe -v error \
                -print_format json \
                -show_streams \
                -select_streams a "$f" \
                | jq -r '.[].[0].codec_name' \
                | rg '^pcm_([\w]+)' --replace '$1')"

            local dst="${f%.*}.$dst_ext"
            echo "Converting $f to $dst [$fmt]..."
            echo ffmpeg -i "$f" -f "$fmt" -acodec copy "$dst"
        fi
    done
}

alias wav2raw=wav2pcm
alias w2raw=wav2raw
alias w2p=wav2pcm
alias w2r=w2raw

# tldr
alias tl='tldr --platform macos'

# lorem ipsum
alias tt='tt -theme nord'

# img viewer
alias img=chafa
alias im=img
cimg() {
    curl "$1" | chafa

}

ramdisk() {
    if [ $# != 1 ]; then
        cat <<'EOF'
Usage: ramdisk <size in MiB>
EOF
        return 1
    fi

    if (($1 < 16384 || $1 > (8 * 1024 * 1024))); then
        echo "ERROR: guard ($1)"
        return 1
    fi

    ha -nomount ram://$(($1 * 2))

}

# jq cat
jqc() {
    local f="$1"
    shift

    cat "$f" | jq $@

}

alias mk=make
alias hc=hashcat

# android
alias fb=fastboot
alias aemu=emulator

# ollama
alias llm=ollama
alias llml='llm list'
alias llmr='llm run'
alias llms='llm serve'
alias llmp='llm pull'

# npm/npx

alias npm='npm --no-fund'
alias npi='npm i'
alias npu='npm update'
alias ngi='npi -g'
alias ngu='npu -g'

alias npid='npm i -D'
alias npr='npm run dev'
alias ntsx='npx tsx'

# font smoothing
alias fontsmoothing='defaults -currentHost read -g AppleFontSmoothing'
alias setfontsmoothing='defaults -currentHost write -g AppleFontSmoothing -int'
alias delfontsmoothing='defaults -currentHost delete -g AppleFontSmoothing'

# rye
alias re=rye

alias rea='re add'
alias rer='re remove'

rel() {
    if [[ -f "$PWD/pyproject.toml" &&
        "$(cat pyproject.toml)" =~ \[tool.rye\] ]]; then
        re list
    else
        re tools list
    fi

}
alias resync='re sync'
alias res=resync
alias rerun='re run'

alias relint='rerun lint'
alias reli=rlint
alias refix='rerun fix'
alias refi=rfix
alias reshow='re show'
alias resh='re show'
alias relock='re lock'

alias ret='re tools'

alias retest='rerun test'

function rei() { _foreach rye tools install -- "$@"; }
function reu() { _foreach rye tools uninstall -- "$@"; }

alias retl='ret list'

function howmuch() {
    local seconds=$1
    local days=$((seconds / 86400))
    local hours=$(((seconds % 86400) / 3600))
    local minutes=$(((seconds % 3600) / 60))
    local secs=$((seconds % 60))

    output=""

    if [ $days -gt 0 ]; then
        output+="$days day"
        [ $days -gt 1 ] && output+="s"
        output+=", "
    fi
    if [ $hours -gt 0 ]; then
        output+="$hours hour"
        [ $hours -gt 1 ] && output+="s"
        output+=", "
    fi
    if [ $minutes -gt 0 ]; then
        output+="$minutes minute"
        [ $minutes -gt 1 ] && output+="s"
        output+=", "
    fi
    if [ $secs -gt 0 ]; then
        output+="$secs second"
        [ $secs -gt 1 ] && output+="s"
    fi

    # Remove trailing comma and space if they exist
    echo $(echo $output | sed 's/, $//')
}

# downloads
function dl() {
    if [ $# -lt 2 ]; then
        cat <<'EOF'
download files to the current directory using `dlm`

usage:

dl <maxConcurrentDownloads> <urls>...
EOF
        return 1
    fi

    local tmp="$(mktemp)"
    local max="$1"
    shift

    for url in "$@"; do
        echo "'$url'" >>"$tmp"
    done

    dlm --inputFile "$tmp" \
        --maxConcurrentDownloads "$max" \
        --outputDir .
}

function y() {
    if [ $# = 0 ]; then
        cat <<'EOF'
list youtube video streams using yt-dlp
exports previewed URL as YT_DLP_URL

Usage:
    y <URL>
EOF
        return 1
    fi

    local url="$1"
    shift

    export YT_DLP_URL="$url"
    export YT_DLP_URL_EXPORT_TS="$(date "+%s")"

    yt-dlp -F "$url" "$@"
    echo 'lib.sh: the url has been exported as YT_DLP_URL': "$YT_DLP_URL"
    echo
}

function ye() {

    if [ "${YT_DLP_URL}" = "" ]; then
        cat <<'EOF'
YouTube downloads

Usage:
    y <url>
	Shows available formats and exports url to YT_DLP_URL env variable
	for later usage with `ye` and `yeah`
    ye|yeah [yt-dlp opts]
	runs `yt-dlp` with url saved in YT_DLP_URL env variable by `y` command
	and forwards passed arguments to `yt-dlp`.

	the difference between `ye` and `yeah`: the second command will
	use `aria2c` as downloader.

	Options passed to `aria2c` are hardcoded:
	    --file-allocation=falloc --optimize-concurrent-download

	Note: `yeah` will fail if there is no `aria2c` in PATH
EOF
        return 1
    fi

    if [ "${YT_DLP_URL_EXPORT_TS}" != "" ]; then
        local ts="$(date "+%s")"
        local duration="$((ts - YT_DLP_URL_EXPORT_TS))"

        if [ ! $duration -le 60 ]; then

            while true; do
                read -p "$(
                    cat <<EOF

I found non-empty YT_DLP_URL, prefetched $(howmuch duration) ago:

${YT_DLP_URL}

Do you still want to use it for your download? [Yy]|[Nn]
EOF
                )" yn
                case $yn in
                    [Yy]*) break ;;
                    [Nn]*) return 1 ;;
                    *) echo "Please answer yes or no." ;;
                esac
            done
        fi
    fi

    yt-dlp "${YT_DLP_URL}" "$@"
}

unset -f aria2c
unset -f a2c
_aria2c="$(which aria2c)"
function aria2c() {
    "$_aria2c" --file-allocation=falloc --optimize-concurrent-downloads "$@"
}
alias a2c=aria2c

function yea() {
    _require aria2c || return 1

    ye "$@" \
        --external-downloader aria2c \
        --downloader-args "aria2c:--file-allocation=falloc --optimize-concurrent-downloads"
}
alias yeah=yea

function dlogin() {
    local pat=${*:-$(cat)}

    local url="${2:-ghcr.io}"
    local user="${3:-ink-splatters}"

    echo $pat | docker login "$url" -u $user --password-stdin
}

function qlean() { # quick cleanup
    sudo rm -rf /{,/var}/tmp/.* /{,/var}/tmp/*
    s rm -f /var/vm/sleepimage
    s rm -rf /var/logs
    fd -t f . /var/log -x sudo rm -f
    sudo rm -rf /var/networkd/*
    sudo rm -rf /var/db/{diagnostics,analytics,systemstats}/*
    sudo rm -rf /var/db/{NANDTelemetryServices,awdd,fsevents,spindump,uuidtext}

    cld ~/Library/Logs
    sudo rm -rf /Library/{Logs,Caches}/*

    rm -rf ~/Library/{Developer,Metadata}
    sudo rm -rf /Library/Bluetooth
}

function cconv() {
    if [ ! $# ]; then
        cat <<EOF
1. detects input encoding using chardet
2. converts input data using iconv

Usage: $(basename $0) <input file name>
EOF
        return 1
    fi

    _require chardetect iconv || return 1

    iconv -f $(chardetect "$1" --minimal) -t utf-8 "$1"
}

# fzf

alias ezf='fzf -e'
alias izf='fzf -i'
alias iezf='fzf -e -i'

alias azf='fzf --bind ctrl-a:select-all,ctrl-d:deselect-all,ctrl-t:toggle-all'
alias mez='azf -e -m'
alias miz='azf -i -m'
alias miez='azf -e -i -m'

# time
alias diso='date  "+%Y-%m-%d"'
alias dtiso='date  "+%Y-%m-%dT%H:%M:%S"'
alias dt='date  "+%Y-%m-%d %H:%M:%S"'

# ripgrep
alias rgnc='rg --color=never'

# tor
mytorsocks() {
    _exec netsocks localhost 9050
    tor
    _exec netsocks "" ""
}

# gollama
alias gollama='gollama -lm-dir ~/.lm-studio/models'

# proper .Trash / .Trashes folders setup

ensuretrashfor() {
    local u=$1
    #    local g=$(id -gn $u)
    local h=$(gethome $u)

    if [ "$__OSINSTALL_ENVIRONMENT" == 1 ]; then
        local h="$(getdatadir)$h"
    fi

    local t="$h/.Trash"

    _sexec rm -rf "$h/.Trashes"

    _sexec mkdir -p "$t"
    #    _sexec chmod 1311 "$t"
    _sexec chmod 700 "$t"
    _sexec chown $u "$t"
}

ensuretrashesfor() {

    local u=$1
    local g=$(id -gn $u)
    shift

    for v in "$@"; do
        local t="$v/.Trashes"
        _sexec mkdir -p "$t"
        _sexec chmod 1311 "$t"
        _sexec chown root:wheel "$t"

        if [ $u != 0 ]; then
            local tu="$t/$u"
            _sexec mkdir -p "$tu"
            _sexec chown $u:$g "$tu"
            _sexec chmod 700 "$tu"
        fi
    done
}

alias ensuretrash='ensuretrashfor $(id -u)'
alias ensuretrashes='ensuretrashesfor $(id -u)'

# tart
alias trt=tart
alias trr='tart run --no-audio --net-bridged=en0 --root-disk-opts="sync=fsync" --capture-system-keys'

# age
alias age=rage
alias age-keygen='rage-keygen'

fln() {
    local src="$1"
    local dst="$2"

    local info=$(statx "$src" 2>&1) || {
        echo "$output" >&2
        return 1
    }

    osascript -e 'tell application "Finder" to make alias file to POSIX file "$src" at POSIX file "$dst"' || return 1

    echo "Created Finder alias: $src [$info] -> $dst"
}

alias cv=cert-viewer
alias cg=certgraph

# sqldump

sqldump() {
    if [ $# = 0 ]; then
        cat <<EOF
Usage: $0 <sqlite db filename> [mode]

default mode is "line"
EOF
        return 1
    fi

    local mode="${2:-line}"
    local cmd=(sqlite3 "$1")
    local cmddump=(sqlite3 -"$mode" "$1")

    local tables=($("${cmd[@]}" .tables))

    if [ "$mode" != "json" ]; then
        printf "%s\n\n" "BEGIN DUMP"
    fi

    for t in "${tables[@]}"; do
        local count=$("${cmd[@]}" "select count(*) from $t")

        if [ "$count" = 0 ]; then
            if [ "$mode" != "json" ]; then
                echo "<EMPTY>"
                echo
            fi
            continue
        fi

        if [ "$mode" != "json" ]; then
            printf "TABLE: %s\n" "$t"
        fi

        "${cmddump[@]}" "select * from $t"

        if [ "$mode" != "json" ]; then
            echo
        fi
    done

    if [ "$mode" != "json" ]; then
        printf "%s\n\n" "END DUMP"
    fi
}

# tpaste.us

tcopy() {
    curl -F 'tpaste=<-' https://tpaste.us/ | tee /dev/tty | c
}

tpaste() {
    local input="$1"
    if [ "$input" = "" ]; then
        input="$(pbpaste)"
    fi

    if [[ $input =~ ^https?:// ]]; then
        local url="$input"
    elif [[ $input =~ [\w]{4} ]]; then
        local url="https://tpaste.us/$input"
    else
        echo Unknown paste format
        return 1
    fi

    curl "$url" || {
        echo Failed to retrieve paste: "$1"
        return 1
    }
}

# ip-api.com

whatip() {
    _curl_get http://ip-api.com/json/"$1" | jq
}

# list zombie processes
#
function zombies() {

    ps aux | grep Z

    >&2 cat <<'EOF'

In your head, in your head
Zombie, zombie, zombie-ie-ie...
		in memory of D. O'Riordan
EOF

}

alias zs=zombies

# parent pid

ppidof() {
    ps -o ppid= -p "$1"
}

# base64
alias b64=base64
alias b64d='base64 -d'

# bun

unset -f bun
alias _bun="$(which bun)"

function bun() {
    local args=()
    if [ $# -gt 0 ]; then
        if [ ! -f "$PWD/package.json" ]; then
            echo "running in global context"
            args+=(-g)
        fi

        args+=("$@")
    fi
    _bun "${args[@]}"
}

alias bn=bun
alias bpm='bn pm'
alias bpmc='bpm cache'
alias bcgd='bpmc rm' # a-la `ncgd`
alias bnl='bpm ls'
function bni() {
    _require bunx fd
    bn i "$@"

    local exes=
    mapfile -t exes < <(fd -t l . ~/.bun/bin -x readlink)

    for e in "${exes[@]}"; do sed -i '' -E 's/(#\!\/usr\/bin\/env) (node)/\1 bunx \2/g' "$HOME/.bun/bin/$e"; done

    echo 'Fixed up shebangs'
}
alias bnr='bn rm'
alias bnu='bn update'
alias bnxn='bunx'      # bunx "run with node"
alias bnx='bunx --bun' # force run with bun
alias bnre="${_bun[*]} repl"
alias bnn="${_bun[*]} init"
alias bnc="${bun[*]} c"

# sdkman
alias sdkl='sdk current'
alias sdkll='sdk list'
alias sdkr='sdk uninstall'
alias sdku='sdk update'
alias sdki='sdk install'
alias sdksu='sdk selfupdate'
alias sdkuse='sdk use'
alias sdkset='sdk default'
alias sdkdef=sdkset
sdkclean() {
    echo tmp metadata version | x -n1 sdk flush
}

# tectonic
alias tec=tectonic
teco() {
    tec "$1" && open "${1%.*}".pdf
}

# TODO: ✂ - - - - - - - - - - - - - - - - - - -

_init() {

    local self="$(getself)"
    echo -- self: "$self"

    alias fsl="source '$self'"
    alias flel="vi '$self'"

    if [[ $__OSINSTALL_ENVIRONMENT != 1 ]]; then
        system=/

    else
        local selfdir="$(getselfdir)"
        echo -- selfdir: "$selfdir"

        local data="$(getdatadir)"

        local vg=$(d info "$data" | grep 'APFS Volume Group' | grep -Eo '[0-9A-F-]{36}')

        local tmp=$(mktemp)
        alvg | grep "Volume Group $vg" -A10 >$tmp

        local svdev=/dev/$(cat $tmp | grep -E 'APFS Volume Disk \(Role\).+System' | grep -oE 'disk[0-9]+s[0-9]+')
        local dvdev=/dev/$(cat $tmp | grep -E 'APFS Volume Disk \(Role\).+Data' | grep -oE 'disk[0-9]+s[0-9]+')

        local system="$(dm $svdev | sed -E 's/(Volume) (.+) on \/dev\/disk[0-9]+s[0-9]+ mounted$/\/\1s\/\2/g')"
        echo -- mounted $svdev: "$system"

        local previouspath="/usr/bin:/bin:/usr/sbin:/sbin"
        export PATH="$data/usr/local/bin:$previouspath$(echo usr/bin:usr/libexec:usr/sbin:sbin:bin | sed -E 's@^|:@:'"$system\/"'@g')"

        echo -- linking vim runtime from system volume to: $HOME/vim

        rm -rf "$HOME"/vim
        ln -sf "$system"/usr/share/vim "$HOME"/vim

        local vimrc="$HOME"/.vimrc
        echo -- copying .vimrc to: $vimrc
        cp "$selfdir"/.vimrc "$vimrc"
        chmod 644 "$vimrc"
        chown $(whoami) "$vimrc"

        echo -- preparing the persistence in Recovery OS

        local bspath=/etc/profile

        local bkpath='N/A'

        local tmpfile=$(mktemp)
        if [ -f $bspath ]; then
            bkpath=$bspath.orig
            if [ ! -f $bkpath ]; then
                cp -a $bspath $bkpath
            else
                echo -- not overwriting backed up original profile: $bkpath
            fi
        fi

        # TODO: WTF?
        cat $tmpfile >$bspath

        # there is no sudo in RecoveryOS
        _sudo='"$@"'

        # rsync path on Sonoma
        _rsync="$system/usr/libexec/rsync/rsync.samba"
        cat <<EOF >$bspath
# lib.sh footer written on $(date '+%+')
__LIBSH_INITIALIZED=1 source "$self"

alias fsl="source '$self'"
alias flel="vi '$self'"
alias fs="source /etc/profile"
alias fle="vi /etc/profile"

export PATH="$PATH"
echo -- PATH: "$PATH"

sudo() {
    $_sudo
}

_mandoc() {
    if [ "\${1##*.}" = ".gz" ] ; then
        mandoc "\$1" | gunzip | less
    else
        mandoc "\$1"| less
    fi
}

man() {
    local name=\$1
    local i=n

    if [[ \$(( name )) != 0 ]]; then
	i=\$name
	name=\$2
	if [ \$name = "" ] ; then
	    echo Specify the man page to view.
	    return 1
	fi
    fi

    local fnbase='$system'/usr/share/man/man

    local fnith=\${fnbase}\$i/\$name.\$i
    local fn1st=\${fnbase}1/\$name.1

    local fns=( \$fnith \$fnith.gz \$fn1st \$fn1st.gz )

    for ((i=0;i<"\${#fns[@]}";i++)) ; do
	if [ -e "\${fns[i]}" ] ; then
	    _mandoc "\${fns[i]}"
	    return \$?
	fi
    done

    echo "No man file for: \$name."
    return 1
}

export VIMRUNTIME="$HOME"/vim/vim91

# on Sonoma we must create rsync alias
# pointing to unusual location
if [ -f "$_rsync" ]; then
	alias rsync="'$_rsync'"
fi

# end of lib.sh footer
EOF
        source $bspath

        cat <<EOF

Summary:
	Bootstrapped to: $bspath
		Wrote:	$bspath
		Backup: $bkpath

	Self:	$self

	Volume Group:	$vg
		System:	$svdev
		Data:	$dvdev

EOF
        echo -- initialized!
    fi

}

if [[ $__LIBSH_INITIALIZED != 1 ]]; then
    _init
    echo -- updated \$PATH: "$PATH"
fi
