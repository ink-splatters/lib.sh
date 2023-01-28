LIBSH_VERSION=20230128
cat <<EOF
			lib.sh v$LIBSH_VERSION
Initializing...

EOF

# status

function _problem() { echo '**' there is a problem with: $@; }

# uuid generation
alias uuid=uuidgen
alias ugen=uuid
alias ug=ugen
alias u0='printf "%s"  00000000-0000-0000-0000-000000000000'

# generation using /dev/random

function urand() {
	if [[ $# == 0 ]]; then
		cat <<EOF
the util takes <count> bytes from /dev/urandom and outputs lower-case hex values

usage: urand <count> [-f] [-n]

<count>		byte count
-f, --force	if count > 64, the flag is required
-n, --newline	if specified, '\n' is added after the output

example: to get 256 bit nonce use: $(urand 32)

EOF
		return 1
	fi

	local f=0
	local n=0

	local count=$1
	shift
	((count == 0)) &&
		echo "ERROR: invalid value: $count" &&
		return 1

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

	((count > 64)) && ((f != 1)) &&
		echo 'for count > 64 use -f' &&
		return 1

	dd if=/dev/urandom bs=1 count=$count 2>/dev/null | xxd -p | tr -d '\n'

	((n == 1)) && echo
}

alias ur=urand
function urn() {
	ur $@ -n
}

# pair of short nonces
function urpair() {
	ur 16 | grep -Eo '.{16}'
}

alias about='macchina'
alias br='broot'

alias v='ivpn'
alias vh='v -h'
alias vhh='v -h -full'
alias vf='v firewall'
alias von='vf -on'
alias voff='vf -off'
alias vfe='vf -exceptions'
alias vs='ivpn status'
alias vc='ivpn connect'
alias vcl='vc -last'
alias vd='ivpn disconnect'

# editing / viewing

alias _vi=/usr/bin/vi

# editing / viewing
if [[ "$EDITOR" == "" ]]; then
	export EDITOR=vim
fi
alias vi="$EDITOR"
alias fs="source ~/.zshrc"
alias fle="vim $HOME/.zshrc"
alias batlog='bat --paging=never -l log'
alias e=echo

# themes
# TODO: list wezterm themes?
# alias themes="kitty +kitten themes"

# launchctl

alias lc='launchctl'
alias lcbo='lc bootout'
alias lcd='lc disable'
alias lcbs='lc bootstrap'
alias lck='lc kill'
alias lcks='lc kickstart -k'
alias c=pbcopy
alias p=pbpaste
alias ptrim="p | tr -d '\n'"
alias ptr=ptrim

# plists

alias pb=/usr/libexec/PlistBuddy
alias pp='pb -c print'
alias xml1='plutil -convert xml1'
alias bin1='plutil -convert binary1'

# functools kinda stuff (love it)
alias x=xargs
alias xo='x -n1'

# uppercase
alias upper='tr "[[:lower:]]" "[[:upper:]]"'
alias up=upper

alias xpp="xargs -n1 -I@ -R -1 sh -c 'echo @ ; echo ; /usr/libexec/PlistBuddy -c print @'"
alias xfetch="ls | xargs -n1 -I@ -R -1 sh -c 'pushd @ ; git fetch -vp ; popd'"

# file system / ls + clean/rm utils

alias laa='ls -laO@e'
alias la='ls -la'

alias f=find

alias _editto='ditto --rsrc --noqtn --extattr --preserveHFSCompression --persistRootless'
alias ecpnoacl=_editto
alias ecp='_editto --acl'
alias editto=ecp

alias ecpnoacl=
function _fdrm() {
	local nameflag="$1"
	local what="$2"
	shift 2

	find "$@" "$nameflag" "$what" -exec rm -rf {} \;

}

function fdrm() {
	local what="$1"
	shift
	_fdrm -name "$what" "$@"
}

function fdirm() {
	local what="$1"
	shift
	_fdrm -iname "$what" "$@"
}

function cleandirs() {
	for d in "$@"; do rm -rf "$d"/* "$d"/.*; done

}
alias cld=cleandirs
# attrs

alias xd='xattr -rd'
alias xsd='xattr -rsd'
function _x() {

	local args="$1"
	local attr="$2"
	shift 2

	xattr $args $attr "$@" | grep -Eo ' com.+' | sort -u
}

function xv() {
	local attr="$1"
	shift
	_x -rv $attr "$@"
}

function xsv() {
	local attr="$1"
	shift
	_x -rsv $attr "$@"
}

# flags

alias cfu='chflags -R uchg,schg'
function fdirs() {
	for d in "$@"; do
		chflags -R nouchg,noschg "$d" 2>/dev/null
		rm -rf "$d"
		mkdir -p "$d"
		chflags uchg,schg "$d"
	done

}

function ffiles() {
	for d in "$@"; do
		chflags -R nouchg,noschg "$d" 2>/dev/null
		rm -rf "$d"
		touch "$d"
		chflags uchg,schg "$d"
	done

}
alias lock='chflags uchg,schg'
alias lockr='lock -R'
alias unlock='chflags -R nouchg,noschg'
alias ufdirs=unlock

# index

alias mdx='mdutil -X'
alias mdoff='mdutil -i off -d'

function mdon() { mdutil -i on "$1" -E; }
alias mdaoff='mdoff -a'

# wireless && networking
alias airportd=/usr/libexec/airportd
alias ap='airport'
alias apd='airportd'
alias won='sudo /usr/libexec/airportd setpower on'
alias woff='sudo /usr/libexec/airportd setpower off'
alias wup='sudo ifconfig en0 up'
alias wdown='sudo ifconfig en0 down'
alias wassoc='sudo /usr/libexec/airportd assoc --ssid'
alias rewifi='echo down up | x -I@ sh -c "echo -- @ ; sudo ifconfig en0 @ ; sleep 1"'

function wchan() {
	if [ $1 != "" ]; then
		wdown
		echo -setting channel to: $1
		sudo airport -c=$1
		sleep 1
	else
		airport -c
	fi
}
function wscan() { sudo airport -s "$1"; }
alias wi='airport -I'
alias winfo=wi
alias ngrep0='sudo ngrep -d en0'

function tree {
	broot -c :pt "$@"
}
alias s=sudo
alias si='sudo -i'
alias k='kill -9'

function _maybe() {
	commdand -v $@ >/dev/null 2>&1 && $@
}

function mdcat() {
	glow "$@"

	echo "this is not actual mdcat"
}

if [ -n "${commands[fzf - share]}" ]; then
	source "$(fzf-share)/key-bindings.zsh"
	source "$(fzf-share)/completion.zsh"
fi

# no anymore myaw in da houze
# alias kd='kitty +kitten diff'

alias mk=mkdir
alias mkp='mk -p'
alias _fd=fd
alias fd='_fd -iuuu'
alias _rg=rg
alias rg='_rg -uuu'
alias rgi='_rg -iuuu'

# TODO: mind that c is for pbcopy
# c() {
# 	if [[ $# -gt 1 ]] ; then echo error ; return ; fi
#	uutils-coreutils "$1"
# }

alias ns='networksetup'
alias nl='nslookup'

alias xpkgs="xargs -n1 | sed -E 's/^/nixpkgs\./g'"

function _i() { echo "$@" | xpkgs | xargs nix-env -iA; }
alias i=_i

alias u='nix-env -e'
alias q='nix-env -q'

#TM snapshots

alias t=tmutil
alias snap='tmutil localsnapshot'
alias ts=snap
alias _tus='tmutil deletelocalsnapshots'
function unsnap() {

	# _tus /
	# for v in /Volumes/* ; do _tus "$v" ; done

	mount | grep -E '/dev.+on /' | sed -E "s/^.+on (.+) \(.+/\'\1'/g" | xargs -n1 -J% tmutil deletelocalsnapshots %
	echo Unmounted volumes were unaffected.

}
alias usnap=unsnap
alias tus=unsnap

# diskutil general

alias d='diskutil'
alias l='diskutil list'
alias dm='d mount'
alias dum='d umount'
alias dud='d umountDisk'
alias dr='d rename'

# apfs

alias a='d apfs'
alias au='a unlock'
alias al='a lock'
alias alu='a listUsers'

function ausr() { a listUsers "$1" | grep -Eo '[0-9A-F-]{36}' | head -1; }

alias alvg='a listVolumeGroups'
alias adelvg='a deleteVolumeGroup'
alias als='a listSnapshots'
alias aav='a addVolume'
alias adel='a deleteVolume'

function aev() { a encryptVolume "$1" -user disk; }
function adv() { a decryptVolume "$1" -user $(ausr "$1"); }

function aav() {
	if [[ $# -lt 2 ]]; then
		echo not enough args
		return
	fi
	a addVolume "$1" APFS "$2"
}

# git

alias g=git
alias gb='g branch'
alias gba='gb a'
alias gs='g status'
alias gc='g commit'
alias gca='gc -a'
alias gco='g checkout'
alias gpr='g pull --rebase'
alias gri='g rebase -i'
alias gf='g fetch -vp'
alias gl='g log'
alias gl1='gl -1'
alias gd='git difftool --no-symlinks --dir-diff'

# hdiutil

alias h=hdiutil
alias _ha='h attach'
alias _hnv='_ha -noverify'
alias _hnvo='_hnv -owners on'
alias hm=_hnvo
alias ha='hm -nomount'
alias has='ha -shadow'
alias hms='hm -shadow'
alias hd='_h detach'
alias hi='_h info'

# TODO: ✂ - - - - - - - - - - - - - - - - - - -

function _init() {

	local exp='self="${BASH_SOURCE[0]:-${(%):-%x}}"'
	eval $(echo $exp)

	if [[ $(echo "$self" | grep -Eo '^[/]') == "" ]]; then self="$(pwd)/$self"; fi

	echo -- self: $self

	alias fsl="source '$self'"
	alias flel="vi '$self'"

	if [[ "$__OSINSTALL_ENVIRONMENT" != 1 ]]; then
		system=/

	else
		local data="$(echo "$self" | sed -E 's/(^\/Volumes\/[^/]+)\/.+$/\1/g')"
		local vg=$(d info "$data" | grep 'APFS Volume Group' | grep -Eo '[0-9A-F-]{36}')

		local tmp=$(mktemp)
		alvg | grep "Volume Group $vg" -A10 >$tmp

		local svdev=/dev/$(cat $tmp | grep -E 'APFS Volume Disk \(Role\).+System' | grep -oE 'disk[0-9]+s[0-9]+')
		local dvdev=/dev/$(cat $tmp | grep -E 'APFS Volume Disk \(Role\).+Data' | grep -oE 'disk[0-9]+s[0-9]+')

		local system="$(dm $svdev | sed -E 's/(Volume) (.+) on \/dev\/disk[0-9]+s[0-9]+ mounted$/\/\1s\/\2/g')"
		echo -- mounted $svdev: "$system"

		local previouspath="/usr/bin:/bin:/usr/sbin:/sbin"
		export PATH="$data/usr/local/bin:$previouspath$(echo usr/bin:usr/libexec:usr/sbin:sbin:bin | sed -E 's@^|:@:'"$system\/"'@g')"

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

		cat $tmpfile >$bspath
		cat <<EOF >$bspath
# lib.sh footer written on $(date '+%+')
__LIBSH_INITIALIZED=1 source "$self"

alias fsl="source '$self'"
alias flel="vi '$self'"
alias fs="source /etc/profile"
alias fle="vi /etc/profile"

export PATH="$PATH"
echo -- PATH: "$PATH"
# end of lib.sh footer
EOF

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
