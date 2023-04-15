LIBSH_VERSION=20230415_dev
cat <<EOF
			lib.sh v$LIBSH_VERSION
Initializing...

EOF

# status

function _problem() { echo '**' there was a problem running: $@; }

# uuid generation
alias uuid=uuidgen
alias ugen=uuid
alias ug=ugen
alias u0='printf "%s"  00000000-0000-0000-0000-000000000000'

# uppercase
alias upper='tr "[[:lower:]]" "[[:upper:]]"'
alias up=upper

# generation using /dev/random

function rand() {
	if [[ $# == 0 ]]; then
		cat <<EOF
the util takes <count> bytes from /dev/random and outputs lower-case hex values

usage: rand <count> [-f] [-n]

<count>		byte count
-f, --force	if count > 64, the flag is required
-n, --newline	if specified, '\n' is added after the output

example: to get 256 bit nonce use: $(rand 32)

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

	dd if=/dev/random bs=1 count=$count 2>/dev/null | xxd -p | tr -d '\n'

	((n == 1)) && echo
}

function randn() {
	rand $@ -n
}

alias randp='rand 8 | grep -Eo ".{8}"' # pair of short nonces
alias randup='randp | up'

# networking

alias n='sudo nextdns'
alias na='n activate'
alias nd='n deactivate'
alias ni='n install'
alias nl='nslookup'
alias nr='n restart'
alias ns='n status'
alias nu='n uninstall'
alias ncw='n config wizard'

function m() {
	mullvad $@
}

alias mc='m connect ; m status'
alias md='m disconnect ; m status'
alias mr='echo Reconnecting... ; m reconnect ; m status'
alias mvpn='m lockdown-mode set'

alias net='networksetup'
alias ng=ngrep

function mac() {

	local interface=en0

	if [ "$1" != "" ]; then
		interface="$1"
	fi

	ifconfig $interface | grep ether | grep -Eo ' [0-9a-f:]+' | tr -d ' \t'

}

function randmac() {

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

	/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z
	local mac=$(rand 6 | sed -E 's/([0-9a-f]{2})/:\1/g' | sed 's/^://g')

	echo -- "generated value: $mac; attempting to set..."
	ifconfig $interface ether "$mac"
	(($? == 0)) && mac && echo done.
}

# status / system info

#alias about='macchina'

alias ms='m status'

# mullvad status with increasing verbosity

# TODO: get local network status

function _status_dns() {
	printf "\t"
	m dns get | grep Custom
}

function _status_always_req() {

	printf "\t"
	m lockdown-mode get

}
function _mss() {

	echo
	printf "Mullvad status:\n\t"
	ms
}

function mss() {
	_mss
	_status_dns
	_status_always_req
}

function msss() {
	_mss
	_status_always_req

	local dns="$(m dns get)"
	printf "\tDNS:\n"

	echo "$dns" | sed 's/ DNS//g' | sed 's/^/\t\t/g'

	printf "\tRelay info:\n\t\t%s\n" "$(m relay get | sed -E 's/^[^:]+: //g')"
}

function nets() {

	local keys=(IP Mask Gateway Ether DNS)
	local values=($(net -getinfo 'Wi-Fi' | grep -E '^(IP |Sub|Router|^Wi-Fi)' | tr -d ' \t' | sed -E 's/^[^:]+://g'))
	values+=($(net -getdnsservers 'Wi-Fi'))

	echo
	echo Network status:
	for ((i = 1; i <= ${#keys[@]}; i++)); do
		printf "\t"
		echo "${keys[i]}: ${values[i]}"
	done
}

alias br='broot'
alias umamba=micromamba
alias um=umamba
alias ma=umamba
alias maa='ma activate'

# editing / viewing

alias _vi=/usr/bin/vi

# editing / viewing
if [[ "$EDITOR" == "" ]]; then
	export EDITOR=vim
fi
alias vi="$EDITOR"
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
alias x1='x -n1'

alias xpp="xargs -n1 -I@ -R -1 sh -c 'echo @ ; echo ; /usr/libexec/PlistBuddy -c print @'"
alias xfetch="ls | xargs -n1 -I@ -R -1 sh -c 'pushd @ ; git fetch -vp ; popd'"

# file system / ls + clean/rm utils

alias laa='ls -laO@e'
alias la='ls -la'

alias f=find

# find helpers:
# - support 1 search term (for now) in 1 or more locations
# - search term gets globbed from both sides, by default
# - case insensitive versions are postfixed with i
# - globbing is tunable with prefix: no prefix, l, r, n[no globbing]

# function f() { local what="$1" ; shift ; echo find $@ -name "'*${what}*'"; }
# function fi() { local what="$1" ; shift ; find $@ -iname "'*${what}*'"; }

# function lf() { local what="$1" ; shift ; find $@ -name "'*${what}'" ; }
# function lfi() { local what="$1" ; shift ; find $@ -iname "'*${what}'" ; }

# function rf() { local what="$1" ; shift ; find $@ -name "${what}*'"; }
# function rfi() { local what="$1" ; shift ; find $@ -iname "${what}*'"; }

# function nf() { local what="$1" ; shift ; find $@ -name "${what}'" ; }
# function nfi() { local what="$1" ; shift ; find $@ -iname "${what}" ; }

alias _editto='ditto --rsrc --noqtn --extattr --preserveHFSCompression --persistRootless'
alias ecp='_editto --acl'
alias ecpnoacl='_editto --noacl'
alias editto=ecp
alias edittonoacl=ecpnoacl

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

# fs lockers

# Despite not to be inferred from names exactly, all the routines lock file system objects from
# further changes by both System and User.

# There are destructive and non-destructive versions of the routines.

# WARNING
# They serve temporary, opinionated measure against macOS annoyances, depriving it from configs
# and Data believed to disturb User Privacy. They may or may not help, potentially being capable to make things worse,
# in the worst case scenario - kill the system, cause extremely wierd issues hard to debug
# because of unexpected and unpredictable modifications to OS state.
# Unwise use may kill your system. It's possible that resource utilization would go crazy by those
# daemons deprived of their precious things, grinning, moaning and craving for their getting back.
#
# If you are still not scared enough: it's like opening combustion engine' gas distribution mechanism,
# pouring some good pack of IKEA screws, (which are ALWAYS left after you assemble your another piece, aren't thy).
# Don't hesitate to throw any useless thing found in the garage on it, as much as space allows.
# When it becomes evident that no room has left, do fix up the new gasket and the lid on the top of it,
# as per your engine service manual. It's time to start it up!
# --
# I mean wa w... ww.wait! NO! Don't do it!!!!1111 Wait!!

# 1. destructive

# before locking, erases directories'  contents and lock those from further changes by both system or user.
# "softer" versions are still destructive!

function fdirs() {
	for d in "$@"; do
		chflags -R nouchg,noschg "$d" 2>/dev/null
		rm -rf "$d"
		mkdir -p "$d"
		chflags uchg,schg "$d"
	done

}
# "softer" version
# same but preserve original folders and its ownership, permissions, unrelated BSD flags and  xattrs
function sfdirs() {
	for d in "$@"; do
		chflags -R nouchg,noschg "$d" 2>/dev/null

		if [ ! -d "$d" ]; then mkdir "$d"; fi

		cleandirs 1>/dev/null "$d"
		chflags uchg,schg "$d"
	done
}
alias sfd=sfdirs

function ffiles() {
	for f in "$@"; do
		chflags nouchg,noschg "$f" 2>/dev/null
		rm -f "$f"
		touch "$f"
		chflags uchg,schg "$f"
	done
}
# "softer" version
# same but preserve original files and its ownership, permissions, unrelated BSD flags and  xattrs
function sffiles() {
	for f in "$@"; do
		chflags nouchg,noschg "$f" 2>/dev/null
		truncate -s 0 "$f"
		chflags uchg,schg "$f"
	done
}

alias sff=sffiles

# 2. non-destructive

alias lock='chflags uchg,schg'
alias unlock='chflags nouchg,noschg'
# recursive version
alias unlockr='chflags -R nouchg,noschg'
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
	# for v in /Volumes/* /nix ; do _tus "$v" ; done

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
alias muw='mount -uw'

# apfs

function msnap() {
	if [[ $# < 3 || "$1" == "-h" || "$1" == "--help" ]]; then
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

	local mopt=(-s $s $@)

	if [ ! -d "$m" ]; then
		mkdir -p "$m"
		echo "-- mount point: $m created ( didn't exist )"
	fi

	mount_apfs ${mopt[*]} "$@" $d "$m"
}

alias a='d apfs'
alias au='a unlock'
alias al='a lock'
alias alu='a listUsers'

function ausr() { a listUsers "$1" | grep -Eo '[0-9A-F-]{36}' | head -1; }

alias alvg='a listVolumeGroups'
alias adelvg='a deleteVolumeGroup'
alias als='a listSnapshots'
alias adels='a deleteSnapshot'
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
alias gba='gb -a'
alias gbd='gb -D'
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
alias hd='h detach'
alias hi='h info'

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
	if [[ "$__OSINSTALL_ENVIRONMENT" != 1 ]]; then
		ms
	fi
fi
