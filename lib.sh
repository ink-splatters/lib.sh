LIBSH_VERSION=20230816_01b82ac
cat <<EOF
			lib.sh v$LIBSH_VERSION
Initializing...

EOF

# helpers

_problem() { echo '**' there was a problem running: $@; }
_maybe() { command -v $@ >/dev/null 2>&1 && $@; }

_alias() {
	local name="$1"
	shift
	args=($@)
	alias $name="${args[*]}"
}
_salias() {
	local name="$1"
	shift
	args=($@)
	alias $name="sudo ${args[*]}"
} # sudo

#sudo

alias s=sudo
alias si='sudo -i'

# functools kinda stuff (love it)
alias x=xargs
alias x1='x -n1'

alias xpp="xargs -n1 -I@ -R -1 sh -c 'echo @ ; echo ; /usr/libexec/PlistBuddy -c print @'"
alias xfetch="ls | xargs -n1 -I@ -R -1 sh -c 'pushd @ ; git fetch -vp ; popd'"

# uuid generation
alias uuid=uuidgen
alias ugen=uuid
alias ug=ugen
alias u0='printf "%s"  00000000-0000-0000-0000-000000000000'

# uppercase
alias upper='tr "[[:lower:]]" "[[:upper:]]"'
alias up=upper

# better xxd: https://github.com/felixge/go-xxd
alias xd=go-xxd

# status / system info
alias about='macchina'
alias info=about

# generation using /dev/random

rand() {
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

randn() {
	rand $@ -n
}

alias randp='rand 8 | grep -Eo ".{8}"' # pair of short nonces
alias randup='randp | up'

# system // resources
alias pg='pgrep -i'

_salias k kill
_salias kall killall

alias k9='k -9'

pk() { pg "$1" | x kill -9; }

alias t=btop
alias bw=bandwhich

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
alias nu='n uninstall'
alias ncw='n config wizard'
alias m=mullvad

alias mc='m connect ; m status'
alias md='m disconnect ; m status'
alias mr='echo Reconnecting... ; m reconnect ; m status'
alias mvpn='m lockdown-mode set'

_salias ap /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
_salias apd /usr/libexec/airportd
_salias ifc ifconfig

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

	mvpn off
	md
	nd
	nu
	sleep 1

	rt -n flush
	dsc -flushcache
	kall -m HUP mDNSResponder

	ifc down
	sleep 1

	ifc en0 up
	sleep 1

	na
	ni
	mc
	sleep 1
	mc
	nr
	sleep 1

	mvpn on

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

alias netsetup=networksetup

mac() {

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

nets() {

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

alias br=broot

alias pkg=pkgutil
alias pkgs='pkg --pkgs'
_salias pkgf pkgutil --forget
alias pkgd=pkgf
alias upkg=pkgf

# python
alias um=micromamba
alias uma='um activate'
alias uenv='um env'

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
alias pl=plutil
alias plc='pl -convert'
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

alias laa='ls -laO@e'
alias la='ls -la'

alias f=find

# TODO: fix broken
# find helpers:
# - support 1 search term (for now) in 1 or more locations
# - search term gets globbed from both sides, by default
# - case insensitive versions are postfixed with i
# - globbing is tunable with prefix: no prefix, l, r, n[no globbing]

# f() { local what="$1" ; shift ; echo find $@ -name "'*${what}*'"; }
# fi() { local what="$1" ; shift ; find $@ -iname "'*${what}*'"; }

# lf() { local what="$1" ; shift ; find $@ -name "'*${what}'" ; }
# lfi() { local what="$1" ; shift ; find $@ -iname "'*${what}'" ; }

# rf() { local what="$1" ; shift ; find $@ -name "${what}*'"; }
# rfi() { local what="$1" ; shift ; find $@ -iname "${what}*'"; }

# nf() { local what="$1" ; shift ; find $@ -name "${what}'" ; }
# nfi() { local what="$1" ; shift ; find $@ -iname "${what}" ; }

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
alias xa='xattr'
alias xad='xattr -d'
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

# as it shadows legitimate app:

alias csv=/nix/var/nix/profiles/default/bin/xsv

# fs lockers

# Despite not to be inferred from names exactly, all the routines lock file system objects from
# further changes by both System and User.

# There are destructive and non-destructive versions of the routines.

# 1. destructive

# before locking, erases directories'  contents and lock those from further changes by both system or user.
# "softer" versions are still destructive!

fdirs() {
	for d in "$@"; do
		chflags -R nouchg,noschg "$d" 2>/dev/null
		rm -rf "$d"
		mkdir -p "$d"
		chflags uchg,schg "$d"
	done

}
# - "softer" version
# same but preserve original folders and its ownership, permissions, unrelated BSD flags and  xattrs
sfdirs() {
	for d in "$@"; do
		chflags -R nouchg,noschg "$d" 2>/dev/null

		if [ ! -d "$d" ]; then mkdir "$d"; fi

		cleandirs 1>/dev/null "$d"
		chflags uchg,schg "$d"
	done
}
alias sfd=sfdirs

ffiles() {
	for f in "$@"; do
		chflags nouchg,noschg "$f" 2>/dev/null
		rm -f "$f"
		touch "$f"
		chflags uchg,schg "$f"
	done
}
# - "softer" version
# same but preserve original files and its ownership, permissions, unrelated BSD flags and  xattrs
sffiles() {
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

mdon() { mdutil -i on "$1" -E; }
alias mdoffa='mdoff -a'

mdcat() {
	glow "$@"

	echo "this is not actual mdcat"
}

if [ -n "${commands[fzf - share]}" ]; then
	source "$(fzf-share)/key-bindings.zsh"
	source "$(fzf-share)/completion.zsh"
fi

# no myaw in da houze
# alias kd='kitty +kitten diff'

alias mk=mkdir
alias mkp='mk -p'
alias _rg=rg
alias rg='_rg -uuu'
alias rgi='_rg -iuuu'

# TODO: mind that c is for pbcopy
# c() {
# 	if [[ $# -gt 1 ]] ; then echo error ; return ; fi
#	uutils-coreutils "$1"
# }

alias xpkgs="xargs -n1 | sed -E 's/^/nixpkgs\./g'"

_i() { echo "$@" | xpkgs | xargs nix-env -iA; }
alias i=_i

alias u='nix-env -e'
alias q='nix-env -q'

#TM snapshots

alias tm=tmutil
alias ts='tmutil localsnapshot'
alias _tu='tmutil deletelocalsnapshots'

function tu() {

	vols=($(ls /Volumes) /nix)
	pics=/Users/ic/Pictures

	if [ -d $pics ]; then vols+=($pics); fi

	for v in "${vols[@]}"; do _tu "$v"; done

	# TODO: handle spaces
	mount | grep -E '/dev.+on /' | sed -E "s/^.+on (.+) \(.+/\'\1'/g" | xargs -n1 -J% tmutil deletelocalsnapshots %
	echo Unmounted volumes were unaffected.

}

# General APFS snapshots

# https://github.com/ahl/apfs
alias snap=snapUtil

# list APFS snapshots
alias snapl='snap -l'

# create APFS snapshot
alias snapc='snap -c'

# rename APFS snapshot
alias snapr='snap -n'

# Delete APFS snapshot, alternative to adels
alias snapd='snap -d'
alias adels2=snapd

# mount APFS snapshot (alternative to mount_apfs -s )
alias snapm='snap -s'
alias msnap2='snap -s'

# APFS snapshot info
alias snapi='snap -o'

# Revert to APFS snapshot
alias tosnap='snap -r'

# diskutil general

alias d='diskutil'
alias l='diskutil list'
alias dm='d mount'
alias dum='d umount'
alias dud='d umountDisk'
alias dr='d rename'
alias muw='mount -uw'
_salias eo diskutil enableOwnership

# apfs
_salias apfs.util /System/Library/Filesystems/apfs.fs/Contents/Resources/apfs.util
msnap() {
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

ausr() { a listUsers "$1" | grep -Eo '[0-9A-F-]{36}' | head -1; }

alias alvg='a listVolumeGroups'
alias adelvg='a deleteVolumeGroup'
alias als='a listSnapshots'
alias adels='a deleteSnapshot'
alias aav='a addVolume'
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

	if (($EUID != 0)); then
		_sudo=sudo
	fi

	local src="$1"
	local tgt="$2"
	shift 2

	$_sudo asr restore -s "$src" -t "$tgt" -noprompt -noverify $@
}

srestore() {
	local snap="$1"
	local src="$2"
	local tgt="$3"

	shift 3

	clone "$src" "$tgt" --toSnapshot "$snap" $@
}

# git

alias g=git

#  working copy
alias gs='g status'
alias gco='g checkout'
alias gcr='gco -b'

alias ga='g add'
alias garenorm='ga --renormalize'
alias grm='g rm'
alias grmc='grm --cached'
alias grmr='grm -r'
alias grmf='grm -rf'

alias grmcr='grmc -r'
alias grmcrf='grmc -rf'

#  branches  "CRUD"
alias gb='g branch'
alias gba='gb -a'
alias gbd='gb -D'
alias gbc='gco -b'

# tags

alias _gt='g tag'
alias gtag=_gt

alias gtl='_gt -l'

gt() {
	gtl
	cat <<'EOF'
Use `gtag` to create a new tag
EOF
}

alias gtpush='g push --tags'
alias gtd='_gt -d'

# commits

alias gc='g commit -a'
alias gcae='g commit --allow-empty'

#  merge / rebase
alias gp='g pull'
alias gpr='gp --rebase'

# grep
alias gg='g grep'

#  lfs
alias gl='g lfs'

#   lfs install
alias glinst='gl install'
alias gluninst='gl uninstall'

alias glt='gl track'

glu() {
	gl untrack "$@"
	garenorm .
}
alias glut=glu
alias glc='gl clone'

#   lfs fetch
alias glf='gl fetch'
alias gfl=glf # marry it to gf a.k.a. git fetch

#    lfs fetch recent / all
alias glfrecent='glf --recent'
alias glfall='glf --all'

#   locks
#   see https://www.atlassian.com/git/tutorials/git-lfs#installing-git-lfs
gltlockable() {

	glt "$1" --lockable &&
		cat <<EOF
IMPORTANT: ensure the desired pattern is in .gitattributes first:

echo "$1" filter=lfs diff=lfs merge=lfs -text lockable >> .gitattributes
gltl "$1"
EOF

}

alias gll='gl lock'
alias glul='gl unlock'

#   lfs prune
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
alias gpl=glp # marry it to gp a.k.a. git pull

alias gr='g rebase'
alias gri='gr -i'
alias gf='g fetch -vp'

# logs
#   note: gl prefix is shared with git lfs aliases
alias glog='g log'
alias glo=glog
alias gl1='glog -1'
alias gl2='glog -2'
alias gl3='glog -3'
alias gl4='glog -4'
alias gl8='glog -8'

# patches and diffs

alias gd='g diff'
alias gda='gd apply --whitespace=fix'
alias gdastat='gda --stat --apply' # --apply by some reason means 'dry run'
alias gdstat=gdastat

alias gdiff='git difftool --no-symlinks --dir-diff' # TODO: check, was it intented to use it with gitui?
alias gldiff='glog --all -p'

#  git lfs related, see: https://www.atlassian.com/git/tutorials/git-lfs#fetching-history
#   -S should follow git lfs sha-256 oid
alias gldiffs='glog --all -p -S'

#  pushes
#   best used with push.autoSetupRemote = true
alias gpush='g push'

gpushd() {
	if [[ $# -lt 1 ]]; then
		cat <<'EOF'
Usage: gpushd <branch|tag> [origin]
EOF
		return 1
	fi

	local origin="$2"
	if [ "$origin" != "" ]; then shift; else origin=origin; fi

	gpush $origin --delete $1
}
alias gpusht=gtpush

#  remotes
alias gre='g remote'
alias grea='gre add'
alias grerm='gre remove'
alias gremv='gre rename'
alias gregu='gre get-url'
alias greg=gregu
gresu() {
	local origin=$1
	local url="$2"
	gre set-url $1 "$2"
}

# restore
alias gres='g restore'
alias gress='gres --staged'

#  gitui
alias gui='gitui'

# rust
alias ru=rustup
alias car=cargo

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

# nerdctl
alias nctl='colima nerdctl'

# TODO: ✂ - - - - - - - - - - - - - - - - - - -

_init() {

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

		# patch for Sonoma
		alias rsync="'$system/usr/libexec/rsync/rsync.samba'"

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

# patch for Sonoma
alias rsync="'$system/usr/libexec/rsync/rsync.samba'"
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
