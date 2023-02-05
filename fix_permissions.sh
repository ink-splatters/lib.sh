#!/bin/sh

set -e
set -o pipefail

if [[ $# == 0 ]] ; then
        cat <<EOF
Fix Permissions
Restore (patched) rootfs' original permissions.

TODO: modify script to fully generate patched rootfs from templates.

WARNING: the util does NOT check your current directory,
make sure you run it from the place you want the output to be put to.

Usage: $0 <rootfs> [ --arch <value>,... ]
EOF
        cat <<'EOF'
        The util by default strips anything but arm64e from fat binaries.
        On Apple Silicon that's preferable for all the system binaries.

        You may want to specify the architectures you would like to preserve.
        see (`man ditto`) for the reference.

EOF
        exit 1 
fi

rootfs="$1"
archstr=( --arch arm64e )

if [[ $# -gt 1 ]] ; then
	shift
	archstr=( $@ )
fi

echo -- checking lib.sh ...

if [[ "$LIBSH_PATH" == "" ]] ; then
	echo ERROR: lib.sh not initialized
	exit 1
fi

TEMPLATES_PATH=/System/Library/Templates

if [[ "$__OSINSTALL_ENVIRONMENT" == 1 ]]; then
	echo --  __OSINSTALL_ENVIRONMENT. 

	if [[ "$LIBSH_SYSTEM_PATH" == "" ]] ; then
		echo ERROR: \$LIBSH_SYSTEM_PATH is not set
		echo
		env
	
		exit 1
	fi

	TEMPLATES_PATH="$LIBSH_SYSTEM_PATH"/System/Library/Templates
fi

echo -- templates path: "$TEMPLATES_PATH"

set -x

ditto \
	${archstr[*]} \
	--rsrc \
	--noacl \
	--noqtn \
	--extattr \
	--preserveHFSCompression \
	--persistRootless \
	"$TEMPLATES_PATH"/Data "$rootfs".fixed

pushd "$rootfs"
rsync -vhrlDHS --delete . ../"$rootfs".fixed  || popd

set +x

echo Done.
