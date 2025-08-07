#!/bin/sh
#
# This script is an example of how a local gpg-agent (running on a
# machine which the user physically uses) can be forwarded to the
# remote server and there it can be used as a source of C4GH keys.
#
# WARNING: This is only the minimal setup required by oarepo-c4gh
# package, it is NOT enough to work with actual GPG keys! The only
# purpose of this script is to allow the user to use locally connected
# OpenPGP smart card and/or token (like YubiKey) for processing
# encrypted data on the remote host!
#
# Usage:
#   sh gpg-agent-forward.sh username@remote.tld
#
# All options are passed on as ssh command-line arguments.
#

# Detect remote UID
USERID=
if [ -z "$USERID" ] ; then
    USERID=`ssh -q "$@" id -u`
fi

# Firstly we ensure the required directories exist (yes, running gpg
# is enough):
#   gpg --list-keys
#
# Secondly we ensure no local gpg-agent is running on the remote
# machine:
#   gpgconf --kill gpg-agent
#
# And thirdly we explicitly remove the socket file (to avoid various
# common problems):
#  rm /run/user/$USERID/gnupg/S.gpg-agent
#
ssh "$@" "gpg --list-keys ; gpgconf --kill gpg-agent ; rm /run/user/$USERID/gnupg/S.gpg-agent"

# Then we establish a ssh session forwarding the FULL agent socket.
#
# WARNING: forwarding the EXTRA agent socket is NOT enough as the
# HAVEKEY command has limited functionality then. It may be possible
# to use the extra socket (and it can be considered a good practice),
# however that requires the user to specify the GPG "keygrip" of the
# token - which places unnecessary burden on the user.
#
ssh -R "/run/user/$USERID/gnupg/S.gpg-agent:$(gpgconf --list-dir agent-socket)" "$@"
