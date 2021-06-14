#!/bin/bash
# WHMCS Credential Manager
# Copyright (c) 2020 Chris Elliott
#
# This software is licensed under the terms of the MIT License.
# https://github.com/c-elliott/credentialmanager/LICENSE
#
# This file provides the KeyCLI component which enables
# admins to create, show and purge unlock tokens, or
# simulate WHMCS requests for test purposes.
#
# This must be on a seperate server to WHMCS.

# Settings
KEYSERVER_URL="https://keyserver.yourdomain.com/keyserver.php"
KEYSERVER_SECRET="long-random-string-here-max-100-chars"
ORIGIN="admin" # admin or whmcs
WRAPPER_PUBLIC_KEY="" # only required for whmcs testing

# Do not edit below this line

if [[ $1 == "unlock" ]] && [[ ! -z $2 ]]; then
    if [[ $ORIGIN == "whmcs" ]]; then
        read -p "This will send an email to the client, are you sure?: (y/n) " CHECK
        if [[ $CHECK != "y" ]]; then
            exit 1
        fi
    fi
    curl -q -X POST \
        -F "origin=$ORIGIN" \
        -F "secret=$KEYSERVER_SECRET" \
        -F "request=unlock_key" \
        -F "client_id=$2" \
        -F "client_ip=$(curl -s icanhazip.com)" \
        -F "whmcs_url=http://whmcs-url-here.com/credentialmanager.php" \
        $KEYSERVER_URL

elif [[ $1 == "public" ]] && [[ ! -z $2 ]] && [[ ! -z $3 ]]; then
    curl -q -X POST \
        -F "origin=$ORIGIN" \
        -F "secret=$KEYSERVER_SECRET" \
        -F "request=public_key" \
        -F "client_id=$2" \
        -F "client_email=$3" \
        -F "wrapper_key=$WRAPPER_PUBLIC_KEY" \
        $KEYSERVER_URL

elif [[ $1 == "private" ]] && [[ ! -z $2 ]]; then
    curl -q -X POST \
        -F "origin=$ORIGIN" \
        -F "secret=$KEYSERVER_SECRET" \
        -F "request=private_key" \
        -F "unlock_key=$2" \
        -F "wrapper_key=$WRAPPER_PUBLIC_KEY" \
        $KEYSERVER_URL

elif [[ $1 == "show" ]]; then
    curl -q -X POST \
        -F "origin=$ORIGIN" \
        -F "secret=$KEYSERVER_SECRET" \
        -F "request=show_unlock_keys" \
        $KEYSERVER_URL

elif [[ $1 == "purge" ]]; then
    curl -q -X POST \
        -F "origin=$ORIGIN" \
        -F "secret=$KEYSERVER_SECRET" \
        -F "request=purge_unlock_keys" \
        $KEYSERVER_URL

elif [[ $1 == "update" ]] && [[ ! -z $2 ]] && [[ ! -z $3 ]]; then
    curl -q -X POST \
        -F "origin=$ORIGIN" \
        -F "secret=$KEYSERVER_SECRET" \
        -F "request=update_email" \
        -F "client_id=$2" \
        -F "client_email=$3" \
        $KEYSERVER_URL

else
    echo "     __"
    echo "    /o \_____"
    echo "    \__/-=\"=\"\`"
    echo "Credential Manager"
    echo "      KeyCLI"
    echo ""
    echo "$ORIGIN:"
    echo "  keycli.sh unlock <client-id>"
    if [[ $ORIGIN == "admin" ]]; then
        echo "  keycli.sh show"
        echo "  keycli.sh purge"
        echo "  keycli.sh update <client-id> <client-email>"
    elif [[ $ORIGIN == "whmcs" ]]; then
        echo "  keycli.sh public <client-id> <client-email>"
        echo "  keycli.sh private <unlock-key>"
    fi
    echo ""
fi
