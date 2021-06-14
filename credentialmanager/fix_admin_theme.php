<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file provides a quick fix if the admin page stops
* displaying correctly after a WHMCS update.
*/

if (http_response_code()) {
    die('This cannot be run via a webserver');
}

$path = dirname(__FILE__);

if (!strpos($path, 'modules/addons/credentialmanager')) {
    echo 'Error! You must run this within <whmcs_dir>/modules/addons/credentialmanager/';
    exit;
}

if ($argc > 1) {
    require 'setup.php';
    if ($argv[1] == 'add') {
        $result = credentialmanager_add_adminarea();
        if ($result) {
            echo "Done. Dont forget to chown your public_html directory.\n";
        } else {
            echo "Error! Backups may exist in adminarea/ or failed to copy files.\n";
        }
    }
    if ($argv[1] == 'remove') {
        $result = credentialmanager_remove_adminarea();
        if ($result) {
            echo "Done. Dont forget to chown your public_html directory.\n";
        } else {
            echo "Error! Failed to restore admin theme\n";
        }
    }
} else {
    echo "Syntax: php fix_admin_theme.php <add/remove>\n";
}
