<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file is intended to be run under a cronjob to
* automatically remove custom credentials, after 14
* days have past since the last update.
*/

if (http_response_code()) {
    die('This cannot be run via a webserver');
}

require '../../../init.php';
use Illuminate\Database\Capsule\Manager as Capsule;

try {
    $result = Capsule::table('cm_credentials')
        ->where('type', 'custom')
        ->where('updated_at', '<=', date('Y-m-d H:i:s',time()-1209600))
        ->delete();
} catch (Exception $e) {
    echo $e;
}
