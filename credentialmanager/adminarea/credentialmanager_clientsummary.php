<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file adds Credential Manager to the client summary
* "Other Actions" panel in the admin area.
*/

add_hook('AdminAreaClientSummaryActionLinks', 1, function($vars) {
    $return = [];
    $return[] = "<img src=\"images/icons/servers.png\" border=\"0\" align=\"absmiddle\"> "
               ."<a href=\"addonmodules.php?module=credentialmanager&client_id={$vars['userid']}\">Open Credential Manager</a>";

    return $return;
});
