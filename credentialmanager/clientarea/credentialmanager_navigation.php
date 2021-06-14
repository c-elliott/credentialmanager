<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file adds Credential Manager to the support dropdown
* in the main client navigation menu.
*/

use WHMCS\View\Menu\Item as MenuItem;

add_hook('ClientAreaPrimaryNavbar', 1, function (MenuItem $primaryNavbar)
{
    if (!is_null($primaryNavbar->getChild('Support'))) {
        $primaryNavbar->getChild('Support')
            ->addChild('Credential Manager', array(
                'label' => 'Credential Manager',
                'uri' => 'credentialmanager.php',
                'order' => '1',
            ));
    }
});
