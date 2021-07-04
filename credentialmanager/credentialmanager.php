<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file provides the WHMCS module and includes additional
* files for setup and admin area output.
*/

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

function credentialmanager_config()
{
    return [
        'name' => 'Credential Manager',
        'description' => 'Credential Manager provides strong encrypted storage'
            . ' for credentials, accessible by clients and admins.',
        'author' => 'Chris Elliott',
        'language' => 'english',
        'version' => '1.1',
        'fields' => [
            'debug_client_id' => [
                'FriendlyName' => 'Debug client ID',
                'Type' => 'text',
                'Size' => '11',
                'Default' => '',
                'Description' => 'Prevents all except the specified client id from using the ClientArea page',
            ],
            'keyserver_url' => [
                'FriendlyName' => 'Keyserver hostname',
                'Type' => 'text',
                'Size' => '50',
                'Default' => 'https://yourdomain.com/keyserver.php',
                'Description' => 'Enter full url to your Keyserver',
            ],
            'keyserver_secret' => [
                'FriendlyName' => 'Keyserver secret',
                'Type' => 'text',
                'Size' => '100',
                'Default' => '',
                'Description' => 'Enter a strong random string upto 100 characters',
            ],
            'custom_credential_limit' => [
                'FriendlyName' => 'Custom credential limit',
                'Type' => 'text',
                'Size' => '3',
                'Default' => '10',
                'Description' => 'Enter value between 0-999',
            ],
            'enduser_credential_limit' => [
                'FriendlyName' => 'Enduser credential limit',
                'Type' => 'text',
                'Size' => '3',
                'Default' => '50',
                'Description' => 'Enter value between 0-999',
            ],
            'managed_credential_types' => [
                'FriendlyName' => 'Managed credential types',
                'Type' => 'text',
                'Size' => '200',
                'Default' => 'ansible,elk,cpanel,directadmin,lamp,lemp,nagios,plesk,solusvm_master,solusvm_dns,solusvm_xen,solusvm_kvm,solusvm_openvz,sensu,webmin,other',
                'Description' => 'Enter comma seperated list',
            ],
            'recurring_credential_types' => [
                'FriendlyName' => 'Recurring credential types',
                'Type' => 'text',
                'Size' => '200',
                'Default' => 'ansible,elk,cpanel,directadmin,lamp,lemp,nagios,plesk,solusvm_master,solusvm_dns,solusvm_xen,solusvm_kvm,solusvm_openvz,sensu,webmin,other',
                'Description' => 'Enter comma seperated list',
            ]
        ]
    ];
}

function credentialmanager_activate()
{
    require 'setup.php';
    $create_tables = credentialmanager_create_tables();
    $create_wrapper_keypair = credentialmanager_create_wrapper_keypair();
    $add_clientarea = credentialmanager_add_clientarea();
    $add_adminarea = credentialmanager_add_adminarea();
    if (!$create_tables) {
        $description = 'Failed to create database tables';
        return ['status' => 'error', 'description' => $description];
    } elseif (!$create_wrapper_keypair) {
        $description = 'Failed to create wrapper keypair';
        return ['status' => 'error', 'description' => $description];
    } elseif (!$add_clientarea) {
        $description = 'Failed to add clientarea page';
        return ['status' => 'error', 'description' => $description];
    } elseif (!$add_adminarea) {
        $description = 'Failed to add adminarea modifications';
        return ['status' => 'error', 'description' => $description];
    }
    $description = 'WHMCS module ready to go. Now click configure to check'
                  .' basic settings and add your KeyServer.';
    return ['status' => 'success', 'description' => $description];
}

function credentialmanager_deactivate()
{
    require 'setup.php';
    $remove_clientarea = credentialmanager_remove_clientarea();
    $remove_adminarea = credentialmanager_remove_adminarea();
    if (!$remove_clientarea) {
        $description = 'Failed to remove clientarea page';
        return ['status' => 'error', 'description' => $description];
    } elseif (!$remove_adminarea) {
        $description = 'Failed to remove adminarea modifications';
        return ['status' => 'error', 'description' => $description];
    }
    $description = 'Clientarea pages removed. Database tables will remain.';
    return ['status' => 'success', 'description' => $description];
}

function credentialmanager_upgrade($vars)
{
    require 'setup.php';
    $update_tables = credentialmanager_update_tables($vars['version']);
}

function credentialmanager_output($vars)
{
    require 'admin.php';
    echo $body;
}

function credentialmanager_sidebar($vars)
{
    // Not used
}
