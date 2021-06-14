<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file provides functions for WHMCS module on
* activation/de-activation/upgrade
*/

use WHMCS\Database\Capsule;

function credentialmanager_create_tables()
{
    if (!Capsule::schema()->hasTable('cm_credentials')) {
        try {
            Capsule::schema()->create(
                'cm_credentials',
                function ($table) {
                    $table->integer('cred_id', true);
                    $table->integer('client_id', false);
                    $table->string('ticket', 30);
                    $table->string('type', 50);
                    $table->string('hostname', 50);
                    $table->string('ipaddr', 39);
                    $table->text('ssh_user');
                    $table->text('ssh_pswd');
                    $table->integer('ssh_port', false);
                    $table->boolean('ssh_key_root');
                    $table->boolean('ssh_key_user');
                    $table->text('root_pswd');
                    $table->text('notes');
                    $table->timestamps();
                }
            );
        } catch (\Exception $e) {
            return false;
        }
    }
    if (!Capsule::schema()->hasTable('cm_wrapper_keys')) {
        try {
            Capsule::schema()->create(
                'cm_wrapper_keys',
                function ($table) {
                    $table->integer('key_id', true);
                    $table->text('public_key');
                    $table->text('private_key');
                    $table->timestamps();
                }
            );
        } catch (\Exception $e) {
            return false;
        }
    }
    return true;
}

function credentialmanager_update_tables($current_version)
{
    return true;
}

function credentialmanager_create_wrapper_keypair()
{
    $wrapper_keys = Capsule::table('cm_wrapper_keys')
        ->get();
    if ($wrapper_keys->count() == 0) {
        $now = date('Y-m-d H:i:s');
        $private_key = sodium_crypto_box_keypair();
        $private_hex = sodium_bin2hex($private_key);
        $public_key = sodium_crypto_box_publickey($private_key);
        $public_hex = sodium_bin2hex($public_key);
        $wrapper_key = [
            'public_key' => $public_hex,
            'private_Key' => $private_hex,
            'created_at' => $now,
            'updated_at' => $now
        ];
        try {
            $result = Capsule::table('cm_wrapper_keys')
                ->insert($wrapper_key);
        } catch (Exception $e) {
            return false;
        }
        $wrapper_keys = Capsule::table('cm_wrapper_keys')
            ->get();
        if ($wrapper_keys->count() == 0) {
            return false;
        }
    }
    return true;
}

function credentialmanager_remove_clientarea()
{
    $path = dirname(__FILE__);
    $files = [
        "{$path}/../../../includes/hooks/credentialmanager_navigation.php",
        "{$path}/../../../credentialmanager.php",
        "{$path}/../../../templates/twenty-one/credentialmanager.tpl"
    ];
    foreach ($files as $file) {
        if (file_exists($file)) {
            unlink($file);
        }
    }
    if (
        file_exists("{$path}/../../../credentialmanager.php") ||
        file_exists("{$path}/../../../templates/twenty-one/credentialmanager.tpl") ||
        file_exists("{$path}/../../../includes/hooks/credentialmanager_navigation.php")
    ) {
        return false;
    }
    return true;
}

function credentialmanager_add_clientarea()
{
    if (!credentialmanager_remove_clientarea()) {
        return false;
    }
    $path = dirname(__FILE__);
    copy("{$path}/clientarea/credentialmanager.php", "{$path}/../../../credentialmanager.php");
    copy("{$path}/clientarea/credentialmanager.tpl", "{$path}/../../../templates/twenty-one/credentialmanager.tpl");
    copy("{$path}/clientarea/credentialmanager_navigation.php", "{$path}/../../../includes/hooks/credentialmanager_navigation.php");
    if (
        !file_exists("{$path}/../../../credentialmanager.php") ||
        !file_exists("{$path}/../../../templates/twenty-one/credentialmanager.tpl") ||
        !file_exists("{$path}/../../../includes/hooks/credentialmanager_navigation.php")
    ) {
        return false;
    }
    return true;
}

function credentialmanager_add_adminarea()
{
    $path = dirname(__FILE__);
    if (
        file_exists("{$path}/adminarea/header.tpl.original") ||
        file_exists("{$path}/adminarea/sidebar.tpl.original")
    ) {
        return false;
    }
    rename("{$path}/../../../admin/templates/blend/header.tpl", "{$path}/adminarea/header.tpl.original");
    rename("{$path}/../../../admin/templates/blend/sidebar.tpl", "{$path}/adminarea/sidebar.tpl.original");
    copy("{$path}/adminarea/header.tpl", "{$path}/../../../admin/templates/blend/header.tpl");
    copy("{$path}/adminarea/sidebar.tpl", "{$path}/../../../admin/templates/blend/sidebar.tpl");
    copy("{$path}/adminarea/credentialmanager_blend.css", "{$path}/../../../admin/templates/blend/css/credentialmanager_blend.css");
    copy("{$path}/adminarea/credentialmanager_clientsummary.php", "{$path}/../../../includes/hooks/credentialmanager_clientsummary.php");
    if (
        !file_exists("{$path}/adminarea/header.tpl.original") ||
        !file_exists("{$path}/adminarea/sidebar.tpl.original") ||
        !file_exists("{$path}/../../../admin/templates/blend/header.tpl") ||
        !file_exists("{$path}/../../../admin/templates/blend/sidebar.tpl") ||
        !file_exists("{$path}/../../../admin/templates/blend/css/credentialmanager_blend.css") ||
        !file_exists("{$path}/../../../includes/hooks/credentialmanager_clientsummary.php")

    ) {
        return false;
    }
    return true;
}

function credentialmanager_remove_adminarea()
{
    $path = dirname(__FILE__);
    if (
        !file_exists("{$path}/adminarea/header.tpl.original") ||
        !file_exists("{$path}/adminarea/sidebar.tpl.original")
    ){
        return false;
    }
    $files = [
        "{$path}/../../../admin/templates/blend/header.tpl",
        "{$path}/../../../admin/templates/blend/sidebar.tpl",
        "{$path}/../../../admin/templates/blend/css/credentialmanager_blend.css",
        "{$path}/../../../includes/hooks/credentialmanager_clientsummary.php"
    ];
    foreach ($files as $file) {
        if (file_exists($file)) {
            unlink($file);
        }
    }
    rename("{$path}/adminarea/header.tpl.original", "{$path}/../../../admin/templates/blend/header.tpl");
    rename("{$path}/adminarea/sidebar.tpl.original", "{$path}/../../../admin/templates/blend/sidebar.tpl");
    if (
        !file_exists("{$path}/../../../admin/templates/blend/header.tpl") ||
        !file_exists("{$path}/../../../admin/templates/blend/sidebar.tpl") ||
        file_exists("{$path}/../../../admin/templates/blend/css/credentialmanager_blend.css") ||
        file_exists("{$path}/../../../includes/hooks/credentialmanager_clientsummary.php")
    ) {
        return false;
    }
    return true;
}
