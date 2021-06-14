<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file provides the ClientArea interface
*/

if (
    $_SERVER['HTTPS'] != 'on' ||
    $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'http'
) {
    $url = "https://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
    header('HTTP/1.1 301 Moved Permanently');
    header("Location: {$url}");
    exit;
}

use WHMCS\Authentication\CurrentUser;
use WHMCS\ClientArea;
define('CLIENTAREA', true);
require __DIR__ . '/init.php';
$ca = new ClientArea();
$ca->setPageTitle('Credential Manager');
$ca->addToBreadCrumb('clientarea.php', Lang::trans('globalsystemname'));
$ca->addToBreadCrumb('credentialmanager.php', 'Credential Manager');
$ca->initPage();
$ca->requireLogin();
$currentUser = new CurrentUser();
$authUser = $currentUser->user();

if ($authUser) {
    $selectedClient = $currentUser->client();
} else {
    $ca->assign('userFullname', 'Guest');
}

if ($selectedClient) {
    $client_id = $selectedClient->id;
    require 'modules/addons/credentialmanager/core.php';
    $cm = new CredentialManager();
} else {
    echo 'No valid client is selected';
    exit;
}

if ($client_id != $cm->debug_client_id && $cm->debug_client_id != '') {
    echo "Sorry you cant access this right now. Debug enabled for ID {$cm->debug_client_id}";
    exit;
}

if ($_GET) {
    if ($_GET['action'] == 'add' || ($_GET['action'] == 'modify')) {
        $cm->buildMainModal($client_id, $_GET);
    } elseif ($_GET['action'] == 'delete') {
        $cm->buildDeleteModal($client_id, $_GET);
    } else {
        echo 'Invalid GET request';
    }
    unset($_GET);
    exit;
}

if ($_POST) {
    if (array_key_exists('action', $_POST)) {
        if ($_POST['action'] == 'add') {
            $alert = $cm->addCredential($client_id, $_POST);
        } elseif ($_POST['action'] == 'modify') {
            $alert = $cm->modifyCredential($client_id, $_POST);
        } elseif ($_POST['action'] == 'delete') {
            $alert = $cm->removeCredential($client_id, $_POST);
        } elseif ($_POST['action'] == 'requestkey') {
            if ($cm->admin) {
                $alert = $cm->buildAlert('danger', 'You are logged in as admin, use KeyCLI to create unlock keys.');
            } else {
                $alert = $cm->requestUnlockKey($client_id, $_POST);
            }
        } elseif ($_POST['action'] == 'unlock' && array_key_exists('unlock_key', $_POST)) {
            $alert = $cm->requestUnlock($client_id, $_POST);
        } else {
            $alert = $cm->buildAlert('danger', 'Invalid POST request');
        }
    } else {
        $alert = $cm->buildAlert('danger', 'Unknown POST request');
    }
    $_SESSION['alert'] = $alert;
    $_SESSION['page_refresh_count'] = 0;
    unset($_POST);
    header('Location: credentialmanager.php');
}

if ($_SESSION['page_refresh_count'] >= 2) {
    unset($_SESSION['page_refresh_count']);
    unset($_SESSION['alert']);
} else {
    $_SESSION['page_refresh_count']++;
}

$limits = $cm->getCredentialLimits();
$ca->assign('csrf_token', $cm->getCSRF());
$ca->assign('unlock_status', $cm->buildUnlockStatus($client_id));
$ca->assign('alert_pill', $_SESSION['alert']);
$ca->assign('custom_count', $cm->countCredentials($client_id, 'custom'));
$ca->assign('custom_limit', $limits['custom_credential_limit']);
$ca->assign('custom_table', $cm->buildCustomTable($client_id));
$ca->assign('managed_count', $cm->countCredentials($client_id, 'managed'));
$ca->assign('managed_table', $cm->buildManagedTable($client_id));
$ca->assign('recurring_count', $cm->countCredentials($client_id, 'recurring'));
$ca->assign('recurring_table', $cm->buildRecurringTable($client_id));
$ca->assign('enduser_count', $cm->countCredentials($client_id, 'enduser'));
$ca->assign('enduser_limit', $limits['enduser_credential_limit']);
$ca->assign('enduser_table', $cm->buildEnduserTable($client_id));
$ca->setTemplate('credentialmanager');
$ca->output();
