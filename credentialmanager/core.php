<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file provides the core functions for WHMCS
* shared between the Client and Admin area.
*/

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

use WHMCS\Database\Capsule;

class CredentialManager
{

    function __construct()
    {
        $this->admin = false;
        $this->prepareModuleSettings();
        $this->preparePrivateKey();
    }

    function prepareModuleSettings()
    {
        try {
            $result = Capsule::table('tbladdonmodules')
                ->where('module', '=', 'credentialmanager')
                ->where('setting', '=', 'debug_client_id')
                ->orwhere('module', '=', 'credentialmanager')
                ->where('setting', '=', 'custom_credential_limit')
                ->orwhere('module', '=', 'credentialmanager')
                ->where('setting', '=', 'enduser_credential_limit')
                ->orwhere('module', '=', 'credentialmanager')
                ->where('setting', '=', 'managed_credential_types')
                ->orwhere('module', '=', 'credentialmanager')
                ->where('setting', '=', 'keyserver_url')
                ->orwhere('module', '=', 'credentialmanager')
                ->where('setting', '=', 'keyserver_secret')
                ->orwhere('module', '=', 'credentialmanager')
                ->select('setting', 'value')
                ->get();
            foreach($result as $row) {
                $setting = $row->setting;
                $this->$setting = $row->value;
            }
        } catch (Exception $e) {
            die('Error! Failed to retrieve required module settings');
        }
    }

    function preparePrivateKey()
    {
        if (array_key_exists('cm_unlock_keys', $_SESSION)) {
            foreach(array_keys($_SESSION['cm_unlock_keys']) as $client_id) {
                $this->requestPrivateKey($client_id, $_SESSION['cm_unlock_keys'][$client_id]);
            }
        }
    }

    function checkQuery($result)
    {
        if (is_int($result)) {
            return $result;
        } elseif ($result->isEmpty()) {
            return false;
        } elseif ($result->count() == 1) {
            return $result[0];
        }
        return $result;
    }

    function getWrapperKeys()
    {
        try {
            $result = Capsule::table('cm_wrapper_keys')
                ->get();
        } catch (Exception $e) {
            echo $e;
        }
        return $result[0];
    }

    function getClientEmail($client_id)
    {
        try {
            $result = Capsule::table('tblclients')
                ->where('id', '=', $client_id)
                ->pluck('email');
        } catch (Exception $e) {
            echo $e;
        }
        return $this->checkQuery($result);
    }

    function getClientName($client_id)
    {
        try {
            $result = Capsule::table('tblclients')
                ->where('id', '=', $client_id)
                ->select('firstname', 'lastname')
                ->get();
        } catch (Exception $e) {
            echo $e;
        }
        return $result[0];
    }

    function getClientIP()
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        }
        return $_SERVER['REMOTE_ADDR'];
    }

    function getCredential($client_id, $cred_id)
    {
        try {
            $result = Capsule::table('cm_credentials')
                ->where('client_id', '=', $client_id)
                ->where('cred_id', '=', $cred_id)
                ->get();
        } catch (Exception $e) {
            echo $e;
        }
        return $this->checkQuery($result);
    }

    function getCredentials($client_id, $type)
    {
        try {
            $result = Capsule::table('cm_credentials')
                ->where('client_id', '=', $client_id)
                ->where('type', 'LIKE', "{$type}%%")
                ->get();
        } catch (Exception $e) {
            echo $e;
        }
        return $result;
    }

    function getCredentialTypes($type)
    {
        try {
            $result = Capsule::table('tbladdonmodules')
                ->where('module', '=', 'credentialmanager')
                ->where('setting', '=', "{$type}_credential_types")
                ->pluck('value');
        } catch (Exception $e) {
            echo $e;
        }
        return $this->checkQuery($result);
    }

    function getCredentialLimits()
    {
        try {
            $result = Capsule::table('tbladdonmodules')
                ->where('module', '=', 'credentialmanager')
                ->where('setting', 'LIKE', '%%_credential_limit')
                ->pluck('value', 'setting');
        } catch (Exception $e) {
            echo $e;
        }
        return $this->checkQuery($result);
    }

    function countCredentials($client_id, $type)
    {
        try {
            $result = Capsule::table('cm_credentials')
                ->where('client_id', '=', $client_id)
                ->where('type', 'LIKE', "{$type}%%")
                ->count('cred_id');
        } catch (Exception $e) {
            echo $e;
        }
        return $this->checkQuery($result);
    }

    function insertCredential($credential)
    {
        try {
            $now = date('Y-m-d H:i:s');
            $credential['created_at'] = $now;
            $credential['updated_at'] = $now;
            $result = Capsule::table('cm_credentials')
                ->insert($credential);
        } catch (Exception $e) {
            echo $e;
        }
        return $result;
    }

    function updateCredential($credential)
    {
        try {
            $now = date('Y-m-d H:i:s');
            $credential['updated_at'] = $now;
            $result = Capsule::table('cm_credentials')
                ->where('client_id', $credential['client_id'])
                ->where('cred_id', $credential['cred_id'])
                ->update($credential);
        } catch (Exception $e) {
            echo $e;
        }
        return $result;
    }

    function deleteCredential($client_id, $cred_id)
    {
        try {
            $result = Capsule::table('cm_credentials')
                ->where('client_id', $client_id)
                ->where('cred_id', $cred_id)
                ->delete();
        } catch (Exception $e) {
            echo $e;
        }
        return $result;
    }

    function postKeyserver($request)
    {
        $ch = curl_init($this->keyserver_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $request);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_FORBID_REUSE, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        // Ideally the below should be true, however
        // CAPATH and CAINFO appear to have no effect
        // on cPanel servers, so CA's cannot be verified.
        curl_setopt($ch, CURLOPT_SSL_VERIFYSTATUS, false);
        $response = curl_exec($ch);
        curl_close($ch);
        if (empty($response)) {
            return false;
        }
        return $response;
    }

    function getRandom()
    {
        return base64_encode(openssl_random_pseudo_bytes(20));
    }

    function getCSRF()
    {
        if ($_SESSION['tkval']) {
            return sha1($_SESSION['tkval'] . session_id() . ':whmcscrsf');
        }
        return sha1($this->getRandom() . session_id() . ':whmcscsrf');
    }

    function checkCSRF($csrf)
    {
        $new = $this->getCSRF();
        return ($csrf == $new);
    }

    function encrypt($plain_text, $public_key)
    {
        try {
            $public_bin = sodium_hex2bin($public_key);
            $cipher_bin = sodium_crypto_box_seal($plain_text, $public_bin);
            $cipher_hex = sodium_bin2hex($cipher_bin);
        } catch (Exception $e) {
            return false;
        }
        return $cipher_hex;
    }

    function decrypt($cipher_hex, $private_key)
    {
        try {
            $private_bin = sodium_hex2bin($private_key);
            $cipher_bin = sodium_hex2bin($cipher_hex);
            $plain_text = sodium_crypto_box_seal_open($cipher_bin, $private_bin);
        } catch (Exception $e) {
            return false;
        }
        return $plain_text;
    }

    function sanitizeString($data)
    {
        return filter_var($data, FILTER_SANITIZE_STRING, FILTER_FLAG_NO_ENCODE_QUOTES);
    }

    function sanitizeHostname($data)
    {
        if (!empty($data)) {
            return filter_var($data, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);
        }
        return $data;
    }

    function sanitizeInt($data)
    {
        if (empty($data)) {
            return $data;
        } elseif ($data == 0) {
            return false;
        }
        return filter_var($data, FILTER_VALIDATE_INT);
    }

    function sanitizeBool($data)
    {
        if ($data != '0' && $data != '1') {
            $data = 0;
        }
        return $data;
    }

    function sanitizeIP($data)
    {
        if (!empty($data)) {
            return filter_var($data, FILTER_VALIDATE_IP);
        }
        return $data;
    }

    function validateCredential($client_id, $data)
    {
        if (!array_key_exists('cred_id', $data)) {
            $data['cred_id'] = 0;
        }
        $credential = [
            'client_id' => $this->sanitizeInt($client_id),
            'cred_id' => $this->sanitizeInt($data['cred_id']),
            'ticket' => $this->sanitizeString($data['ticket']),
            'type' => $this->sanitizeString($data['type']),
            'hostname' => $this->sanitizeHostname($data['hostname']),
            'ipaddr' => $this->sanitizeIP($data['ipaddr']),
            'ssh_user' => $this->sanitizeHostname($data['ssh_user']),
            'ssh_pswd' => $this->sanitizeString($data['ssh_pswd']),
            'ssh_port' => $this->sanitizeInt($data['ssh_port']),
            'ssh_key_root' => $this->sanitizeBool($data['ssh_key_root']),
            'ssh_key_user' => $this->sanitizeBool($data['ssh_key_user']),
            'root_pswd' => $this->sanitizeString($data['root_pswd']),
            'notes' => $this->sanitizeString($data['notes'])
        ];
        $valid = true;
        $alert = '';
        if (!$credential['client_id']) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'Invalid client id.');
        }
        if (strlen($credential['ticket']) < 3 || strlen($ticket) > 30) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'Ticket/reference must be between 3-30 characters.');
        }
        if (substr($credential['type'], 0, 6) != 'custom' &&
            substr($credential['type'], 0, 8) != 'managed_' &&
            substr($credential['type'], 0, 10) != 'recurring_' &&
            substr($credential['type'], 0, 7) != 'enduser') {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'Invalid credential type.');
        }
        if (strlen($$credential['type']) > 50) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'Credential type must be 50 characters or less.');
        }
        if ($credential['hostname'] === false || strlen($credential['hostname']) > 50) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'Hostname must be valid and 50 characters or less.');
        }
        if ($credential['ipaddr'] === false) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'IP Address must be valid.');
        }
        if (strlen($credential['ssh_user']) > 50) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'SSH User must be 50 characters or less.');
        }
        if (strlen($credential['ssh_pswd']) > 100) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'SSH Password must be 100 characters or less.');
        }
        if ($credential['ssh_port'] === false || strlen($credential['ssh_port']) > 5) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'SSH Port must be a number 5 characters or less.');
        }
        if (strlen($credential['root_pswd']) > 100) {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'Root Password must be 100 characters or less.');
        }
        if (strlen($credential['notes']) > '2000') {
            $valid = false;
            $alert .= $this->buildAlert('danger', 'Notes must be 2000 chars or less.');
        }
        if ($alert) {
            return $alert;
        }
        $encrypted = ['ssh_user', 'ssh_pswd', 'root_pswd', 'notes'];
        foreach ($encrypted as $field) {
            if (!empty($credential[$field])) {
                $public_key = $this->requestPublicKey($client_id);
                if (strpos($public_key, 'Error!') !== false) {
                    $alert .= $this->buildAlert('danger', str_replace('Error!', '', $public_key));
                    return $alert;
                }
                $cipher_hex = $this->encrypt($credential[$field], $public_key);
                if (!$cipher_hex) {
                    $alert .= $this->buildAlert('danger', 'Encryption failed, Keyserver may be unreachable.');
                    return $alert;
                }
                $credential[$field] = $cipher_hex;
            }
        }
        return $credential;
    }

    function addCredential($client_id, $data)
    {
        if (!$this->checkCSRF($data['token'])) {
            return $this->buildAlert('danger', 'Invalid CSRF token. Check if you have multiple windows open.');
        }
        $credential = $this->validateCredential($client_id, $data);
        if (!is_array($credential)) {
            return $credential;
        }
        if (($credential['type'] == 'custom' || $credential['type'] == 'enduser') && !$this->admin) {
            $count = $this->countCredentials($client_id, $credential['type']);
            if (!$count) {
                $count = 0;
            }
            $limits = $this->getCredentialLimits();
            if (!$limits) {
                return $this->buildAlert('danger', 'Failed to check credential limits.');
            }
            if ($credential['type'] == 'custom' && $count >= $limits['custom_credential_limit']) {
                return $this->buildAlert('danger', "You can only have upto {$limits['custom_credential_limit']} custom credentials.");
            } elseif ($credential['type'] == 'enduser' && $count >= $limits['enduser_credential_limit']) {
                return $this->buildAlert('danger', "You can only have upto {$limits['enduser_credential_limit']} custom credentials.");
            } elseif ($credential['type'] == 'enduser' && $count == 0 && !$this->admin) {
                return $this->buildAlert('danger', 'You are not authorized to add enduser credentials.');
            }
        } elseif ($credential['type'] != 'custom' && $credential['type'] != 'enduser' && !$this->admin) {
            return $this->buildAlert('danger', 'You are not authorized to add managed credentials.');
        }
        unset($credential['cred_id']);
        $insert = $this->insertCredential($credential);
        if (!$insert) {
            return $this->buildAlert('danger', 'Failed to insert new credential.');
        }
        return $this->buildAlert('success', 'A new credential was added.');
    }

    function modifyCredential($client_id, $data)
    {
        if (!$this->checkCSRF($data['token'])) {
            return $this->buildAlert('danger', 'Invalid CSRF token. Check if you have multiple windows open.');
        }
        $credential = $this->validateCredential($client_id, $data);
        if (!is_array($credential)) {
            return $credential;
        }
        $existing_credential = $this->getCredential($client_id, $credential['cred_id']);
        if (!$existing_credential) {
            return $this->buildAlert('danger', 'Credential does not exist, or you are not authorized to modify it.');
        }
        $update = $this->updateCredential($credential);
        if (!$update) {
            return $this->buildAlert('danger', 'Failed to update credential.');
        }
        return $this->buildAlert('success', 'Updated credential.');
    }

    function removeCredential($client_id, $data)
    {
        if (!$this->checkCSRF($data['token'])) {
            return $this->buildAlert('danger', 'Invalid CSRF token. Check if you have multiple windows open.');
        }
        $cred_id = $this->sanitizeInt($data['cred_id']);
        if (!$cred_id) {
            return $alert = $this->buildAlert('danger', 'Invalid credential ID.');
        }
        $credential = $this->getCredential($client_id, $cred_id);
        if (!$credential) {
            return $this->buildAlert('danger', 'Credential does not exist, or you are not authorized to delete it.');
        }
        $delete = $this->deleteCredential($client_id, $cred_id);
        if (!$delete) {
            return $this->buildAlert('danger', 'Failed to delete credential.');
        }
        return $this->buildAlert('success', 'Deleted credential.');
    }

    function requestUnlock($client_id, $post)
    {
        if (!$this->checkCSRF($post['token'])) {
            return $this->buildAlert('danger', 'Invalid CSRF token. Check if you have multiple windows open.');
        }
        return $this->requestPrivateKey($client_id, $post['unlock_key']);
    }

    function requestUnlockKey($client_id)
    {
        if (!$this->checkCSRF($data['token'])) {
            return $this->buildAlert('danger', 'Invalid CSRF token. Check if you have multiple windows open.');
        }
        $request = [
            'origin' => 'whmcs',
            'secret' => $this->keyserver_secret,
            'request' => 'unlock_key',
            'client_id' => $client_id,
            'client_ip' => $this->getClientIP(),
            'whmcs_url' => "https://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}"
        ];
        $response = $this->postKeyserver($request);
        if ($response === false) {
            return $this->buildAlert('danger', 'Failed to request unlock key');
        }
        if (strpos($response, 'Error!') !== false) {
            return $this->buildAlert('danger', $response);
        }
        return $this->buildAlert('success', $response);
    }

    function requestPublicKey($client_id)
    {
        $wrapper_keys = $this->getWrapperKeys();
        $request = [
            'origin' => 'whmcs',
            'secret' => $this->keyserver_secret,
            'request' => 'public_key',
            'client_id' => $client_id,
            'client_email' => $this->getClientEmail($client_id),
            'wrapper_key' => $wrapper_keys->public_key
         ];
        $response = $this->postKeyserver($request);
        if (strpos($response, 'Error!') !== false) {
            return $response;
        }
        $public_key = $this->decrypt($response, $wrapper_keys->private_key);
        return $public_key;
    }

    function requestPrivateKey($client_id, $unlock_key)
    {
        $client_private_key = "client_{$client_id}_private_key";
        $wrapper_keys = $this->getWrapperKeys();
        $request = [
            'origin' => 'whmcs',
            'secret' => $this->keyserver_secret,
            'request' => 'private_key',
            'unlock_key' => $unlock_key,
            'wrapper_key' => $wrapper_keys->public_key
         ];
        $response = $this->postKeyserver($request);
        if ($response === false) {
            return $this->buildAlert('danger', 'Failed to request private key');
        }
        if (strpos($response, 'Error!') !== false) {
            unset($_SESSION['cm_unlock_keys'][$client_id]);
            unset($this->$client_private_key);
            return $this->buildAlert('danger', str_replace('Error!', '', $response));
        }
        $private_key = $this->decrypt($response, $wrapper_keys->private_key);
        if (!$private_key) {
            return $this->buildAlert('danger', 'Failed to unwrap private key');
        }
        if (!array_key_exists('cm_unlock_keys', $_SESSION)) {
            $_SESSION['cm_unlock_keys'] = [];
        }
        $_SESSION['cm_unlock_keys'][$client_id] = $unlock_key;
        $this->$client_private_key = $private_key;
        return $this->buildAlert('success', 'Private key received, you can view unencrypted data until the key expires');
    }

    function buildAlert($type, $message)
    {
        if ($type == 'danger') {
            $title = 'Error';
        } else {
            $title = ucwords($type);
        }
        $alert .= "<div class=\"alert alert-{$type} alert-dismissible small\">\n";
        $alert .= "<a href=\"#\" class=\"close\" data-dismiss=\"alert\" aria-label=\"close\">&times;</a>\n";
        $alert .= "<strong>{$title}!</strong> {$message}\n";
        $alert .= "</div>";
        return $alert;
    }

    function buildUnlockStatus($client_id)
    {
        $vars = ['style' => 'success', 'icon' => 'lock', 'text' => 'Locked'];
        $client_private_key = "client_{$client_id}_private_key";
        if ($this->$client_private_key) {
            $vars = ['style' => 'warning', 'icon' => 'lock-open', 'text' => 'Unlocked'];
        }
        $status .= "<p class=\"text-center text-{$vars['style']} h3\">";
        $status .= "<i class=\"fa fa-lg fa-{$vars['icon']}\" aria-hidden=\"true\"></i>&nbsp;&nbsp;{$vars['text']}";
        $status .= "</p>";
        return $status;
    }

    function buildTable($credentials, $type, $schema)
    {
        $csrf = "&token={$this->getCSRF()}";
        if ($credentials->count()) {
            $csrf = '&token='.$this->getCSRF();
            $table .= "<table class=\"table table-hover small\">\n";
            $table .= "  <thead>\n";
            $table .= "    <tr>\n";
            foreach (array_keys($schema) as $title) {
                $table .= "      <th scope=\"col\">{$title}</th>\n";
            }
            $table .= "    </tr>\n";
            $table .= "  </thead>\n";
            $table .= "  <tbody>\n";
            foreach ($credentials as $credential) {
                $table .= "    <tr>\n";
                foreach ($schema as $field) {
                    if ($field == 'ssh_user' || $field == 'ssh_pswd' || $field == 'root_pswd') {
                        if (!empty($credential->$field)) {
                            $table .= "      <td><i class=\"fa fa-lock\" aria-hidden=\"true\"></i></td>\n";
                        } else {
                            $table .= "      <td>-</td>\n";
                        }
                    } elseif ($field == 'type') {
                        $type_field = explode('_', $credential->$field);
                        $type_field = implode('_', array_slice($type_field, 1));
                        $table .= "      <td>{$type_field}</td>\n";
                    } elseif ($field == 'ssh_key') {
                        if ($credential->ssh_key_user == 1 && $credential->ssh_key_root == 1) {
                            $ssh_key_field = 'both';
                        } elseif ($credential->ssh_key_user == 1) {
                            $ssh_key_field = 'user';
                        } elseif ($credential->ssh_key_root == 1) {
                            $ssh_key_field = 'root';
                        } else {
                            $ssh_key_field = '-';
                        }
                        $table .= "      <td>{$ssh_key_field}</td>\n";
                    } elseif ($field == 'ssh_port') {
                        if ($credential->$field == 0) {
                            $ssh_port_field = '';
                        } else {
                            $ssh_port_field = $credential->$field;
                        }
                        $table .= "      <td>{$ssh_port_field}</td>\n";
                    } elseif (is_array($field)) {
                        $table .= "      <td>";
                        if (in_array('modify', $schema['Actions'])) {
                            $table .= "<button class=\"btn btn-xs btn-primary\" onclick=\"loadModifyModal('id={$credential->cred_id}{$csrf}')\">View/Modify</button>&nbsp;&nbsp;";
                        }
                        if (in_array('delete', $schema['Actions'])) {
                            $table .= "<button class=\"btn btn-xs btn-danger\" onclick=\"loadDeleteModal('id={$credential->cred_id}{$csrf}')\">Delete</button>";
                        }
                        $table .= "      </td>\n";
                    } else {
                        $table .= "      <td>{$credential->$field}</td>\n";
                    }
                }
                $table .= "    </tr>\n";
            }
            $table .= "  </tbody>\n";
            $table .= "</table>\n";
        } else {
            $table = 'There are 0 credentials';
        }
        if (in_array('add', $schema['Actions'])) {
            $table .= "<br><button class=\"btn btn-medium btn-primary\" onclick=\"loadAddModal('type={$type}{$csrf}')\">Add a credential</button>";
        }
        return $table;
    }

    function buildCustomTable($client_id)
    {
        $credentials = $this->getCredentials($client_id, 'custom');
        $schema = [
            'Ticket/Reference' => 'ticket',
            'Hostname' => 'hostname',
            'IP Address' => 'ipaddr',
            'Created' => 'created_at',
            'Updated' => 'updated_at',
            'Actions' => ['modify', 'delete']
        ];
        if ($credentials->count() < $this->getCredentialLimits()['custom_credential_limit']) {
            $schema['Actions'][] = 'add';
        }
        return $this->buildTable($credentials, 'custom', $schema);
    }

    function buildManagedTable($client_id)
    {
        $credentials = $this->getCredentials($client_id, 'managed');
        $schema = [
            'Hostname' => 'hostname',
            'IP Address' => 'ipaddr',
            'Type' => 'type',
            'SSH User' => 'ssh_user',
            'SSH Pswd' => 'ssh_pswd',
            'SSH Key' => 'ssh_key',
            'SSH Port' => 'ssh_port',
            'Root Pswd' => 'root_pswd',
            'Actions' => ['modify']
        ];
        if ($this->admin) {
            $schema['Actions'][] = 'add';
            $schema['Actions'][] = 'delete';
        }
        return $this->buildTable($credentials, 'managed', $schema);
    }

    function buildRecurringTable($client_id)
    {
        $credentials = $this->getCredentials($client_id, 'recurring');
        $schema = [
            'Hostname' => 'hostname',
            'IP Address' => 'ipaddr',
            'Type' => 'type',
            'SSH User' => 'ssh_user',
            'SSH Pswd' => 'ssh_pswd',
            'SSH Key' => 'ssh_key',
            'SSH Port' => 'ssh_port',
            'Root Pswd' => 'root_pswd',
            'Actions' => ['modify']
        ];
        if ($this->admin) {
            $schema['Actions'][] = 'add';
            $schema['Actions'][] = 'delete';
        }
        return $this->buildTable($credentials, 'recurring', $schema);
    }

    function buildEnduserTable($client_id)
    {
        $credentials = $this->getCredentials($client_id, 'enduser');
        $schema = [
            'Ticket/Reference' => 'ticket',
            'Hostname' => 'hostname',
            'IP Address' => 'ipaddr',
            'Created' => 'created_at',
            'Updated' => 'updated_at',
            'Actions' => ['modify', 'delete']
        ];
        if ($credentials->count() >= 1 || $this->admin) {
            $schema['Actions'][] = 'add';
        }
        return $this->buildTable($credentials, 'enduser', $schema);
    }

    function buildMainModal($client_id, $data)
    {
        if (!$this->checkCSRF($data['token'])) {
            $body = 'Error! Invalid CSRF token.<br><br>';
            $body .= 'If this continues, try refreshing the page.<br>';
            $body .= 'Ensure you dont have multiple pages open at once.';
            die($body);
        }
        $cred_id = $this->sanitizeInt($data['id']);
        if ($data['action'] == 'modify' && $cred_id) {
            $existing_credential = $this->getCredential($client_id, $cred_id);
            if (!$existing_credential) {
                die('Error! Credential does not exist, or you are not authorized to view it.');
            }
            $credential = [
                'cred_id' => $cred_id,
                'ticket' => $existing_credential->ticket,
                'type' => $existing_credential->type,
                'hostname' => $existing_credential->hostname,
                'ipaddr' => $existing_credential->ipaddr,
                'ssh_user' => $existing_credential->ssh_user,
                'ssh_pswd' => $existing_credential->ssh_pswd,
                'ssh_port' => $existing_credential->ssh_port,
                'ssh_key_root' => $existing_credential->ssh_key_root,
                'ssh_key_user' => $existing_credential->ssh_key_user,
                'root_pswd' => $existing_credential->root_pswd,
                'notes' => $existing_credential->notes
            ];
            $client_private_key = "client_{$client_id}_private_key";
            if ($this->$client_private_key) {
                $encrypted = ['ssh_user', 'ssh_pswd', 'root_pswd', 'notes'];
                foreach ($encrypted as $field) {
                    if (!empty($credential[$field])) {
                        $credential[$field] = $this->decrypt($credential[$field], $this->$client_private_key);
                    }
                }
            }
        }
        if ($data['action'] == 'add') {
            $credential = [
                'cred_id' => '',
                'ticket' => '',
                'type' => $data['type'],
                'hostname' => '',
                'ipaddr' => '',
                'ssh_user' => '',
                'ssh_pswd' => '',
                'ssh_port' => '',
                'ssh_key_root' => '',
                'ssh_key_user' => '',
                'root_pswd' => '',
                'notes' => ''
            ];
        }
        // Never display encrypted data
        if (!empty($credential['ssh_user']) && !isset($this->$client_private_key)) {
            $credential['ssh_user'] = 'encrypted';
        }
        if (!empty($credential['ssh_pswd']) && !isset($this->$client_private_key)) {
            $credential['ssh_pswd'] = 'encrypted';
        }
        if (!empty($credential['root_pswd']) && !isset($this->$client_private_key)) {
            $credential['root_pswd'] = 'encrypted';
        }
        if (!empty($credential['notes']) && !isset($this->$client_private_key)) {
            $credential['notes'] = 'encrypted';
        }
        // Checkboxes should be ticked based on value
        if ($credential['ssh_key_user'] >= 1) {
            $credential['ssh_key_user'] = 'checked';
        }
        if ($credential['ssh_key_root'] >= 1) {
            $credential['ssh_key_root'] = 'checked';
        }
        // Prevent null SSH port appearing as 0
        if ($credential['ssh_port'] == 0) {
            $credential['ssh_port'] = '';
        }
        // Clients can only change hostname/ip address on custom and enduser
        $readonly = '';
        if ($credential['type'] != 'custom' && $credential['type'] != 'enduser' && !$this->admin) {
            $readonly = 'readonly';
        }
        if ($credential['type'] == 'custom' || $credential['type'] == 'enduser' || $data['action'] == 'modify') {
            $type_field = "<input type=\"hidden\" name=\"type\" value=\"{$credential['type']}\">";
        }
        // For admins populate a type list from DB
        if ($data['action'] == 'add' && $credential['type'] != 'custom' && $credential['type'] != 'enduser' && $this->admin) {
            if ($credential['type'] == 'managed') {
                $types = $this->getCredentialTypes('managed');
            } elseif ($credential['type'] == 'recurring') {
                $types = $this->getCredentialTypes('recurring');
            }
            $options = '';
            foreach(explode(',', $types) as $type) {
                $options .= "<option>{$data['type']}_{$type}</option>";
            }
            $type_field = <<<TYPE
            <div class="form-group row">
            <label for="type" class="col-sm-2 col-form-label">Type</label>
            <div class="col-sm-10">
            <select class="form-control" name="type">
            {$options}
            </select>
            </div>
            </div>
            TYPE;
        }
        $body = <<<BODY
        <form id="{$data['action']}Form" method="post" action="">
        <input type="hidden" name="action" value="{$data['action']}">
        <input type="hidden" name="cred_id" value="{$cred_id}">
        <input type="hidden" name="token" value="{$data['token']}">
        <div class="form-row">
        <div class="form-group col-md-6">
        <label for="hostname">Hostname</label>
        <input type="text" maxlength="50" {$readonly} class="form-control form-control-sm" name="hostname" value="{$credential['hostname']}">
        </div>
        <div class="form-group col-md-6">
        <label for="ipadddr">IP Address</label>
        <input type="text" maxlength="128" {$readonly} class="form-control form-control-sm" name="ipaddr" value="{$credential['ipaddr']}">
        </div>
        </div>
        <div class="form-row">
        <div class="form-group col-md-6">
        <label for="ssh_user">SSH User</label>
        <input type="text" maxlength="50" class="form-control form-control-sm" name="ssh_user" placeholder="Optional" value="{$credential['ssh_user']}">
        </div>
        <div class="form-group col-md-6">
        <label for="ssh_password">SSH Password</label>
        <input type="text" maxlength="100" class="form-control form-control-sm" name="ssh_pswd" placeholder="Optional" value="{$credential['ssh_pswd']}">
        </div>
        </div>
        <div class="form-row">
        <div class="form-group col-md-6">
        <label for="root_pswd">Root Password</label>
        <input type="text" maxlength="100" class="form-control form-control-sm" name="root_pswd" placeholder="Root Password" value="{$credential['root_pswd']}">
        </div>
        <div class="form-group col-md-6">
        <label for="ssh_port">SSH Port</label>
        <input type="text" maxlength="5" class="form-control form-control-sm" name="ssh_port" placeholder="SSH Port" value="{$credential['ssh_port']}">
        </div>
        </div>
        <div class="form-group row">
        <div class="col-sm-2"><label>SSH Key</label></div>
        <div class="col-sm-4">
        <div class="form-check">
        <input class="form-check-input" type="checkbox" id="ssh_key_root" name="ssh_key_root" value="1" {$credential['ssh_key_root']}>
        <label class="form-check-label" for="ssh_key">Enabled for Root</label>
        </div>
        </div>
        <div class="col-sm-4">
        <div class="form-check">
        <input class="form-check-input" type="checkbox" id="ssh_key_user" name="ssh_key_user" value="1" {$credential['ssh_key_user']}>
        <label class="form-check-label" for="ssh_key">Enabled for SSH User</label>
        </div>
        </div>
        </div>
        <div class="form-group row">
        <label for="ticket" class="col-sm-2 col-form-label">Ticket/Ref*</label>
        <div class="col-sm-10">
        <input type="text" maxlength="30" class="form-control form-control-sm" name="ticket" placeholder="Ticket or reference" value="{$credential['ticket']}">
        </div>
        </div>
        {$type_field}
        <div class="form-group row">
        <label for="notes" class="col-sm-2 col-form-label">Notes</label>
        <div class="col-sm-10">
        <textarea rows="5" maxlength="2000" class="form-control form-control-sm" name="notes" placeholder="Optional">{$credential['notes']}</textarea>
        <small class="form-text text-muted">*Ticket/reference is a mandatory field.<br>Changing an <strong>encrypted</strong> field replaces existing data.</small>
        </div>
        </div>
        </form>
        BODY;
        echo $body;
    }

    function buildDeleteModal($client_id, $data)
    {
        if (!$this->checkCSRF($data['token'])) {
            $body = 'Error! Invalid CSRF token.<br><br>';
            $body .= 'If this continues, try refreshing the page.<br>';
            $body .= 'Ensure you dont have multiple pages open at once.';
            die($body);
        }
        $cred_id = $this->sanitizeInt($data['id']);
        if (!$cred_id) {
            die('Invalid credential ID.');
        }
        $credential = $this->getCredential($client_id, $cred_id);
        if (!$credential) {
            die('Error! Credential does not exist, or you are not authorized to delete it');
        }
        $body = <<<BODY
        Are you sure you want to delete this credential?<br><br>
        <form id="deleteForm" method="post" action="">
        <input type="hidden" name="action" value="delete">
        <input type="hidden" name="cred_id" value="{$cred_id}">
        <input type="hidden" name="token" value="{$data['token']}">
        <div class="form-row">
        <div class="form-group col-md-6">
        <label for="hostname">Hostname</label>
        <input type="text" maxlength="50" readonly class="form-control form-control-sm" name="hostname" value="{$credential->hostname}">
        </div>
        </div>
        <div class="form-row">
        <div class="form-group col-md-6">
        <label for="hostname">Ticket/Reference</label>
        <input type="text" maxlength="50" readonly class="form-control form-control-sm" name="ticket" value="{$credential->ticket}">
        </div>
        </div>
        </form>
        BODY;
        echo $body;
    }

}
