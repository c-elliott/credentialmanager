<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file provides the Keyserver component which generates
* short-lived unlock keys and manages unique asymmetric
* keypairs for each client.
*
* This must be hosted on a seperate server to WHMCS,
* and the database file must not be accessible by
* the webserver.
*/

// Configure your Keyserver here
$settings = [
    'allow_whmcs_ips'    => ['xx.xx.xx.xx'],
    'allow_admin_ips'    => ['xx.xx.xx.xx'],
    'allow_whmcs_secret' => 'long-random-string-here-max-100-chars',
    'allow_admin_secret' => 'long-random-string-here-max-100-chars',
    'unlock_key_minutes' => 60,
    'unlock_email_from'  => 'noreply@keyserver.yourdomain.com',
    'database_file'      => '/var/keyserver/keyserver.db'
];

// Do not edit below this line

class Keyserver
{

    function __construct($settings)
    {
        $this->allow_whmcs_ips = $settings['allow_whmcs_ips'];
        $this->allow_admin_ips = $settings['allow_admin_ips'];
        $this->allow_whmcs_secret = $settings['allow_whmcs_secret'];
        $this->allow_admin_secret = $settings['allow_admin_secret'];
        $this->unlock_key_minutes = $settings['unlock_key_minutes'];
        $this->unlock_email_from = $settings['unlock_email_from'];
        $this->database_file = $settings['database_file'];
    }

    function initializeDatabase()
    {
        try {
            $db = new SQLite3($this->database_file, SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);
            $create_unlock_keys = $db->query(
                'CREATE TABLE IF NOT EXISTS "unlock_keys" (
                    "unlock_key" TEXT PRIMARY KEY NOT NULL,
                    "client_id" INTEGER NOT NULL,
                    "client_ip" TEXT NOT NULL,
                    "origin" TEXT NOT NULL,
                    "expires_at" TEXT NOT NULL)');
            $create_client_keypairs = $db->query(
                'CREATE TABLE IF NOT EXISTS "client_keypairs" (
                    "client_id" INTEGER PRIMARY KEY NOT NULL,
                    "client_email" TEXT NOT NULL,
                    "private_key" TEXT NOT NULL,
                    "public_key" TEXT NOT NULL,
                    "created_at" TEXT NOT NULL)');
        } catch (Exception $e) {
            die("Error! {$e->getMessage()}");
        }
        if (!$create_unlock_keys || !$create_client_keypairs) {
            die('Error! Unable to check/create database tables');
        }
        return $db;
    }

    function countUnlockKeys($client_id)
    {
        $query = $this->db->prepare(
            'SELECT count(unlock_key)
             FROM "unlock_keys"
             WHERE "client_id" = :client_id');
        $query->bindValue(':client_id', $client_id);
        $result = $query->execute()->fetchArray();
        return $result['count(unlock_key)'];
    }

    function getUnlockKeys()
    {
        $query = $this->db->prepare(
            'SELECT * FROM "unlock_keys"'
        );
        $unlock_keys = $query->execute();
        return $unlock_keys;
    }

    function getUnlockKey($unlock_key)
    {
        $query = $this->db->prepare(
            'SELECT *
             FROM "unlock_keys"
             WHERE "unlock_key" = :unlock_key'
        );
        $query->bindValue(':unlock_key', $unlock_key);
        $unlock_key = $query->execute()->fetchArray();
        return $unlock_key;
    }

    function getPublicKey($client_id)
    {
        $query = $this->db->prepare(
            'SELECT "public_key", "client_email"
             FROM "client_keypairs"
             WHERE "client_id" = :client_id'
        );
        $query->bindValue(':client_id', $client_id);
        $public_key = $query->execute()->fetchArray();
        return $public_key;
    }

    function getPrivateKey($client_id)
    {
        $query = $this->db->prepare(
            'SELECT "private_key"
             FROM "client_keypairs"
             WHERE "client_id" = :client_id'
        );
        $query->bindValue(':client_id', $client_id);
        $private_key = $query->execute()->fetchArray();
        return $private_key;
    }

    function deleteUnlockKey($unlock_key)
    {
        $query = $this->db->prepare(
            'DELETE FROM "unlock_keys"
             WHERE "unlock_key" = :unlock_key');
        $query->bindValue(':unlock_key', $unlock_key);
        $deleted = $query->execute();
        return $deleted;
    }

    function createUnlockKey($client_id, $client_ip, $origin)
    {
        $unlock_key = bin2hex(random_bytes(20));
        $expires_at = date('Y-m-d H:i:s', strtotime("{$this->unlock_key_minutes} minute"));
        $query = $this->db->prepare(
            'INSERT INTO "unlock_keys" (
                "unlock_key",
                "client_id",
                "client_ip",
                "origin",
                "expires_at")
             VALUES (
                :unlock_key,
                :client_id,
                :client_ip,
                :origin,
                :expires_at)'
        );
        $query->bindValue(':unlock_key', $unlock_key);
        $query->bindValue(':client_id', $client_id);
        $query->bindValue(':client_ip', $client_ip);
        $query->bindValue(':origin', $origin);
        $query->bindValue(':expires_at', $expires_at);
        $created = $query->execute();
        if (!$created) {
            return $created;
        }
        return $unlock_key;
    }

    function createKeypair($client_id, $client_email)
    {
        $private_key = sodium_crypto_box_keypair();
        $private_hex = sodium_bin2hex($private_key);
        $public_key = sodium_crypto_box_publickey($private_key);
        $public_hex = sodium_bin2hex($public_key);
        $query = $this->db->prepare(
            'INSERT INTO "client_keypairs" (
                "client_id",
                "client_email",
                "private_key",
                "public_key",
                "created_at")
            VALUES (
                :client_id,
                :client_email,
                :private_key,
                :public_key,
                :created_at)'
        );
        $query->bindValue(':client_id', $client_id);
        $query->bindValue(':client_email', $client_email);
        $query->bindValue(':private_key', $private_hex);
        $query->bindValue(':public_key', $public_hex);
        $query->bindValue(':created_at', date('Y-m-d H:i:s'));
        $result = $query->execute();
        return $result;
    }

    function updateKeypairEmail($client_id, $client_email)
    {
        $query = $this->db->prepare(
            'UPDATE "client_keypairs"
             SET "client_email" = :client_email
             WHERE "client_id" = :client_id');
        $query->bindValue(':client_id', $client_id);
        $query->bindValue(':client_email', $client_email);
        $result = $query->execute();
        return $result;
    }

    function validInput($array, $keys)
    {
        foreach ($keys as $key) {
            if (!array_key_exists($key, $array)) {
                return false;
            }
            if (empty($array[$key])) {
                return false;
            }
            if ($key == 'client_id' && !filter_var($array[$key], FILTER_VALIDATE_INT)) {
                return false;
            }
            if ($key == 'client_ip' && !filter_var($array[$key], FILTER_VALIDATE_IP)) {
                return false;
            }
            if ($key == 'client_email' && !filter_var($array[$key], FILTER_VALIDATE_EMAIL)) {
                return false;
            }
            if ($key == 'whmcs_url' && !filter_var($array[$key], FILTER_VALIDATE_URL)) {
                return false;
            }
        }
        return true;
    }

    function checkAuth($secret, $origin) {
        if ($origin == 'whmcs') {
            if ($secret == $this->allow_whmcs_secret &&
                in_array($_SERVER['REMOTE_ADDR'], $this->allow_whmcs_ips)) {
                return true;
            }
        }
        if ($origin == 'admin') {
            if ($secret == $this->allow_admin_secret &&
                in_array($_SERVER['REMOTE_ADDR'], $this->allow_admin_ips)) {
                return true;
            }
        }
        return false;
    }

    function wrapKey($wrapper_key, $key)
    {
        try {
            $wrapper_bin = sodium_hex2bin($wrapper_key);
            $wrapped_key = sodium_crypto_box_seal($key, $wrapper_bin);
            $wrapped_hex = sodium_bin2hex($wrapped_key);
        } catch (Exception $e) {
            return false;
        }
        if(empty($wrapped_hex)) {
            return false;
        }
        return $wrapped_hex;
    }

    function emailUnlockKey($unlock_key, $client_email, $client_ip, $whmcs_url)
    {
        $tnow = date('Y-m-d H:i:s');
        $subj = "Credential Manager Unlock Key";
        $head = "From: {$this->unlock_email_from}";
        $head .= "\nMIME-Version: 1.0\r\n";
        $head .= "Content-Type: text/html; charset=ISO-8859-1\r\n";
        $body = "<html>\n<body>\n<p>";
        $body .= "You are receiving this email because a Credential Manager ";
        $body .= "unlock key was requested.</p>\n";
        $body .= "<p>To view your decrypted credentials, login to Credential ";
        $body .= "Manager and click the \"Enter unlock key\" button at the top right, ";
        $body .= "then enter the unlock key provided below.</p>\n";
        $body .= "<p>This key will expire after {$this->unlock_key_minutes} minutes.</p>\n";
        $body .= "<h4>Unlock key</h4>\n";
        $body .= "<p>{$unlock_key}</p>\n";
        $body .= "<h4>Request details</h4>\n";
        $body .= "<p>URL: <a href=\"{$whmcs_url}\">{$whmcs_url}</a><br>";
        $body .= "IP Address: {$client_ip}<br>";
        $body .= "Timestamp: {$tnow} UTC<br>";
        $body .= "</p>\n";
        $body .= "<p>If these details do not look correct, please contact your server management provider.</p>\n";
        $body .= "<p>Thank You</p>\n</body>\n</html>";
        $body = wordwrap($body, 70);
        return mail($client_email, $subj, $body, $head, "-f {$this->unlock_email_from}");
    }

    function requestEmailChange($client_id, $client_email)
    {
        $public_key = $this->getPublicKey($client_id);
	    if (!$public_key) {
	        return "Error! Keypair does not exist for this client. Nothing to change\n";
	    }
	    $current_email = $public_key['client_email'];
	    $updated = $this->updateKeypairEmail($client_id, $client_email);
	    if (!$updated) {
            echo "Error! Failed to update client email\n";
	    }
	return "Updated email for client id {$client_id} {$current_email} --> {$client_email}\n";
    }

    function requestUnlockKey($origin, $client_id, $client_ip, $whmcs_url)
    {
        $public_key = $this->getPublicKey($client_id);
        if (!$public_key) {
	        return "Error! Keypair does not exist for this client, add some data first.\n";
        }
        $count = $this->countUnlockKeys($client_id);
        if ($count >= 10) {
            return "Error! {$count} unlock keys already exist for client id {$client_id}\n";
        }
        $unlock_key = $this->createUnlockKey($client_id, $client_ip, $origin);
        if (!$unlock_key) {
            return "Error! Failed to create unlock key\n";
        }
        if ($origin == 'whmcs') {
            $email_sent = $this->emailUnlockKey($unlock_key, $public_key['client_email'], $client_ip, $whmcs_url);
            if ($email_sent) {
                return "Unlock key sent to {$public_key['client_email']}. Want to change this? Please contact support.\n";
            }
            return "Error! Failed to send unlock key to {$public_key['client_email']}\n";
        } else {
            return "{$unlock_key}\n";
        }
    }

    function requestPublicKey($client_id, $client_email, $wrapper_key)
    {
        $public_key = $this->getPublicKey($client_id);
        if (!$public_key) {
		    $created = $this->createKeypair($client_id, $client_email);
            if ($created) {
                $public_key = $this->getPublicKey($client_id);
            } else {
                return "Error! Failed to create client keypair\n";
            }
	    }
        if ($client_email != $public_key['client_email']) {
            return "Error! Your current email address {$client_email} does not match your keypair {$public_key['client_email']}. Please contact support.\n";
        }
        $wrapped_public_key = $this->wrapKey($wrapper_key, $public_key['public_key']);
        if (!$wrapped_public_key || empty($wrapped_public_key)) {
            return "Error! Failed to wrap public key\n";
        }
        return $wrapped_public_key;;
    }

    function requestPrivateKey($unlock_key, $wrapper_key)
    {
        $unlock_key = $this->getUnlockKey($unlock_key);
        if (!$unlock_key) {
            return "Error! Unlock key invalid or has expired\n";
        }
        $time_now = date('Y-m-d H:i:s');
        if ($time_now >= $unlock_key['expires_at']) {
            return "Error! Unlock key expired at {$unlock_key['expires_at']}\n";
        }
        $private_key = $this->getPrivateKey($unlock_key['client_id']);
        if (!$private_key) {
            return "Error! Failed to get private key\n";
        }
        $wrapped_private_key = $this->wrapKey($wrapper_key, $private_key[0]);
        if (!$wrapped_private_key) {
            return "Error! Failed to wrap private key\n";
        }
        return $wrapped_private_key;
    }

    function showUnlockKeys()
    {
        $unlock_keys = $this->getUnlockKeys();
        $keys = '';
        while ($unlock_key = $unlock_keys->fetchArray()) {
            $keys .= "".str_repeat('-', 52)."\n";
            $keys .= "unlock_key: {$unlock_key['unlock_key']}\n";
            $keys .= "client_id:  {$unlock_key['client_id']}\n";
            $keys .= "client_ip:  {$unlock_key['client_ip']}\n";
            $keys .= "origin:     {$unlock_key['origin']}\n";
            $keys .= "expires_at: {$unlock_key['expires_at']}\n";
        }
        if ($keys == '') {
            return "Failed to retrieve unlock keys, or none exist\n";
        }
        return $keys;
    }

    function purgeUnlockKeys()
    {
        $unlock_keys = $this->getUnlockKeys();
        if (!$unlock_keys) {
            return "Failed to retrieve unlock keys, or none exist\n";
        }
        $purge = false;
        $result = '';
        while ($unlock_key = $unlock_keys->fetchArray()) {
            if (date('Y-m-d H:i:s') >= $unlock_key['expires_at']) {
                $purge = true;
                $deleted = $this->deleteUnlockKey($unlock_key['unlock_key']);
                if (!$deleted) {
                    return "Failed to purge {$unlock_key['unlock_key']} expired {$unlock_key['expires_at']}\n";
                }
                $result .= "Purged {$unlock_key['unlock_key']} expired {$unlock_key['expires_at']}\n";
            }
        }
        if (!$purge) {
            return "Nothing to purge. All unlock keys valid within {$this->unlock_key_minutes} minute(s)\n";
        }
        return $result;
    }

    function postHandler($post)
    {
        if (!$this->validInput($post, ['secret', 'origin', 'request'])) {
            die('Error! Malformed request');
        }
        if (!$this->checkAuth($post['secret'], $post['origin'])) {
            die ('Error! Unauthorized');
        }

        $this->db = $this->initializeDatabase();
        $result = false;

        if ($post['request'] == 'update_email' && $post['origin'] == 'admin') {
	    if ($this->validInput($post, ['client_id', 'client_email'])) {
	        $result = $this->requestEmailChange($post['client_id'], $post['client_email']);
            }
        }

        if ($post['request'] == 'unlock_key') {
            if ($this->validInput($post, ['client_id', 'client_ip', 'whmcs_url'])) {
                $result = $this->requestUnlockKey($post['origin'], $post['client_id'],
                    $post['client_ip'], $post['whmcs_url']);
            }
        }

        if ($post['request'] == 'public_key' && $post['origin'] == 'whmcs') {
            if ($this->validInput($post, ['client_id', 'client_email', 'wrapper_key'])) {
                $result = $this->requestPublicKey($post['client_id'], $post['client_email'], $post['wrapper_key']);
            }
        }

        if ($post['request'] == 'private_key' && $post['origin'] == 'whmcs') {
            if ($this->validInput($post, ['unlock_key', 'wrapper_key'])) {
                $result = $this->requestPrivateKey($post['unlock_key'], $post['wrapper_key']);
            }
        }

        if ($post['request'] == 'show_unlock_keys' && $post['origin'] == 'admin') {
            $result = $this->showUnlockKeys();
        }

        if ($post['request'] == 'purge_unlock_keys' && $post['origin'] == 'admin') {
            $result = $this->purgeUnlockKeys();
        }

        if ($result) {
            echo $result;
        } else {
            echo "Error! Invalid request\n";
        }

        $this->db->close();
    }

}

if (!http_response_code() && $argc > 1) {
    if ($argv[1] == 'purge') {
        $ks = new Keyserver($settings);
        $ks->db = $ks->initializeDatabase();
        echo $ks->purgeUnlockKeys();
        $ks->db->close();
    }
} elseif (array_key_exists('REQUEST_SCHEME', $_SERVER)) {
    if ($_SERVER['REQUEST_SCHEME'] == 'https' && $_POST) {
        $ks = new Keyserver($settings);
        $ks->postHandler($_POST);
    }
}
