# Credential Manager

## Introduction
Credential Manager is a WHMCS module designed to share login credentials and other sensitve information between clients and admins. This scenario requires reversible encryption, which most solutions implement by storing a private or symmetric key on the same server as WHMCS where the data resides. This vulnerability is addressed by using an external source of asymmetric keypairs, and requires a manual exchange of a short-lived "unlock key" to permit retrieval of private keys for decryption.

It consists of 3 components: WHMCS module, Keyserver and KeyCLI.

Refer to the **examples** directory for screenshots of the module and major data flows.

## Main Features
- Custom, managed, recurring and enduser credential types
- Configurable limit on number of custom and enduser credentials
- Any client can add short-term custom credentials
- Custom credentials are automatically deleted after 14 days since the last update
- A client can only add enduser credentials when at least 1 has been added by an admin
- Managed and recurring credential types can only be added by admins
- Clients cannot change hostnames or IP's of managed and recurring credentials
- Clients can request an "unlock key" sent by email to view their unencrypted data
- Admins can request a client "unlock key" from an authorized system using KeyCLI

## Security Features
- Enforced SSL, Input validation, CSRF protection, SQL parameter binding
- Usernames, passwords and notes are encrypted in the WHMCS database using libsodium (NaCl)
- Each client has a unique asymmetric keypair, not based on any master hash / static value
- WHMCS can only send unlock keys to the email address associated with a keypair
- Email addresses associated with keypairs can only be updated by admins using KeyCLI
- Client keypairs are provided by a remote Keyserver, never stored in session data or on disk on WHMCS
- All keys returned from Keyserver to Credential Manager are wrapped with a public key provided by Credential Manager
- Keyserver stores all client keypairs in a standalone SQLite3 database
- Keyserver authorizes requests based on IP and secret values

## Requirements (As tested)

- Three servers (1x, WHMCS, 1x Keyserver, 1x KeyCLI)
- PHP 7.x with SQLite3, libsodium, curl_exec enabled
- WHMCS 8.x with twenty-one theme
- Mailserver ons system running Keyserver

## Installation

Setup is quite simple, the code takes care of creating database tables and the wrapper keypair on WHMCS side.

1. Upload keyserver.php on a server not hosting WHMCS.
2. Edit the file and update settings, use a different secret for whmcs and admin (Max 100 chars).
```
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
```
4. Make sure the database file will not be exposed to the internet, it should be outside documentroot.
5. Add a cronjob to purge expired tokens, this should run at least every 5 minutes.
```
*/5 * * * * php -q <webserver-root>/keyserver.php purge
```
5. With Keyserver setup, you should now have a URL like https://keyserver.yourserver.com/keyserver.php
6. Copy the credentialmanager directory to addon/modules/credentialmanager within your WHMCS install.
7. Go to your WHMCS admin page, then system settings at the top right and find "Addon Modules".
8. Select "activate" next to Credential Manager in the list.
9. If successful, click on configure next to Credential Manager.
10. Update the Keyserver URL with the link you prepared earlier, and update the other settings as desired.
11. Add a cronjob to automatically remove custom credentials after 14 days of inactivity
```
*/5 * * * * php -q <whmcs-root>/modules/addons/credentialmanager/purge_custom_credentials.php
```
12. Copy keycli.sh script to your 3rd server for admins to create unlock tokens
13. Edit keycli.sh and enter the keyserver url and secrets you created earlier
```
# Settings
KEYSERVER_URL="https://keyserver.yourdomain.com/keyserver.php"
KEYSERVER_SECRET="long-random-string-here-max-100-chars"
REQUEST_ORIGIN="admin" # <-- admin or whmcs
TEST_EMAIL="you@yourdomain.com"
WRAPPER_PUBLIC_KEY="" # <-- only required for whmcs testing
```
14. Ready to test! Note that WHMCS updates may restore the changes required to the admin theme for the admin page to display correctly. A script "fix_admin_theme.php" is included in the module directory as a workaround.

## License

The MIT License (MIT)

Copyright (c) 2020 Chris Elliott

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.