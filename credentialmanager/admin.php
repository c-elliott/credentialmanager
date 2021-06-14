<?php
/*
* WHMCS Credential Manager
* Copyright (c) 2020 Chris Elliott
*
* This software is licensed under the terms of the MIT License.
* https://github.com/c-elliott/credentialmanager/LICENSE
*
* This file provides the Admin page and is included
* by the WHMCS module.
*/

if (!defined("WHMCS")) {
  die("This file cannot be accessed directly");
}

if (
  $_SERVER['HTTPS'] != 'on' ||
  $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'http'
) {
  $url = "https://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
  header('HTTP/1.1 301 Moved Permanently');
  header("Location: {$url}");
  exit;
}

require 'core.php';
$cm = new CredentialManager();
$cm->admin = true;

if ($_GET) {
    if (array_key_exists('client_id',  $_GET)) {
        $client_id = $_GET['client_id'];
        $client_name_db = $cm->getClientName($client_id);
        $client_name = "({$client_name_db->firstname} {$client_name_db->lastname})";
    } else {
        $client_id = 'None';
        $client_name = '';
    }
    if ($_GET['action'] == 'add' || ($_GET['action'] == 'modify')) {
        $cm->buildMainModal($client_id, $_GET);
        exit;
    } elseif ($_GET['action'] == 'delete') {
        $cm->buildDeleteModal($client_id, $_GET);
        exit;
    }
    unset($_GET);
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
            $alert = $cm->requestUnlockKey($client_id, $_POST);
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
    header("Location: addonmodules.php?module=credentialmanager&client_id={$client_id}");
}

if ($_SESSION['page_refresh_count'] >= 2) {
    unset($_SESSION['page_refresh_count']);
    unset($_SESSION['alert']);
} else {
    $_SESSION['page_refresh_count']++;
}

$csrf_token = $cm->getCSRF();
$unlock_status = $cm->buildUnlockStatus($client_id);
$alert_pill = $_SESSION['alert'];

if ($client_id == 'None') {
    $custom_limit = 0;
    $custom_count = 0;
    $custom_table = '';
    $managed_count = 0;
    $managed_table = '';
    $recurring_count = 0;
    $recurring_table = '';
    $enduser_count = 0;
    $enduser_limit = 0;
    $enduser_table = '';
} else {
    $limits = $cm->getCredentialLimits();
    $custom_limit = $limits['custom_credential_limit'];
    $custom_count = $cm->countCredentials($client_id, 'custom');
    $custom_table = $cm->buildCustomTable($client_id);
    $managed_count = $cm->countCredentials($client_id, 'managed');
    $managed_table = $cm->buildManagedTable($client_id);
    $recurring_count = $cm->countCredentials($client_id, 'recurring');
    $recurring_table = $cm->buildRecurringTable($client_id);
    $enduser_count = $cm->countCredentials($client_id, 'enduser');
    $enduser_limit = $limits['enduser_credential_limit'];
    $enduser_table = $cm->buildEnduserTable($client_id);
}

$body = <<<BODY
<div class="card text-white bg-dark">
  <div class="card-body">
    <div class="container">
      <div class="row">
        <div class="col-sm-9">
          <h1 class="text-white">Selected Client ID: {$client_id} {$client_name}</h1>
          <p>Use KeyCLI to generate an unlock token for this client if needed.</p>
        </div>
        <div class="col">
          <div class="row m-1">
            <button type="button" class="btn btn-block btn-sm btn-secondary" data-toggle="modal" data-target="#unlockModal">Enter an unlock key</button>
          </div>
          <br>
          {$unlock_status}
        </div>
      </div>
    </div>
  </div>
</div>
{$alert_pill}

<div class="card">
  <div class="card-header text-white bg-dark">
    <i class="fa fa-clock" aria-hidden="true"></i> Custom (Limited Time) [{$custom_count}/{$custom_limit}]
  </div>
  <div class="card-body">
    <p>Add upto {$custom_limit} temporary credentials, if they are not updated after 14 days they will be automatically deleted.</p>
    {$custom_table}
  </div>
</div>

<div class="card">
  <div class="card-header text-white bg-dark">
    <i class="fa fa-cloud" aria-hidden="true"></i> Managed Servers [{$managed_count}]
  </div>
  <div class="card-body">
  {$managed_table}
  </div>
</div>


<div class="card">
  <div class="card-header text-white bg-dark">
    <i class="fa fa-server" aria-hidden="true"></i> Recurring Server Management [{$recurring_count}]
  </div>
  <div class="card-body">
  {$recurring_table}
  </div>
</div>

<div class="card">
  <div class="card-header text-white bg-dark">
    <i class="fa fa-user" aria-hidden="true"></i> End User Support [{$enduser_count}/{$enduser_limit}]
  </div>
  <div class="card-body">
  {$enduser_table}
  </div>
</div>

<div class="modal fade" id="unlockModal" tabindex="-1" aria-labelledby="unlockModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="unlockModalLabel">Enter an unlock key</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"></button>
      </div>
      <div id="unlockBody" class="modal-body">
        <form id="unlockForm" method="post" action="">
        <input type="hidden" name="action" value="unlock">
        <!-- whmcs automatically adds the above csrf token -->
        <textarea rows="5" maxlength="100" class="form-control form-control-sm" name="unlock_key" placeholder="Paste key here"></textarea>
        </form>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary" id="unlockSubmit">Unlock</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="addModal" tabindex="-1" aria-labelledby="addModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="addModalLabel">Add Credential</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"></button>
      </div>
      <div id="addBody" class="modal-body">
        <!-- Populated on demand -->
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary" id="addSubmit">Add Credential</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="modifyModal" tabindex="-1" aria-labelledby="modifyModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="modifyModalLabel">Modify Credential</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"></button>
      </div>
      <div id="modifyBody" class="modal-body">
        <!-- Populated on demand -->
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
        <button type="button" class="btn btn-primary" id="modifySubmit">Save Changes</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="deleteModalLabel">Delete Credential</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"></button>
      </div>
      <div id="deleteBody" class="modal-body">
        <!-- Populated on demand -->
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
        <button type="button" class="btn btn-danger" id="deleteSubmit">Delete Credential</button>
      </div>
    </div>
  </div>
</div>

<script>
function loadAddModal(modal) {
    $('#addBody').load('addonmodules.php?module=credentialmanager&client_id={$client_id}&action=add&' + modal,function() {
        $('#addModal').modal({
                        show : true});
    });
}

function loadModifyModal(modal) {
    $('#modifyBody').load('addonmodules.php?module=credentialmanager&client_id={$client_id}&action=modify&' + modal,function() {
        $('#modifyModal').modal({
			show : true});
    });
}

function loadDeleteModal(modal) {
    $('#deleteBody').load('addonmodules.php?module=credentialmanager&client_id={$client_id}&action=delete&' + modal,function() {
        $('#deleteModal').modal({
                        show : true});
    });
}

$(function() {
    $('#unlockSubmit').on('click', function(e) {
        $('#unlockForm').submit();
    });
});

$(function() {
    $('#addSubmit').on('click', function(e) {
        $('#addForm').submit();
    });
});

$(function() {
    $('#modifySubmit').on('click', function(e) {
        $('#modifyForm').submit();
    });
});

$(function() {
    $('#deleteSubmit').on('click', function(e) {
        $('#deleteForm').submit();
    });
});
</script>
BODY;

if ($client_name_db === NULL) {
    $body = <<<BODY
    Hello Admins!<br><br>
    You must select a valid client to see something useful here.<br><br>
    Options:<br>
    - Use Advanced Search on the left sidebar, then click "Credential Manager" under "Other Actions"<br>
    - View a support ticket, then click "Open Client" on the left sidebar<br>
    - View a client, then use the "Login as user" option, then go to Support > Credential Manager
    BODY;
}
