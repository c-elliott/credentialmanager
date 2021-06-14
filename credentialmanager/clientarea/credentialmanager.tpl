<div class="card text-white bg-dark">
  <div class="card-body">
    <div class="container">
      <div class="row">
        <div class="col-sm-9">
          <h3>Credential Manager&nbsp;&nbsp;<small class="text-muted"><strong>encrypt</strong> your data</small></h3>
          <p>Use this tool to store and share server login details or other sensitive information with us. All <strong>usernames</strong>, <strong>passwords</strong> and <strong>notes</strong> are encrypted with a keypair unique to your account. To decrypt, click the button on the right and a limited-time key will be emailed to you.
        </div>
        <div class="col">
          <form class="m-1" id="requestKeyForm" method="post" action="">
          <!-- whmcs automatically adds the above csrf token -->
          <input type="hidden" name="action" value="requestkey">
          <button type="submit" class="btn btn-block btn-sm btn-secondary" id="requestKeyForm">Request unlock key</button>
          </form>
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
    $('#addBody').load('credentialmanager.php?action=add&' + modal,function() {
        $('#addModal').modal({
                        show : true});
    });
}

function loadModifyModal(modal) {
    $('#modifyBody').load('credentialmanager.php?action=modify&' + modal,function() {
        $('#modifyModal').modal({
			show : true});
    });
}

function loadDeleteModal(modal) {
    $('#deleteBody').load('credentialmanager.php?action=delete&' + modal,function() {
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