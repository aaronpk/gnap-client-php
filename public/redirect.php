<?php
chdir(__DIR__.'/..');
require_once('vendor/autoload.php');

session_start();


$client = GNAPClient::create();

# verify the hash from the redirect
# https://www.ietf.org/archive/id/draft-ietf-gnap-core-protocol-09.html#section-4.2.3

$hashInput = $_SESSION['nonce']."\n"    # client nonce
  .$_SESSION['interact']['finish']."\n" # server nonce
  .$_GET['interact_ref']."\n"
  .$_ENV['GNAP_AS_ENDPOINT'];

$hash = base64_urlencode(hash('sha3-512', $hashInput, true));

if($hash != $_GET['hash']) {
  echo '<p>Error: hash did not match</p>';
  die();
}

$response = $client->post($_SESSION['continue']['uri'], [
  'interact_ref' => $_GET['interact_ref'],
], [
  'Authorization' => 'GNAP '.$_SESSION['continue']['access_token']['value'],
]);

if(isset($response['access_token'])) {

  $_SESSION['access_token'] = array_filter_recursive($response['access_token']);
  $_SESSION['subject']  = $response['subject'];
  $_SESSION['sub'] = GNAPClient::subject_id($response['subject']['sub_ids'], 'opaque')['id'];

  echo '<p>Success!</p>';
  echo '<p>Response from AS:</p>';
  echo '<pre>';
  print_r(array_filter_recursive($response));
  echo '</pre>';
  echo '<p><a href="/">Continue</a></p>';

} else {
  echo '<p>Error getting access token</p>';
  echo '<p><a href="/?logout">Start Over</a></p>';
  echo '<pre>';
  print_r($response);
  echo '</pre>';
}

