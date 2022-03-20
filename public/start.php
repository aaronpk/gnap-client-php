<?php
chdir(__DIR__.'/..');
require_once('vendor/autoload.php');

session_start();


$client = GNAPClient::create();

$_SESSION['nonce'] = bin2hex(random_bytes(10));



$response = $client->start([
  'interact' => [
    'start' => ['redirect'],
    'finish' => [
    	'method' => 'redirect',
    	'uri' => 'http://localhost:8080/redirect.php',
    	'nonce' => $_SESSION['nonce'],
    	'hash_method' => 'sha3',
    ],
  ],
  'access_token' => [
    'access' => [
      [
        'type' => 'api',
      ]
    ]
  ],
  "subject" => [
    "sub_id_formats" => [ "iss_sub", "opaque" ],
  ]
]);


if(isset($response['interact']['redirect'])) {

  echo '<p>Response from AS:</p>';
  echo "<pre>"; print_r(array_filter_recursive($response)); echo "</pre>";
  echo '<a href="'.$response['interact']['redirect'].'">Continue to AS</a>';

	$_SESSION['continue'] = $response['continue'];
  $_SESSION['interact'] = $response['interact'];

} else {
	echo "<p>Error starting transaction</p>";
	echo "<pre>"; print_r($response); echo "</pre>";
}

