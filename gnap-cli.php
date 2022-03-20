<?php
require('vendor/autoload.php');

use phpseclib3\Crypt\RSA;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\JWK;

if(!isset($argv[1])) {
  echo "usage: php sig.php action\n";
  die(1);
}

$redis = new \Predis\Client();
$redis->connect();

switch($argv[1]) {

  case 'keygen':
    $private = RSA::createKey();
    $public = $private->getPublicKey();

    echo (string)$private."\n";
    echo (string)$public."\n";

    file_put_contents($_ENV['PRIVATE_KEY_FILENAME'], $private);
    file_put_contents($_ENV['PUBLIC_KEY_FILENAME'], $public);

    $jwk = JWKFactory::createFromKeyFile($_ENV['PRIVATE_KEY_FILENAME']);
    $publicJSON = json_encode($jwk->toPublic()->all(), JSON_PRETTY_PRINT+JSON_UNESCAPED_SLASHES);
    file_put_contents($_ENV['JWK_FILENAME'], $publicJSON);

    break;

  case 'start':
    
    $client = GNAPClient::create();

    $response = $client->start([
      'interact' => [
        'start' => ['redirect']
      ],
      'access_token' => [
        'access' => [
          [
            'type' => 'api',
          ]
        ]
      ],
      // "subject" => [
      //   "sub_id_formats" => [ "iss_sub", "opaque" ],
      // ]
    ]);
    
    if(isset($response['interact']['redirect'])) {
      echo "Visit this URL in your browser:\n";
      echo $response['interact']['redirect']."\n";
      
      $redis->setex('gnap-interaction', 86400, json_encode($response));
    }
    
    break;

  case 'poll':
    
    $pending = json_decode($redis->get('gnap-interaction'), true);
    
    if(!$pending) {
      die("No interaction pending\n");
    }
    
    $client = GNAPClient::create();
    
    $response = $client->post($pending['continue']['uri'], null, [
      'Authorization' => 'GNAP '.$pending['continue']['access_token']['value'],
    ]);
    
    $redis->setex('gnap-interaction', 86400, json_encode($response));
    
    break;
  
  default:
    die("unknown command\n");

}

