<?php
require('vendor/autoload.php');

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;

# Generate an EC256 key:
# openssl ecparam -genkey -name prime256v1 -noout -out ec256-key.pem

$keyFilename = 'ec256-key.pem';

$jwk = JWKFactory::createFromKeyFile($keyFilename);
$kid = $keyFilename;


$txEndpoint = 'http://host.docker.internal:9834/api/as/transaction';


$request = [
  'client' => [
    'key' => [
      'proof' => 'jwsd',
      'jwk' => $jwk->toPublic()
    ],
    'display' => [
      'name' => 'PHP CLI',
    ],
  ],
  'access_token' => [
    'label' => 'token1',
    'acecss' => ['foo'],
  ],
  'interact' => [
    'redirect' => true,
    'user_code' => true,
  ],
];

$public = $jwk->toPublic()->all();
$public['kid'] = $kid;


$response = signedRequest($txEndpoint, json_encode($request));

if(isset($response['interact'])) {
  echo "Please open this URL in your browser to authorize the application\n";
  echo $response['interact']['redirect']."\n";


  $tokenResponse = null;

  $continue = $response['continue'];
  while($continue && !isset($response['access_token'])) {
    echo "Polling: ".$continue['uri']." with AT ".$continue['access_token']['value']."\n";
    $tokenResponse = signedRequest($continue['uri'], '', $continue['access_token']['value']);
    sleep(1);
    $continue = $tokenResponse['continue'] ?? false;
  }

  print_r($tokenResponse);

}



function signedRequest($url, $body, $accessToken=null) {
  global $jwk, $kid;

  $jwsHeader = [
    'b64' => false,
    'crit' => ['b64'],
    'alg' => 'ES256',
    'kid' => $kid,
    'htu' => $url,
    'htm' => 'POST',
  ];

  if($accessToken) {
    $jwsHeader['at_hash'] = base64_url_encode(hash('sha256', $accessToken, true));
  }

  $algorithmManager = new AlgorithmManager([
      new ES256(),
  ]);

  $jwsBuilder = new JWSBuilder($algorithmManager);
  $jws = $jwsBuilder->create()
    ->withPayload($body)
    ->addSignature($jwk, $jwsHeader)
    ->build();

  $serializer = new CompactSerializer();
  $token = $serializer->serialize($jws);

  $header = substr($token, 0, strpos($token, '.'));
  $signature = substr($token, strrpos($token, '.')+1);

  $detachedJWS = $header . ".." . $signature;

  $headers = [
    'Content-Type: application/json',
    'Detached-JWS: ' . $detachedJWS,
  ];

  if($accessToken) {
    $headers[] = 'Authorization: GNAP ' . $accessToken;
  }

  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
  $response = curl_exec($ch);
  #echo "Response code " . curl_getinfo($ch, CURLINFO_HTTP_CODE) . "\n";
  return json_decode($response, true);
}

function base64_url_encode($binary_data) {
  return strtr(rtrim(base64_encode($binary_data), '='), '+/', '-_');
}
