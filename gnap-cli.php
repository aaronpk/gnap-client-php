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
    [
      'label' => 'token1',
      'access' => ['foo'],
    ],
    [
      'label' => 'token2',
      'access' => ['bar'],
    ]
  ],
  'interact' => [
    'start' => ['redirect', 'user_code' ]
  ],
];

$public = $jwk->toPublic()->all();
$public['kid'] = $kid;


$response = signedRequest($txEndpoint, json_encode($request));

if(isset($response['interact'])) {
  echo "Please open this URL in your browser to authorize the application\n";
  echo $response['interact']['redirect']."\n";

  print_r($response);

  #readline("Press enter to continue");

  $tokenResponse = null;

  $continue = $response['continue'];
  while($continue && !isset($response['access_token'])) {
    echo "Polling: ".$continue['uri']." with AT ".$continue['access_token']['value']."\n";
    $response = signedRequest($continue['uri'], '', $continue['access_token']['value']);
    print_r($response);

    #readline("Press enter to continue");
    sleep(1);
    $continue = $response['continue'] ?? false;
  }

  print_r($response);

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
    $hash = hash('sha256', $accessToken, true);
    $jwsHeader['at_hash'] = base64_url_encode(substr($hash, 0, strlen($hash) / 2));
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

  echo "Making request: $url\n";
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
  $response = curl_exec($ch);
  echo "Response code " . curl_getinfo($ch, CURLINFO_HTTP_CODE) . "\n";
  return json_decode($response, true);
}

function base64_url_encode($binary_data) {
  return strtr(rtrim(base64_encode($binary_data), '='), '+/', '-_');
}
