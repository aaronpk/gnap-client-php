<?php
require('vendor/autoload.php');

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;

$keyFilename = 'ec256-key.pem';

$jwk = JWKFactory::createFromKeyFile($keyFilename);
$kid = $keyFilename;


$txEndpoint = 'https://xyz-as.herokuapp.com/api/as/transaction';


$request = [
  'client' => [
    'key' => [
      'proof' => 'jwsd',
      'jwk' => $jwk->toPublic()->all()
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
    'start' => ['redirect', 'user_code']
  ],
];

$public = $jwk->toPublic()->all();
$public['kid'] = $kid;
$request['client']['key']['jwk']['kid'] = $kid;

$response = signedRequest($txEndpoint, json_encode($request));

if(isset($response['interact'])) {
  echo "Please open this URL in your browser to authorize the application\n";
  echo $response['interact']['redirect']."\n";

  print_r($response);

  readline("Press enter to continue");

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

  // https://datatracker.ietf.org/doc/html/draft-ietf-gnap-core-protocol#section-7.3.3
  $jwsHeader = [
    'kid' => $kid,
    'alg' => 'ES256',
    'typ' => 'gnap-binding+jwsd',
    'htm' => 'POST',
    'uri' => $url,
    'created' => time(),
  ];

  if($accessToken) {
    $hash = hash('sha256', $accessToken, true);
    $jwsHeader['ath'] = base64_url_encode(substr($hash, 0, strlen($hash) / 2));
  }

  $algorithmManager = new AlgorithmManager([
      new ES256(),
  ]);

  print_r($jwsHeader);
  echo $body."\n\n";
  $body_hash = base64_url_encode(hash('sha256', $body, true));
  echo $body_hash."\n\n";

  $jwsBuilder = new JWSBuilder($algorithmManager);
  $jws = $jwsBuilder->create()
    ->withEncodedPayload($body_hash)
    ->addSignature($jwk, $jwsHeader)
    ->build();

  $serializer = new CompactSerializer();
  $token = $serializer->serialize($jws);

  echo $token."\n\n";

  $headers = [
    'Content-Type: application/json',
    'Detached-JWS: ' . $token,
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
