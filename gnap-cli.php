<?php
require('vendor/autoload.php');

use phpseclib3\Crypt\RSA;
use Bakame\Http\StructuredFields;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Core\JWK;

define('CLIENT_NAME', 'PHP CLI');
define('SIG_METHOD', 'pss');

if(!isset($argv[1])) {
  echo "usage: php sig.php action\n";
  die(1);
}

$redis = new \Predis\Client();
$redis->connect();

$privateKeyFilename = 'private.pem';
$gnapASEndpoint = 'https://gnap-as.herokuapp.com/api/as/transaction';
#$gnapASEndpoint = 'http://31.133.128.121:9834/api/as/transaction';

switch($argv[1]) {

  case 'keygen':
    $private = RSA::createKey();
    $public = $private->getPublicKey();

    echo (string)$private."\n";
    echo (string)$public."\n";

    file_put_contents($privateKeyFilename, $private);
    file_put_contents('public.pem', $public);

    $jwk = JWKFactory::createFromKeyFile($privateKeyFilename);
    $publicJSON = json_encode($jwk->toPublic()->all(), JSON_PRETTY_PRINT+JSON_UNESCAPED_SLASHES);
    file_put_contents('public-key.json', $publicJSON);

    break;

  case 'start':
    
    $client = new GNAPClient($privateKeyFilename, CLIENT_NAME, SIG_METHOD);
    
    $response = $client->post($gnapASEndpoint, [
      'interact' => [
        'start' => ['redirect', 'user_code']
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
    
    $client = new GNAPClient($privateKeyFilename, CLIENT_NAME, SIG_METHOD);
    
    $response = $client->post($pending['continue']['uri'], null, [
      'Authorization' => 'GNAP '.$pending['continue']['access_token']['value'],
    ]);
    
    $redis->setex('gnap-interaction', 86400, json_encode($response));
    
    break;
  
  default:
    die("unknown command\n");

}


class GNAPClient {
  
  private RSA $rsa;
  private JWK $jwk;
  
  public function __construct(private string $privateKeyFile, private string $name='', private string $method='pss') {
    if($method == 'pss') {
      $this->rsa = RSA::loadPrivateKey(file_get_contents($this->privateKeyFile))
        ->withHash('sha512')
        ->withMGFHash('sha512')
        ->withSaltLength(64)
        ->withPadding(RSA::SIGNATURE_PSS);
    } else {
      $this->rsa = RSA::loadPrivateKey(file_get_contents($this->privateKeyFile))
        ->withHash('sha256')
        ->withPadding(RSA::SIGNATURE_PKCS1);
    }
    $this->jwk = JWKFactory::createFromKeyFile($this->privateKeyFile);
  }
  
  public function setClientName(string $name) {
    $this->name = $name;
  }
  
  public function get(string $uri, array $headers=[]) {
    $createdAt = time();


  }

  # https://www.ietf.org/archive/id/draft-ietf-gnap-core-protocol-09.html#name-http-message-signing
  
  public function post(string $uri, array|null $params, array $headers=[]) {
    $createdAt = time();
    #$createdAt = 1647699014;

    $messageSignatureBase = [
      '@method' => 'POST',
      '@target-uri' => $uri,
    ];
    
    if($params) {
      $params['client'] = $this->_clientProperties();
      $requestBody = json_encode($params);
      $bodyDigest = StructuredFields\ByteSequence::fromDecoded(hash('sha256', $requestBody, true));
      $bodyDigestValue = StructuredFields\Dictionary::fromPairs([['sha-256', $bodyDigest]])->toHttpValue();

      $messageSignatureBase = array_merge($messageSignatureBase, [
        'content-digest' => $bodyDigestValue,
        'content-length' => strlen($requestBody),
        'content-type' => 'application/json',
      ]);
    }

    if(isset($headers['Authorization'])) {
      $messageSignatureBase['authorization'] = $headers['Authorization'];
    }

    # https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-09.html#name-rsassa-pss-using-sha-512
    // fromMembers is called fromList in later versions
    $signatureParams = StructuredFields\InnerList::fromMembers(array_keys($messageSignatureBase), [
      'created' => $createdAt,
      'keyid' => $this->privateKeyFile,
      'alg' => ($this->method == 'pss' ? 'rsa-pss-sha512' : 'rsa-v1_5-sha256'),
    ]);
    
    $messageSignatureString = '';
    foreach($messageSignatureBase as $k=>$v) {
      $messageSignatureString .= '"'.$k.'": '.$v."\n";
    }
    
    $messageSignatureString .= '"@signature-params": '.$signatureParams->toHttpValue();

    #echo $messageSignatureString."\n\n";
    
    #$messageSignatureString = 'Hello';

    $hashBytes = hash($this->method == 'pss' ? 'sha512' : 'sha256', $messageSignatureString, true);
    $signature = $this->rsa->sign($hashBytes);
    $signatureByteSequence = StructuredFields\ByteSequence::fromDecoded($signature);

    $signatureInput = StructuredFields\Dictionary::fromPairs([['sig', $signatureByteSequence]]);
    
    // https://www.ietf.org/archive/id/draft-ietf-httpbis-message-signatures-09.html#name-the-signature-http-field
    $byteSequence = StructuredFields\ByteSequence::fromDecoded($signature);
    $dictionary = StructuredFields\Dictionary::fromPairs([['sig', $byteSequence]]);
    
    $signatureParamsDictionary = StructuredFields\Dictionary::fromPairs([['sig', $signatureParams]]);

    #echo $requestBody."\n";
    #echo 'Signature: '.$dictionary->toHttpValue();
    #echo "\n";

    $headers['Signature'] = $dictionary->toHttpValue();
    $headers['Signature-Input'] = $signatureParamsDictionary->toHttpValue();
    $headers['Accept'] = 'application/json';
    $headers['Content-Type'] = 'application/json';
    
    if($params) {
      $headers['Content-Length'] = strlen($requestBody);
      $headers['Content-Digest'] = $bodyDigestValue;
    }

    $headerStr = [];
    foreach($headers as $k=>$v) {
      $headerStr[] = "$k: $v";
    }
    $headers = $headerStr;
    
//     echo "POST ".parse_url($uri, PHP_URL_PATH)." HTTP/1.1\r\n";
//     echo "Host: ".parse_url($uri, PHP_URL_HOST)."\r\n";
//     echo implode("\n", $headers);
//     if($params)
//       echo "\r\n\r\n$requestBody\n\n";
// 
//     echo "Public JWK:\n";
//     echo json_encode($this->jwk->toPublic()->all(), JSON_UNESCAPED_SLASHES);
//     echo "\n\n";

    $ch = curl_init($uri);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
    if($params)
      curl_setopt($ch, CURLOPT_POSTFIELDS, $requestBody);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    
    // if(($code=curl_getinfo($ch, CURLINFO_RESPONSE_CODE)) != 200) {
    //   echo "\n\nERROR: ".$code."\n";
    //   echo $response."\n";
    //   die();
    // }
    // 
    echo "Response\n";
    echo $response."\n\n";

    return json_decode($response, true);
  }
  
  private function _clientProperties() {
    return [
      'key' => [
        'proof' => 'httpsig',
        'jwk' => $this->jwk->toPublic()->all(),
      ],
      'display' => [
        'name' => $this->name,
      ],
    ];
  }
}
