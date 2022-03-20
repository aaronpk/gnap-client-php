<?php
use Dotenv\Dotenv;

use BaconQrCode\Renderer\PlainTextRenderer;
use BaconQrCode\Writer;

// Load .env file if exists
$dotenv = Dotenv::createImmutable(__DIR__);
if(file_exists(__DIR__.'/.env')) {
  $dotenv->load();
}

function base64_urlencode($string) {
  return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
}

function array_filter_recursive($input) { 
  foreach($input as &$value) { 
    if(is_array($value)) { 
      $value = array_filter_recursive($value); 
    } 
  } 

  return array_filter($input); 
} 

class QRCodeCLI {

  public static function generate($text) {
    $renderer = new PlainTextRenderer();
    $writer = new Writer($renderer);
    return $writer->writeString($text);
  }

}
