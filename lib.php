<?php
use Dotenv\Dotenv;

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

