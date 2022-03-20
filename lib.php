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
