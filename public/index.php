<?php
chdir(__DIR__.'/..');
require_once('vendor/autoload.php');

session_start();



if(isset($_GET['logout'])) {
  session_destroy();
  header('Location: /');
  die();
}




if(isset($_SESSION['access_token'])) {
  echo '<h2>Dashboard</h2>';
  echo '<p>Logged in</p>';
  echo '<p>' . $_SESSION['name'] . '</p>';
  echo '<pre>'; print_r($_SESSION['access_token']); echo '</pre>';
  echo '<p><a href="/?logout">Log Out</a></p>';
  die();
}

?>


<a href="start.php">Log In</a>


