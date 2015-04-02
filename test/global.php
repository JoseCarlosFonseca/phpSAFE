<?php
$x = 2;
if ( !isset( $_SESSION ) ) {
//expiring 24 hours = 60*60*24= 86400 seconds after the page was loaded
  session_set_cookie_params( 86400 );

  session_start();
}
if ( !isset( $_COOKIE[ 'XSSCookie' ] ) ) {
  setcookie( "XSSCookie", "Informação muito importante e privada = " . time(), time() + 3600 );  /* expire in 1 hour */
}
// Define database constants
define( 'VULN_HOST_PORT', 'localhost:3306' ); //ou ainda define('PHD_HOST', '127.0.0.1:3306');
define( 'VULN_HOST', 'localhost' ); //ou ainda define('PHD_HOST', '127.0.0.1:3306');
define( 'VULN_PORT', '3306' ); //ou ainda define('PHD_HOST', '127.0.0.1:3306');
define( 'VULN_USER', 'web_auth' ); //MySQL connection username
define( 'VULN_PASS', 'web_auth_password' ); //MySQL connection password
define( 'VULN_DB', 'vuln' ); // Mysql server variable to connect to

function strip_script_case_insensitive( $string ) {
  // Prevent inline scripting
  //Ze: I used \/ in stead of * to work with the XSS attack experiment
  $string = preg_replace( "/<script[^>]*>.*?<\/script[^>]*>/i", "", $string );
  // Prevent linking to source files
  $string = preg_replace( "/<script[^>]*>/i", "", $string );

  //styles
  $string = preg_replace( "/<style[^>]*>.*<*style[^>]*>/i", "", $string );
  // Prevent linking to source files
  $string = preg_replace( "/<style[^>]*>/i", "", $string );
  return $string;
}

function strip_script( $string ) {
  // Prevent inline scripting
  $string = preg_replace( "/<script[^>]*>.*?<*script[^>]*>/", "", $string );
  // Prevent linking to source files
  $string = preg_replace( "/<script[^>]*>/", "", $string );

  //styles
  $string = preg_replace( "/<style[^>]*>.*<*style[^>]*>/", "", $string );
  // Prevent linking to source files
  $string = preg_replace( "/<style[^>]*>/", "", $string );
  return $string;
}
//    function a() {
//      global $z;
//
//      $z = $_POST[ '213' ];
//
//      return 1;
//    }

    function show_names( $a, $b, $c, $d ) {
      echo "<br />$a<br />";
      echo "<br />$b<br />";  //VULNERABILITY
      echo "<br />$c<br />";
      echo "<br />$d<br />";
      return $a . $b . $c . $d;
    }
?>

<meta http-equiv="content-type" content="text/html; charset=ISO-8859-1" />
<meta http-equiv="Content-Language" content="pt">
<link rel="shortcut icon" href="favicon.ico">
