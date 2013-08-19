<html>
  <head>
    <?php
    require_once("global.php");  // Define database constants
    ?>
    <title>xss1.php</title>
  </head>
  <body>
    <?php
    $x = 1;
    require_once("global.php");  // Define database constants
    echo '$x: ' . $x . "<br /";

    global $test1;
    $test1 = 3;
    echo "<br />Ola$test1<br />";

    $test2 = $_POST[ 'user_name' ];
    echo "<br />Ola$test2<br />";  //VULNERABILITY 

    $test3 = htmlentities( $_POST[ 'user_password' ] );
    echo "<br />Ola$test3<br />";

    $test4 = htmlentities( addslashes( $_POST[ 'user_secret' ] ) );
    echo "<br />Ola$test4<br />";

    show_names( $test1, $test2, $test3, $test4 );

    echo show_names2( $test1, $test3, $test4 ); //VULNERABILITY

    $test5 = show_names( $test1, $test2, $test3, $test4 );
    echo "<br />Ola$test5<br />";  //VULNERABILITY

    $test6 = show_names2( $test1, $test3, $test4 );
    echo "<br />Ola$test6<br />";  //VULNERABILITY

    $test7 = stripslashes( htmlentities( $test1 ) );

    echo $wpdb->query( "delete from " . $wpdb->prefix . "sml where id = '" . $id . "' limit 1" );  //VULNERABILITY
    echo mysql_query( "delete from " . $wpdb->prefix . "sml where id = '" . $id . "' limit 1" );  //VULNERABILITY

    foreach ( $_POST[ 'rem' ] as $id ) {
      $wpdb->query( "delete from " . $wpdb->prefix . "sml where id = '" . $id . "' limit 1" );  //VULNERABILITY
      $count++;
    }

//        unset($test2);

    echo "<br />Ola$test2<br />";  //VULNERABILITY

    for ( $i = 0; $i < 10; $i++ ) {
      echo '$i= ' . $i . '<br />';
    }

    for ( $j = 0; $j < 10; $j++ )
      echo '$j= ' . $j . '<br />';

    function show_names( $a, $b, $c, $d ) {
      echo "<br />$a<br />";
      echo "<br />$b<br />";  //VULNERABILITY
      echo "<br />$c<br />";
      echo "<br />$d<br />";
      return $a . $b . $c . $d;
    }

    function show_names2( $a, $c, $d ) {
      echo "<br />$a<br />";
      echo "<br />$c<br />";
      echo "<br />$d<br />";
      return $a . $_POST[ 'b' ] . $c . $d;
    }

    echo <<<_END
<h1>$test2</h1>  <!--VULNERABILITY-->
_END;
    ?>
    <h1><?php $test2 ?></h1>  <!--VULNERABILITY-->
  </body>
</html>