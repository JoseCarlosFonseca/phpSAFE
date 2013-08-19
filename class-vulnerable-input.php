<?php

class Vulnerable_Input {

//Input and output variables and functions adapted from RIPS 0.54 (http://rips-scanner.sourceforge.net/)
//
//RIPS is a static source code analyser for vulnerabilities in PHP scripts
//by Johannes Dahse (johannes.dahse@rub.de)
//
//TODO when the input variables are extracted using the extract(...) array function
  static $INPUT_VARIABLES = array(
    'phpVars' => array(
      '$_GET',
      '$_POST',
      '$_COOKIE',
      '$_REQUEST',
      '$_FILES',
      '$_SERVER',
      '$_ENV',
      '$HTTP_GET_VARS',
      '$HTTP_POST_VARS',
      '$HTTP_COOKIE_VARS',
      '$HTTP_REQUEST_VARS',
      '$HTTP_POST_FILES',
      '$HTTP_SERVER_VARS',
      '$HTTP_ENV_VARS',
      '$HTTP_RAW_POST_DATA',
      '$argc',
      '$argv',
    ),
    'wpVars' => array(
      'todo',
    )//TODO
  );
  static $INPUT_FUNCTIONS = array(
    'phpFunctions' => array(
      'get_headers',
      'runkit_superglobals',
      'import_request_variables',
    ),
    'phpFileFunctions' => array(
      'bzread',
      'dio_read',
      'exif_imagetype',
      'exif_read_data',
      'exif_thumbnail',
      'fgets',
      'fgetss',
      'file',
      'file_get_contents',
      'fread',
      'get_meta_tags',
      'glob',
      'gzread',
      'readdir',
      'read_exif_data',
      'scandir',
      'zip_read',
    ),
    'phpDatabaseFunctions' => array(
      'mysql_fetch_array',
      'mysql_fetch_assoc',
      'mysql_fetch_field',
      'mysql_fetch_object',
      'mysql_fetch_row',
      'mysql_query',
      'pg_fetch_all',
      'pg_fetch_array',
      'pg_fetch_assoc',
      'pg_fetch_object',
      'pg_fetch_result',
      'pg_fetch_row',
      'sqlite_fetch_all',
      'sqlite_fetch_array',
      'sqlite_fetch_object',
      'sqlite_fetch_single',
      'sqlite_fetch_string',
    ),
    'wpFunctions' => array(
      '$wpdb->get_col',
      '$wpdb->get_results',
      '$wpdb->get_row',
      '$wpdb->get_var',
      '$wpdb->query',
    ),
  );

}

