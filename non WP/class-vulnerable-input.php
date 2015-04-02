<?php
/**

  phpSAFE - PHP Security Analysis For Everyone

  Copyright (C) 2013 by Jose Fonseca (jozefonseca@gmail.com)

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <http://www.gnu.org/licenses/>.

  Wherever third party code has been used, credit has been given in the code's
  comments.

  phpSAFE is released under the GPL

 */

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
    'wpVars' => array( //added by me
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
      'mysql_query', //added by me
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
    /*
    'wpFunctions' => array( //added by me
      '$wpdb->get_col',
      '$wpdb->get_results',
      '$wpdb->get_row',
      '$wpdb->get_var',
      '$wpdb->query',
    ),
    */
  );

}


// The ending PHP tag is omitted. This is actually safer than including it.