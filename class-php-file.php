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
class Php_File {

  /**
   * The PHP file name to be scanned
   * @var string
   */
  public $parser_file_name;

  /**
   * Multi-dimensional array with the PHP file tokens
   * @var array
   */
  public $files_tokens;

  /**
   * Constructor that call all the functions that perform the static analysis looking for vulnerabilities
   * 
   * TODO check if PHP variables inside HTML code are double quoted
   * TODO dynamically created content
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   */
  function __construct( $file_name ) {
    $this->parser_file_name = realpath( $file_name );

    //add the start PHP file and all the PHP files to the multi-dimensional array $files_tokens
    $this->include_php_files( $this->parser_file_name );
  }

  /**
   * Call the function parsePhpFile to get the PHP tokens from the PHP file
   * into the multi-dimensional array $files_tokens
   * Then looks for included and required PHP files and recursively includes them
   * 
   * TODO deal with dynamic includes. At least build a warning mechanism
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   */
  function include_php_files( $file_name ) {
    $file_name = realpath(dirname($file_name )). DIRECTORY_SEPARATOR.basename($file_name );

  if ( $count = $this->php_file_tokens( $file_name ) ) {

      //TODO use include_paths()
      $file_path = dirname( $file_name ) . DIRECTORY_SEPARATOR;

      //find T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE within the $files_tokens[$file_name]
      for ( $i = 0, $count; $i < $count; $i++ ) {
        $token=$this->files_tokens[ $file_name ];
        if ( ( is_array( $token[ $i ] ) )
            && ( ( T_INCLUDE === $token[ $i ][ 0 ] )
            || ( T_INCLUDE_ONCE === $token[ $i ][ 0 ] )
            || ( T_REQUIRE === $token[ $i ][ 0 ] )
            || ( T_REQUIRE_ONCE === $token[ $i ][ 0 ] ) ) ) {
          $file_name_include = null;

          // it may have a '( ... )'
          if ( ( '(' === $token[ $i + 1 ] )
              && ( T_CONSTANT_ENCAPSED_STRING === $token[ $i + 2 ][ 0 ] )
              && ( ')' === $token[ $i + 3 ] ) ) {
            //TODO deal with concatenation
            $file_name_include = $token[ $i + 2 ][ 1 ];
            $i+=3;

            // it may have a ';' at the end 
          } elseif ( (is_array( $token[ $i + 1 ] ) )
              && ( T_CONSTANT_ENCAPSED_STRING === $token[ $i + 1 ][ 0 ] )
              && ( ';' === $token[ $i + 2 ] ) ) {
            //TODO deal with concatenation
            $file_name_include = $token[ $i + 1 ][ 1 ];
            $i+=2;
          } else {
            //TODO deal with dynamic includes
            continue;
          }
          if ( ('"' === substr( $file_name_include, 0, 1 ) ) || ("'" === substr( $file_name_include, 0, 1 ) ) ) {
            $file_name_include = $file_path . substr( $file_name_include, 1, -1 );
          } else {
            $file_name_include = $file_path . $file_name_include;
          }

          //only analyze the included file if it has not been anayzed yet
          if ( !in_array( $file_name_include, $this->files_tokens ) ) {
            //recursive call to itself
            $this->include_php_files( $file_name_include );
          }
        }
      }
    }
  }

  /**
   * Reads the contents of the file, gets the PHP tokens and cleans them removing whitespace and comments.
   * The outcome is stored in the multi-dimensional array $files_tokens with the array of PHP tokens.
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   */
  function php_file_tokens( $file_name ) {
    $file_name = realpath(dirname($file_name )). DIRECTORY_SEPARATOR.basename($file_name );

    if ( file_exists( $file_name ) ) {
      $file_contents = file_get_contents( $file_name );
      $this->files_tokens[ $file_name ] = token_get_all( $file_contents );

      //Remove whitespaces and comments
      foreach ( $this->files_tokens[ $file_name ] as $key => $token ) {
        if ( ( is_array( $token ) ) && ( ( T_WHITESPACE === $token[ 0 ] ) || ( T_COMMENT === $token[ 0 ] ) ) ) {
          //unset the token but keep the indexes untouched
          unset( $this->files_tokens[ $file_name ][ $key ] );
        }
      }

      //normalize the indexes
      $this->files_tokens[ $file_name ] = array_values( $this->files_tokens[ $file_name ] );

      return(count( $this->files_tokens[ $file_name ] ));
    }
    else return(null);
  }

}

// The ending PHP tag is omitted. This is actually safer than including it.