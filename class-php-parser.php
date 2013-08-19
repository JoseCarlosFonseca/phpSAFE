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

require_once 'class-php-file.php';

class PHP_Parser {

  /**
   * The object of the class Php_File
   * @var Php_File class object
   */
  protected $files;

  /**
   * Multi-dimensional array with the PHP user defined functions
   * @var array
   */
  public $files_functions;

  /**
   * Multi-dimensional array with the PHP user defined functions stack
   * This is used to test for recursive functions, so they are not parsed more than once at a time
   * @var array
   */
  protected $files_functions_stack;

  /**
   * The parser debug data
   * @var array
   */
  private $parser_debug;

  /**
   * Multi-dimensional array with the PHP includes and requires
   * @var array
   */
  protected $files_include_require;

  /**
   * Multi-dimensional associative array with the PHP variable attributes
   * @var array
   */
  protected $parser_variables;

  /**
   * Constructor that call all the functions that perform the static analysis looking for vulnerabilities
   * 
   * TODO check if PHP variables inside HTML code are double quoted
   * TODO dynamically created content
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   */
  function __construct( $file_name ) {
    $this->files = new Php_File( $file_name );

    //adds all the user defined functions to the multi-dimensional array $filesFunctions
    $this->include_all_php_files_functions();

    //parses the PHP files and searches for vulnerabilities. Adds the variables to the multi-dimensional array $parser_variables
    $this->main_parser( null, null, null, null );

    //adds the vulnerable variables to the multi-dimensional array $vulnerable_variables
    $this->set_vulnerable_variables();
    //adds the output variables to the multi-dimensional array $output_V_variables
    $this->set_output_variables();
  }

  /**
   * For all the PHP files included in the multi-dimensional array $files_tokens
   * calls the function includePhpFilesFunctions that adds the user defined functions
   * to the multi-dimensional array $filesFunctions.
   */
  function include_all_php_files_functions() {
    foreach ( $this->files->files_tokens as $file_name => $dummy ) {//loop through all the PHP file names
      $this->include_php_files_functions( $file_name );
    }
  }

  /**
   * Searche the contents of the multi-dimensional array $files_tokens for user defined functions
   * and add them to the multi-dimensional array $filesFunctions.
   *
   * TODO functions defined inside other functions
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   */
  function include_php_files_functions( $file_name ) {
    for ( $i = 0, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count; $i++ ) {
      $file_token_start_function_index = 0;
      $file_token_end_function_index = 0;
      $file_start_function_line = 0;
      $file_end_function_line = 0;
      $function_name = null;

      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        //Start of a function definition
        if ( T_FUNCTION === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          $function_name = $this->files->files_tokens[ $file_name ][ $i + 1 ][ 1 ];

          $file_token_start_function_index = $i;
          $file_start_function_line = $this->files->files_tokens[ $file_name ][ $i ][ 2 ];

          $file_token_end_function_index = $this->find_match( $file_name, $i, '{' );

          //generate an array of the function parameters
          $function_parameters = null; //some functions may have no parameters
          $file_token_function_start_parameter_index = $this->find_token( $file_name, $i, '(' );
          $file_token_function_end_parameter_index = $this->find_match( $file_name, $file_token_function_start_parameter_index, '(' );
          for ( $j = $file_token_function_start_parameter_index; $j < $file_token_function_end_parameter_index; $j++ ) {
            if ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $j ][ 0 ] ) {
              $function_parameters[ ] = $this->files->files_tokens[ $file_name ][ $j ][ 1 ];
            }
          }

          //Add the function data to the Multi-dimensional associative array $filesFunctions
          $this->files_functions[ ] = array(
            'function_name' => $function_name,
            'file_name' => $file_name,
            'file_start_line_number' => $file_start_function_line,
            'file_end_line_number' => $file_end_function_line,
            'file_tokens_start_index' => $file_token_start_function_index,
            'file_tokens_end_index' => $file_token_end_function_index,
            'function_parameters' => $function_parameters );

          //unset the $functionParameters array but keep the indexes untouched
          unset( $function_parameters );
        }
      }
    }
  }

  /**
   * Parse the multi-dimensional array $files_tokens and calls 
   * the functions that deal with the various code constructs.
   * This is done in a recursive manner, since many of those functions will call this function to parse their contents.
   * The outcome of this process is the multi-dimensional array $parser_variables with the PHP variables discovered during the parsing.
   * This includes information about variable tainting and vulnerabilities.
   * 
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
   */
  function main_parser( $file_name, $function_name, $block_start_index, $block_end_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );
    if ( is_null( $file_name ) ) {
      //point to the first php file
      reset( $this->files->files_tokens );
      $file_name = key( $this->files->files_tokens );
    }
    if ( is_null( $block_start_index ) ) {
      $block_start_index = 0;
    }
    if ( is_null( $block_end_index ) ) {
      $block_end_index = count( $this->files->files_tokens[ $file_name ] );
    }
    if ( is_null( $function_name ) ) {
      //the main function of the PHP code
      $function_name = 'function';
    }
    $token = $this->files->files_tokens[ $file_name ];
    $this->debug( 'Before main for: ' . $file_name . ' - ' . $block_start_index . ' - ' . $block_end_index . '<br />' );
    //search every FileTokens
    for ( $i = $block_start_index; $i < $block_end_index; $i++ ) {
      //Array tokens
      if ( is_array( $token[ $i ] ) ) {
        //is non PHP code
        if ( T_INLINE_HTML === $token[ $i ][ 0 ] ) {
          $i = $this->parse_non_php( $file_name, $function_name, $i );

          //Loops: T_FOR T_FOREACH T_IF T_WHILE T_SWITCH
        } elseif ( T_FOR === $token[ $i ][ 0 ] ) {
          $i = $this->parse_for( $file_name, $function_name, $i );
        } elseif ( T_FOREACH === $token[ $i ][ 0 ] ) {
          $i = $this->parse_foreach( $file_name, $function_name, $i );
        } elseif ( T_DO === $token[ $i ][ 0 ] ) {
          $i = $this->parse_do_while( $file_name, $function_name, $i );
        } elseif ( T_WHILE === $token[ $i ][ 0 ] ) {
          $i = $this->parse_do_while( $file_name, $function_name, $i );

          //Conditionals: T_IF
        } elseif ( ( T_IF === $token[ $i ][ 0 ] ) || ( T_ELSE === $token[ $i ][ 0 ] ) || ( T_ELSEIF === $token[ $i ][ 0 ]) ) {
          $i = $this->parse_if( $file_name, $function_name, $i );

          //Conditionals: T_SWITCH
        } elseif ( T_SWITCH === $token[ $i ][ 0 ] ) {
          $i = $this->parse_switch( $file_name, $function_name, $i );

          //TODO T_GOTO
          //T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE
        } elseif ( ( T_INCLUDE === $token[ $i ][ 0 ] )
            || ( T_INCLUDE_ONCE === $token[ $i ][ 0 ] )
            || ( T_REQUIRE === $token[ $i ][ 0 ] )
            || ( T_REQUIRE_ONCE === $token[ $i ][ 0 ] ) ) {
          $i = $this->parse_include_require( $file_name, $function_name, $i );

          //Output
        } elseif ( ( T_ECHO === $token[ $i ][ 0 ] )
            || ( T_PRINT === $token[ $i ][ 0 ] )
            || ( T_EXIT === $token[ $i ][ 0 ] ) ) {
          $i = $this->parse_function( $file_name, $function_name, $i );

          //function call
        } elseif ( ($this->is_function( $file_name, $i ))
            || ($this->is_method( $file_name, $i )) ) {
          $i = $this->parse_function( $file_name, $function_name, $i );

          //function definition should be skipped because it is executed when called in the PHP code
        } elseif ( T_FUNCTION === $token[ $i ][ 0 ] ) {
          //skip this token
          $i = $this->find_match( $file_name, $i, '{' );

          //function return
        } elseif ( T_RETURN === $token[ $i ][ 0 ] ) {
          $i = $this->parse_return( $file_name, $function_name, $i );

          //variables
          //TODO T_CURLY_OPEN
        } elseif ( ( T_VARIABLE === $token[ $i ][ 0 ] )
            || ( T_GLOBAL === $token[ $i ][ 0 ] )
            || (($this->is_variable( $file_name, $i ))
            || ($this->is_property( $file_name, $i ))) ) { //is a variable or a global variable
          $i = $this->parse_variable( $file_name, $function_name, $i );

          //T_AND_EQUAL T_CONCAT_EQUAL T_DIV_EQUAL T_MINUS_EQUAL T_MOD_EQUAL T_MUL_EQUAL T_OR_EQUAL T_PLUS_EQUAL T_XOR_EQUAL T_SL_EQUAL T_SR_EQUAL
        } elseif ( ( T_AND_EQUAL === $token[ $i ][ 0 ] )
            || ( T_CONCAT_EQUAL === $token[ $i ][ 0 ] )
            || ( T_DIV_EQUAL === $token[ $i ][ 0 ] )
            || ( T_MINUS_EQUAL === $token[ $i ][ 0 ] )
            || ( T_MOD_EQUAL === $token[ $i ][ 0 ])
            || ( T_MUL_EQUAL === $token[ $i ][ 0 ] )
            || ( T_OR_EQUAL === $token[ $i ][ 0 ] )
            || ( T_PLUS_EQUAL === $token[ $i ][ 0 ] )
            || ( T_XOR_EQUAL === $token[ $i ][ 0 ] )
            || ( T_SL_EQUAL === $token[ $i ][ 0 ])
            || ( T_SR_EQUAL === $token[ $i ][ 0 ] ) ) {
          $i = $this->parse_equal( $file_name, $function_name, $i );

          //AS functioning as an equal sign
        } elseif ( T_AS === $token[ $i ][ 0 ] ) {
          $i = $this->parse_as( $file_name, $function_name, $i );

          //T_UNSET
        } elseif ( T_UNSET === $token[ $i ][ 0 ] ) {
          $i = $this->parse_unset( $file_name, $function_name, $i );
        }

        //Non array tokens
      } else {
        //=
        if ( '=' === $token[ $i ] ) {
          $i = $this->parse_equal( $file_name, $function_name, $i );
        }
      }
    }
  }

  /**
   * create the multi-dimensional associative array with the PHP vulnerable variables
   */
  function set_vulnerable_variables() {
    
  }

  /**
   * create the multi-dimensional associative array with the PHP output variables
   */
  function set_output_variables() {
    
  }

  /**
   * Parse blocks of non PHP code. Currentely nothing is done
   * 
   * TODO check for other local PHP files by analyzing the hyperlinks
   * TODO javascript (hyperlinks, javascript variable usage and PHP variable usage inside javascript)
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
   */
  function parse_non_php( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $block_end_index = $block_start_index; //Index of the start of non PHP code
    do {
      $block_end_index++;
      if ( $block_end_index >= count( $this->files->files_tokens[ $file_name ] ) ) break;
    } while ( !(is_array( $this->files->files_tokens[ $file_name ][ $block_end_index ] )
    && (( T_OPEN_TAG === $this->files->files_tokens[ $file_name ][ $block_end_index ][ 0 ])
    || ( T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[ $file_name ][ $block_end_index ][ 0 ] ))) );
    return( $block_end_index);
  }

  /**
   * Parse for loop. Currentely it only calls the function mainParser.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
   */
  function parse_for( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $block_start_index++;
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index ] ) $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    else $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );

    $this->main_parser( $file_name, $function_name, $block_start_index + 1, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse foreach loop. Currentely it only calls the function mainParser.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
   */
  function parse_foreach( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $block_start_index++;
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index ] ) $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    else $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );

    $this->main_parser( $file_name, $function_name, $block_start_index + 1, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse do...while loop. Currentely it only calls the function mainParser.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_do_while( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    if ( T_DO === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '{' );
      $block_end_index = $this->find_match( $file_name, $block_end_index, ';' );
    }

    if ( T_WHILE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
      //The alternate syntax
      if ( ':' === $this->files->files_tokens[ $file_name ][ $i ][ 0 ][ $block_end_index + 1 ] ) {
        do {
          $block_end_index++;
        } while ( !(is_array( $this->files->files_tokens[ $file_name ][ $block_end_index ] ) && ( T_ENDWHILE === $this->files->files_tokens[ $file_name ][ $block_end_index ][ 0 ] )) );
      }
    }

    $this->main_parser( $file_name, $function_name, $block_start_index + 1, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse if conditional statement. Currentely it only calls the function mainParser.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_if( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    //The alternate syntax
    if ( ':' === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ][ $block_end_index + 1 ] ) {
      do {
        $block_start_index++;
      } while ( !(is_array( $this->files->files_tokens[ $file_name ][ $block_start_index ] )
      && ( T_ENDIF === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] )) );
      $block_end_index = $block_start_index;
    } elseif ( '{' === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ][ $block_end_index + 1 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index + 1, '{' );
    }

    $this->main_parser( $file_name, $function_name, $block_start_index + 1, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse switch conditional statement. Currentely it only calls the function mainParser.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_switch( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $block_end_index = $this->find_match( $file_name, $block_start_index, '{' );
    //The alternate syntax
    if ( ':' === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ][ $block_end_index + 1 ] ) {
      do {
        $block_start_index++;
      } while ( !(is_array( $this->files->files_tokens[ $file_name ][ $block_start_index ] )
      && ( T_ENDSWITCH === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] )) );
      $block_end_index = $block_start_index;
    }

    $this->main_parser( $file_name, $function_name, $block_start_index + 1, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse include, include_once, require and require_once.
   * All of them are processed by calling the function mainParser.
   * 
   * TODO use include_paths()
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_include_require( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );

    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) {
      $file_name_include = $this->files->files_tokens[ $file_name ][ $block_start_index + 2 ][ 1 ];
    } else {
      $file_name_include = $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ][ 1 ];
    }

    //TODO use include_paths()  
    $file_path = dirname( $file_name ) . DIRECTORY_SEPARATOR;

    if ( ('"' === substr( $file_name_include, 0, 1 ) )
        || ("'" === substr( $file_name_include, 0, 1 ) ) ) {
      $file_name_include = substr( $file_name_include, 1, -1 );
    }
    if ( ( T_INCLUDE_ONCE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] )
        || ( T_REQUIRE_ONCE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) ) {
      $once = 'true';
    } else {
      $once = 'false';
    }
    if ( ( T_INCLUDE_ONCE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] )
        || ( T_INCLUDE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) ) {
      $include_require = 'include';
    } else {
      $include_require = 'require';
    }

    $file_name = $file_path . $file_name_include;

    $yes_include_require = false;
    //store the included/required information int the multi-dimensional array variable $filesIncludesRequires
    for ( $i = 0, $count = count( $this->files_include_require ); $i < $count; $i++ ) {
      //check if the included/required file has already been included
      if ( ( $file_name === $this->files_include_require[ $i ][ 'include_require_file_name' ] )
          && ($include_require === $this->files_include_require[ $i ][ 'include_require' ] )
          && ($once === $this->files_include_require[ $i ][ 'once' ] ) ) {
        //the file has already been included/required once
        if ( 'true' === $once ) {
          $this->files_include_require[ $i ][ 'number_of_calls' ] +=1;
          break;
        } else {
          $this->files_include_require[ $i ][ 'number_of_calls' ] +=1;
          $this->files_include_require[ $i ][ 'number_of_calls_executed' ] +=1;
          $yes_include_require = true;
          break;
        }
      }
    }

    //if this include/require has not yet been processed then add it to the multi-dimensional array variable $filesIncludesRequires
    if ( count( $this->files_include_require ) === $i ) {
      $this->files_include_require[ ] = array(
        'include_require_file_name' => $file_name,
        'include_require_name' => $file_name_include,
        'include_require' => $include_require,
        'once' => $once,
        'number_of_calls' => 1,
        'number_of_calls_executed' => 1
      );
      $yes_include_require = true;
    }

    //only process the included file if it should
    if ( true === $yes_include_require ) {
      $this->main_parser( $file_name, null, null, null );
    }

    return( $block_end_index);
  }

  /**
   * parse functions
   * 
   * TODO passing by reference
   * TODO return
   * 
   * note: You define a function with parameters, you call a function with arguments.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_function( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    if ( $this->is_method( $file_name, $block_start_index ) ) {
      //it is an object user defined function
      $target_function_name = $this->get_variable_function_property_method_name( $file_name, $block_start_index );
      $block_start_index+=2;
    } else {
      $target_function_name = $this->get_variable_function_property_method_name( $file_name, $block_start_index );
    }

    if ( $this->is_user_defined_function( $file_name, $target_function_name ) ) {
      //if it is a user defined function test to see if it is already being parsed
      //should not parse functions with recursivity because it will never stop
      $is_function_already_being_parsed = false;
      for ( $i = 0, $count = count( $this->files_functions_stack ); $i < $count; $i++ ) {
        if ( ( $target_function_name === $this->files_functions_stack[ $i ][ 'function_name' ] )
            && ( $file_name === $this->files_functions[ $i ][ 'file_name' ] ) ) {
          $is_function_already_being_parsed = true;
          break;
        }
      }

      //if the function is not already being parsed then parse it
      if ( false === $is_function_already_being_parsed ) {
        //push the function to the stack
        $this->files_functions_stack[ ] = array(
          'function_name' => $target_function_name,
          'file_name' => $file_name,
        );

        //calculate the end token of the function call        
        if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) {
          $block_end_index = $this->find_match( $file_name, $block_start_index + 1, '(' );
          $block_start_index = $block_start_index + 1;
        } else {
          $block_end_index = $this->find_token( $file_name, $block_start_index + 1, ';' );
          $block_start_index = $block_start_index;
        }

        $this->parse_user_defined_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $target_function_name );

        //pop the function from the stack
        //unset the $files_functions_stack but keep the indexes untouched
        unset( $this->files_functions_stack[ count( $this->files_functions_stack ) - 1 ] );
        //normalize the indexes
        $this->files_functions_stack = array_values( $this->files_functions_stack );
      } else {
        $block_end_index = $block_start_index;
      }

      //all other functions that are not defined in the parsed PHP files, like echo, print, exit
    } else {
      //calculate the end token of the function call        
      if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) {
        $block_end_index = $this->find_match( $file_name, $block_start_index + 1, '(' );
        $block_start_index = $block_start_index + 1;
      } else {
        $block_end_index = $this->find_token( $file_name, $block_start_index + 1, ';' );
        $block_start_index = $block_start_index;
      }

      $this->parse_other_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $target_function_name );
    }
    return( $block_end_index);
  }

  /**
   * It is a user defined function so it is parsed
   * 
   * TODO return
   * 
   * note: You define a function with parameters, you call a function with arguments.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $target_function_name with the name of the function
   */
  function parse_user_defined_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $target_function_name ) {
    
  }

  /**
   * If the function is one of the output functions it is checked for tainted variables that could cause a vulnerability.
   * 
   * note: You define a function with parameters, you call a function with arguments.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $target_function_name with the name of the function
   */
  function parse_other_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $target_function_name ) {
    
  }

  /**
   * parse return of functions
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_return( $file_name, $function_name, $block_start_index ) {
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    } else {
      $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );
    }

    $this->parse_return_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index );

    return($block_end_index);
  }

  /**
   * Add a variable with the name of the function with the return value if there is no older one.
   * If the function had already a return value tainted, then do not add a new variable.
   * If the function had already a return value untainted and the new variable is tainted, then add a new variable and delete the old one.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   */
  function parse_return_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index ) {
    
  }

  /**
   * parse the equal token
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_equal( $file_name, $function_name, $block_start_index ) {
    //find the variable that is assigned something by searching backwards in the multi-dimensional array $files_tokens
    $variable_name = null;
    $variable_index = null;
    $i = $block_start_index;

    //get the name of the assigned variable (the one before the equal sign)
    do {
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        if ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          $v = $i;
          //$v is passed by reference
          $variable_name = $this->get_variable_name( $file_name, $v );
        }
      }
      $i--;
    } while ( ( $i >= 0) && (is_null( $variable_name )) );
    $variable_index = $this->get_variable_index( $variable_name, $function_name );
//        $this->debug('$variable_name ' . $variable_name . ' - $function_name ' . $function_name . ' $variable_index ' . $variable_index . '<br />');
    $block_end_index = $this->end_of_php_line( $file_name, $block_start_index );

    $this->parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_index );

    return $block_end_index;
  }

  /**
   * Verify if the variables in the multi-dimensional associative array $parser_variables depend on other variables
   * If any of the variables they depend is TAINTED then the variable is updated to be also TAINTED
   * The multi-dimensional associative array $parser_variables is updated accordingly
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $equal with the values '=' or 'as'
   * If it is an 'as' the assigned variable is the one in the right of the 'as'
   * If it is an '=' the assigned variable is the one in the left of the '=' sign
   * @param string $variable_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_index ) {
    
  }

  /**
   * parse the AS token
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   * @param string $equal with the values '=' or 'as'
   * If it is an 'as' the assigned variable is the one in the right of the 'as'
   * If it is an '=' the assigned variable is the one in the left of the '=' sign
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_as( $file_name, $function_name, $block_start_index ) {

    //find the variable that is assigned something by searching backwards in the multi-dimensional array $files_tokens
    $variable_name = null;
    $variable_index = null;
    $i = $block_start_index;

    //get the name of the assigned variable (the one before the equal sign)
    do {
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        if ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          $v = $i;
          $variable_name = $this->get_variable_name( $file_name, $v ); //$v is passed by reference
        }
      }
      $i--;
    } while ( ( 0 <= $i) && (is_null( $variable_name )) );
    $variable_index = $this->get_variable_index( $variable_name, $function_name );
    $block_end_index = $this->end_of_php_line( $file_name, $block_start_index );

    $this->parse_as_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_index );

    return $block_end_index;
  }

  /**
   * Verify if the variables in the multi-dimensional associative array $parser_variables depend on other variables
   * If any of the variables they depend is TAINTED then the variable is updated to be also TAINTED
   * The multi-dimensional associative array $parser_variables is updated accordingly
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $equal with the values '=' or 'as'
   * If it is an 'as' the assigned variable is the one in the right of the 'as'
   * If it is an '=' the assigned variable is the one in the left of the '=' sign
   * @param string $variable_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_as_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_index ) {
    
  }

  /**
   * Parse variables
   * 
   * TODO object property
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the variable
   */
  function parse_variable( $file_name, $function_name, $block_start_index ) {
    $code_type = PHP_CODE;
    $function_name = $this->find_user_defined_function_name( $file_name, $block_start_index );

    if ( T_GLOBAL === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) {
      $variable_scope = 'global';
      $block_start_index++;
    } else {
      $variable_scope = 'local';
    }
    $block_end_index = $block_start_index;
    //$block_end_index is passed by reference
    $variable_name = $this->get_variable_name( $file_name, $block_end_index );

    $this->parse_variable_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type );

    return( $block_end_index);
  }

  /**
   * Extract the variable information from the multi-dimensional array $files_tokens 
   * and store it in the multi-dimensional associative array $parser_variables
   * Make a distinction between regular and input variables
   * Taint the input variables
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code is being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $variable_name with the name of the variable
   * @param string $variable_scope with the scope of the variable: local or global
   * @param string $code_type with the type of PHP code: php code or non php code
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the variable
   */
  function parse_variable_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type ) {
    
  }

  /**
   * Parse unset
   * The variable is created
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_unset( $file_name, $function_name, $block_start_index ) {
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    else $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );

    $i = $this->parse_variable( $file_name, $function_name, $block_start_index + 1 );
    $v = $block_start_index + 2;
    //$v is passed by reference
    $function_argument_name = $this->get_variable_name( $file_name, $v );

    $function_argument_index = $this->get_variable_index( $function_argument_name, $function_name );

    $this->parse_unset_vulnerability( $block_end_index, $function_argument_index );

    return( $block_end_index);
  }

  /**
   * Parse unset. The variable becomes untainited
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $functionArgumentIndex with the index of tokens the the multi-dimensional array $parser_variables
   */
  function parse_unset_vulnerability( $block_end_index, $functionArgumentIndex ) {
    
  }

  /**
   * Calculate the start of the PHP line of code
   *
   * @param int $pointer with the index of the multi-dimensional array $files_tokens
   * @return int with the index of multi-dimensional associative array $files_tokens that corresponds to the start of the PHP line of code
   */
  function start_of_php_line( $file_name, $pointer ) {
    $is_start_of_line = 0;
    do {
      if ( !is_array( $this->files->files_tokens[ $file_name ][ $pointer ] ) ) {
        if ( ( ';' === $this->files->files_tokens[ $file_name ][ $pointer ] )
            || ( '}' === $this->files->files_tokens[ $file_name ][ $pointer ] )
            || ('{' === $this->files->files_tokens[ $file_name ][ $pointer ] ) ) {
          $is_start_of_line = 1;
        }
      } else {
        if
        ( ( T_OPEN_TAG === $this->files->files_tokens[ $file_name ][ $pointer ][ 0 ] )
            || ( T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[ $file_name ][ $pointer ][ 0 ] ) ) $is_start_of_line = 1;
      }
      if ( ( 0 < $pointer ) && ( 0 === $is_start_of_line ) ) {
        $pointer--;
      } else {
        $is_start_of_line = 1;
      }
    } while ( 0 === $is_start_of_line );
    return $pointer;
  }

  /**
   * Calculate the end of the PHP line of code
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param int $pointer with the index of the multi-dimensional array $files_tokens
   * 
   * @return int with the index of multi-dimensional associative array $parserFileTokens that corresponds to the end of the PHP line of code
   */
  function end_of_php_line( $file_name, $pointer ) {
    $is_end_of_line = 0;
    $count = count( $this->files->files_tokens[ $file_name ] ) - 1;
    do {
      if ( !is_array( $this->files->files_tokens[ $file_name ][ $pointer ] ) ) {
        if ( ( ';' === $this->files->files_tokens[ $file_name ][ $pointer ] )
            || ( '}' === $this->files->files_tokens[ $file_name ][ $pointer ] )
            || ( '{' === $this->files->files_tokens[ $file_name ][ $pointer ] ) ) {
          $is_end_of_line = 1;
        }
      } else {
        if ( T_CLOSE_TAG === $this->files->files_tokens[ $file_name ][ $pointer ][ 0 ] ) {
          $is_end_of_line = 1;
        }
      }
      if ( ( $pointer < $count) && ( 0 === $is_end_of_line ) ) {
        $pointer++;
      } else {
        $is_end_of_line = 1;
      }
    } while ( $is_end_of_line === 0 );
    //if after the ; it is the end of the PHP block then the end of the line is the end of the PHP block
    if ( ( ';' === $this->files->files_tokens[ $file_name ][ $pointer ] )
        && ( T_CLOSE_TAG === $this->files->files_tokens[ $file_name ][ $pointer + 1 ][ 0 ] ) ) {
      $pointer++;
    }
    return $pointer;
  }

  /**
   * Search for the matching end token of the open token passed as an argument.
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $open_token with the open token, that can be a '(' or a '{'
   * 
   * @return int with the index of the end token in the multi-dimensional associative array $files_tokens
   */
  function find_match( $file_name, $block_start_index, $open_token ) {
    switch ( $open_token ) {
      case '(':
        $close_token = ')';
        break;
      case '{':
        $close_token = '}';
        break;

      default:
        return null;
        break;
    }
    $count_open = 0;
    $count_close = 0;
    $block_end_index = $block_start_index;
    //search for the end of the function
    for ( $i = $block_start_index, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count; $i++ ) {
      //the last line of a function is located in the last array, since } does not have a line number
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        $block_end_index = $this->files->files_tokens[ $file_name ][ $i ][ 2 ];
      }
      if ( $this->files->files_tokens[ $file_name ][ $i ] === $open_token ) {
        $count_open++;
      }
      if ( $this->files->files_tokens[ $file_name ][ $i ] === $close_token ) {
        $count_close++;
        if ( $count_open - $count_close === 0 ) {
          $block_end_index = $i;
          break;
        }
      }
    }
    return $block_end_index;
  }

  /**
   * Search for the next token passed as an argument in the multi-dimensional associative array $files_tokens.
   * If in between there are ( or { it resumes the search only after the matching ) } " '
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $token with the token
   * 
   * @return int with the index of the end token in the multi-dimensional associative array $files_tokens
   */
  function find_token( $file_name, $block_start_index, $token ) {
    $block_end_index = $block_start_index;
    //search for the end of the function
    for ( $i = $block_start_index, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count; $i++ ) {
      if ( ( '(' === $this->files->files_tokens[ $file_name ][ $i ] ) || ( '{' === $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        $i = $this->find_match( $file_name, $i, $this->files->files_tokens[ $file_name ][ $i ] );
        $i++;
      }
      if ( '"' === $this->files->files_tokens[ $file_name ][ $i ] ) {
        do {
          $i++;
        } while ( '"' != $this->files->files_tokens[ $file_name ][ $i ] );
      }
      if ( "'" === $this->files->files_tokens[ $file_name ][ $i ] ) {
        do {
          $i++;
        } while ( "'" != $this->files->files_tokens[ $file_name ][ $i ] );
      }
      if ( $this->files->files_tokens[ $file_name ][ $i ] === $token ) {
        $block_end_index = $i;
        break;
      }
    }
    return $block_end_index;
  }

  /**
   * Search for the name of the function from which the code in the multi-dimensional associative array $files_tokens belongs to.
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return string with the name of the function or the string 'function' in the case the code is from outside any function
   */
  function find_user_defined_function_name( $file_name, $file_index ) {
    for ( $i = 0, $count = count( $this->files_functions ); $i < $count; $i++ ) {
      if ( ( $this->files_functions[ $i ][ 'file_name' ] === $file_name)
          && ( $this->files_functions[ $i ][ 'file_tokens_start_index' ] <= $file_index)
          && ( $this->files_functions[ $i ][ 'file_tokens_end_index' ] >= $file_index) ) {
        return $this->files_functions[ $i ][ 'function_name' ];
      }
    }
    return 'function';
  }

  /**
   * return true if the function is a php user defined function and false otherwise
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function that is going to be searched
   * 
   * @return boolean with true if the token is a php user defined function and false otherwise
   */
  function is_user_defined_function( $file_name, $function_name ) {
    for ( $i = 0, $count = count( $this->files_functions ); $i < $count; $i++ ) {
      if ( ( $this->files_functions[ $i ][ 'file_name' ] === $file_name)
          && ( $this->files_functions[ $i ][ 'function_name' ] === $function_name) ) {
        return true;
        break;
      }
    }
    return false;
  }

  /**
   * return true if the token is a php variable and false otherwise
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return boolean with true if the token is a php variable and false otherwise
   */
  function is_variable( $file_name, $file_index ) {
    if ( 'variable' === $this->check_variable_function_property_method( $file_name, $file_index ) ) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * return true if the token is an object property and false otherwise
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return boolean with true if the token is an object property and false otherwise
   */
  function is_property( $file_name, $file_index ) {
    if ( 'property' === $this->check_variable_function_property_method( $file_name, $file_index ) ) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * return true if the token is a php user defined function and false otherwise
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return boolean with true if the token is a php user defined function and false otherwise
   */
  function is_function( $file_name, $file_index ) {
    if ( 'function' === $this->check_variable_function_property_method( $file_name, $file_index ) ) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * return true if the token is an object method and false otherwise
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return boolean with true if the token is an object method and false otherwise
   */
  function is_method( $file_name, $file_index ) {
    if ( 'method' === $this->check_variable_function_property_method( $file_name, $file_index ) ) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * check if the token is a php variable, an object property, a php user defined function or an object method
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return string with 'variable', 'property', 'function' or 'method'
   * if the token is respectively a php variable, an object property, a php user defined function or an object method and null otherwise
   */
  function check_variable_function_property_method( $file_name, $file_index ) {
    //test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
    if ( $file_index >= 0 ) {
      //test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
      if ( ($file_index >= 2)
          && (T_OBJECT_OPERATOR === $this->files->files_tokens[ $file_name ][ $file_index - 1 ][ 0 ] ) ) {
        $file_index = $file_index - 2;
      }

      //method
      if ( ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $this->files->files_tokens[ $file_name ][ $file_index + 2 ][ 0 ] )
          && ( '(' === $this->files->files_tokens[ $file_name ][ $file_index + 3 ][ 0 ] ) ) {
        return 'method';

        //property
      } elseif ( ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $this->files->files_tokens[ $file_name ][ $file_index + 2 ][ 0 ] )
          && ( '(' != $this->files->files_tokens[ $file_name ][ $file_index + 3 ][ 0 ] ) ) {
        return 'property';

        //variable
      } elseif ( ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( '(' != $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] ) ) {
        return 'variable';

        //function
      } elseif ( ( T_STRING === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( '(' === $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] ) ) {
        return 'function';

        //function
      } elseif ( ( T_ECHO === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          || (T_PRINT === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          || (T_EXIT === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] ) ) {
        return 'function';
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  /**
   * check if the token is a php variable, an object property, a php user defined function or an object method
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return string with 'variable', 'property', 'function' or 'method'
   * if the token is respectively a php variable, an object property, a php user defined function or an object method and null otherwise
   */
  function get_variable_function_property_method_name( $file_name, $file_index ) {
    $name = null;
    //test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
    if ( $file_index >= 0 ) {
      //test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
      if ( ($file_index >= 2) && (T_OBJECT_OPERATOR === $this->files->files_tokens[ $file_name ][ $file_index - 1 ][ 0 ] ) ) {
        $file_index = $file_index - 2;
      }

      //method
      if ( ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $this->files->files_tokens[ $file_name ][ $file_index + 2 ][ 0 ] )
          && ( '(' === $this->files->files_tokens[ $file_name ][ $file_index + 3 ][ 0 ] ) ) {
        $name = $this->files->files_tokens[ $file_name ][ $file_index ][ 1 ] . $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 1 ] . $this->files->files_tokens[ $file_name ][ $file_index + 2 ][ 1 ];
        return $name;

        //property
      } elseif ( ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $this->files->files_tokens[ $file_name ][ $file_index + 2 ][ 0 ] )
          && ('(' != $this->files->files_tokens[ $file_name ][ $file_index + 3 ][ 0 ] ) ) {
        $name = $this->files->files_tokens[ $file_name ][ $file_index ][ 1 ] . $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 1 ] . $this->files->files_tokens[ $file_name ][ $file_index + 2 ][ 1 ];
        return $name;

        //variable
      } elseif ( (T_VARIABLE === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( '(' != $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] ) ) {
        $name = $this->files->files_tokens[ $file_name ][ $file_index ][ 1 ];
        return $name;

        //function
      } elseif ( ( T_STRING === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          && ( '(' === $this->files->files_tokens[ $file_name ][ $file_index + 1 ][ 0 ] ) ) {
        $name = $this->files->files_tokens[ $file_name ][ $file_index ][ 1 ];
        return $name;

        //function
      } elseif ( ( T_ECHO === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          || ( T_PRINT === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] )
          || ( T_EXIT === $this->files->files_tokens[ $file_name ][ $file_index ][ 0 ] ) ) {
        $name = $this->files->files_tokens[ $file_name ][ $file_index ][ 1 ];
        return $name;
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  /**
   * get the multi-dimensional associative array with the PHP tokens
   * 
   * @return the multi-dimensional associative array $files_tokens
   */
  function get_files_tokens() {
    return $this->files->files_tokens;
  }

  /**
   * get the multi-dimensional associative array with the user defined functions
   * 
   * @return the multi-dimensional associative array $filesFunctions
   */
  function get_files_functions() {
    return $this->files_functions;
  }

  /**
   * get the array with the parser debug messages
   * 
   * @return the array with the parser debug messages $parserDebug
   */
  function get_parser_debug() {
    return $this->parser_debug;
  }

  /**
   * get the multi-dimensional associative array with the PHP variable attributes
   * 
   * @return the multi-dimensional associative array $parser_variables
   */
  function get_parser_variables() {
    return $this->parser_variables;
  }

  /**
   * get the multi-dimensional associative array with the includes and requires
   * 
   * @return the multi-dimensional associative array $filesIncludeRequire
   */
  function get_files_include_require() {
    return $this->files_include_require;
  }

  /**
   * Show debug information
   *
   * @param string $message with the debug message
   */
  function debug( $message ) {
    $this->parser_debug[ ] = $message;
  }

}

