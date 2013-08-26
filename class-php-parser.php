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

    //add all the user defined functions to the multi-dimensional array $filesFunctions
    $this->include_all_php_files_functions();

    //parse all the functions that are not executed
    for ( $i = (count( $this->files_functions ) - 1); $i > 0; $i-- ) {
      if ( ('not executed' === $this->files_functions[ $i ][ 'executed' ] )
          && ('function' != $this->files_functions[ $i ][ 'function_name' ] ) ) {
        $file_name = $this->files_functions[ $i ][ 'file_name' ];
        $block_start_index = $this->files_functions[ $i ][ 'file_tokens_start_index' ];
        $block_start_index = $this->find_token( $file_name, $block_start_index, '{' );
        $block_end_index = $this->files_functions[ $i ][ 'file_tokens_end_index' ];
        //parse the PHP files and searches for vulnerabilities. Adds the variables to the multi-dimensional array $parser_variables
        $this->main_parser( $file_name, $this->files_functions[ $i ][ 'function_name' ], $block_start_index, $block_end_index );
      }
    }

    //parse the PHP files and searches for vulnerabilities. Adds the variables to the multi-dimensional array $parser_variables
    $this->main_parser( null, null, null, null );

    //add the vulnerable variables to the multi-dimensional array $vulnerable_variables
    $this->set_vulnerable_variables();
    //add the output variables to the multi-dimensional array $output_V_variables
    $this->set_output_variables();
  }

  /**
   * For all the PHP files included in the multi-dimensional array $files_tokens
   * calls the function includePhpFilesFunctions that adds the user defined functions
   * to the multi-dimensional array $filesFunctions.
   */
  function include_all_php_files_functions() {
//loop through all the PHP file names
    foreach ( $this->files->files_tokens as $file_name => $dummy ) {
      $this->include_php_files_functions( $file_name );
    }
  }

  /**
   * Search the contents of the multi-dimensional array $files_tokens for user defined functions
   * and add them to the multi-dimensional array $filesFunctions.
   *
   * TODO functions defined inside other functions
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   */
  function include_php_files_functions( $file_name ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $called_functions = null;
    for ( $i = 0, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count; $i++ ) {
      //generate an array of the function calls

      if ( ( T_ECHO === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
          || ( T_PRINT === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
          || ( T_EXIT === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
          || ($this->is_function( $file_name, $i ))
          || ($this->is_method( $file_name, $i )) ) {
        //calculate the end token of the function call        
        $called_function_name = $this->get_function_method_name( $file_name, $i );
        $called_functions[ ] = array(
          'name' => $called_function_name,
          'file_line_number' => $this->files->files_tokens[ $file_name ][ $i ][ 2 ],
          'user_defined' => 'not user defined',
          'input' => 'not input',
          'output' => 'not output',
          'filter' => 'not filter',
          'revert_filter' => 'not revert filter',
          'other' => 'other',
        );
      } elseif ( T_FUNCTION === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
        //skip this token
        $i = $this->find_match( $file_name, $i, '{' );
      }
    }

    //Add the function data to the Multi-dimensional associative array $filesFunctions
    $this->files_functions[ ] = array(
      'function_name' => 'function',
      'file_name' => $file_name,
      'executed' => 'not executed',
      'file_start_line_number' => 0,
      'file_end_line_number' => $count,
      'file_tokens_start_index' => 0,
      'file_tokens_end_index' => 0,
      'function_parameters' => null,
      'called_functions' => $called_functions,
    );

    for ( $i = 0, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count; $i++ ) {
      $file_token_start_function_index = 0;
      $file_token_end_function_index = 0;
      $file_start_function_line = 0;
      $file_end_function_line = 0;
      $function_name = null;

      //Start of a function definition
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] )
          && (T_FUNCTION === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) ) {
        $function_name = $this->get_function_method_name( $file_name, $i + 1 );

        $file_token_start_function_index = $i;
        $file_start_function_line = $this->files->files_tokens[ $file_name ][ $i ][ 2 ];

        $file_token_end_function_index = $this->find_match( $file_name, $i, '{' );

        //generate an array of the function parameters
        $function_parameters = null; //some functions may have no parameters
        $file_token_function_start_parameter_index = $this->find_token( $file_name, $i, '(' );
        $file_token_function_end_parameter_index = $this->find_match( $file_name, $file_token_function_start_parameter_index, '(' );
        for ( $j = $file_token_function_start_parameter_index; $j < $file_token_function_end_parameter_index; $j++ ) {
          if ( ( $this->is_variable( $file_name, $j )) || ( $this->is_property( $file_name, $j )) ) {
            $function_parameters[ ] = array(
              'parameter_name' => $this->files->files_tokens[ $file_name ][ $j ][ 1 ],
              'file_line_number' => $this->files->files_tokens[ $file_name ][ $j ][ 2 ],
            );
          }
        }

        $called_functions = null;
        //generate an array of the function calls
        for ( $j = $file_token_function_start_parameter_index; $j < $file_token_end_function_index; $j++ ) {

          if ( ( T_ECHO === $this->files->files_tokens[ $file_name ][ $j ][ 0 ] )
              || ( T_PRINT === $this->files->files_tokens[ $file_name ][ $j ][ 0 ] )
              || ( T_EXIT === $this->files->files_tokens[ $file_name ][ $j ][ 0 ] )
              || ($this->is_function( $file_name, $j ))
              || ($this->is_method( $file_name, $j )) ) {
            //calculate the end token of the function call        
            $called_function_name = $this->get_function_method_name( $file_name, $j );
            $called_functions[ ] = array(
              'name' => $called_function_name,
              'file_line_number' => $this->files->files_tokens[ $file_name ][ $j ][ 2 ],
              'user_defined' => 'not user defined',
              'input' => 'not input',
              'output' => 'not output',
              'filter' => 'not filter',
              'revert_filter' => 'not revert filter',
              'other' => 'other',
            );
          } elseif ( T_FUNCTION === $this->files->files_tokens[ $file_name ][ $j ][ 0 ] ) {
            //skip this token
            $j = $this->find_match( $file_name, $j, '{' );
          }
        }

        //Add the function data to the Multi-dimensional associative array $filesFunctions
        $this->files_functions[ ] = array(
          'function_name' => $function_name,
          'file_name' => $file_name,
          'executed' => 'not executed',
          'file_start_line_number' => $file_start_function_line,
          'file_end_line_number' => $file_end_function_line,
          'file_tokens_start_index' => $file_token_start_function_index,
          'file_tokens_end_index' => $file_token_end_function_index,
          'function_parameters' => $function_parameters,
          'called_functions' => $called_functions,
        );

        //unset the $functionParameters array but keep the indexes untouched
        unset( $function_parameters );
      }
    }

    for ( $i = 0, $count = count( $this->files_functions ); $i < $count; $i++ ) {
      for ( $j = 0, $jcount = count( $this->files_functions[ $i ][ 'called_functions' ] ); $j < $jcount; $j++ ) {
        $called_function_name = $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'name' ];

        for ( $k = 0, $kcount = count( $this->files_functions ); $k < $kcount; $k++ ) {
          $function_name = $this->files_functions[ $k ][ 'function_name' ];
          if ( 0 === strcasecmp( $function_name, $called_function_name ) ) {
            $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'user_defined' ] = 'user defined';
            break;
          }
        }
        foreach ( Vulnerable_Input::$INPUT_FUNCTIONS as $key => $value ) {
          foreach ( $value as $output ) {
            //note: PHP functions are not case sensitive
            if ( 0 === strcasecmp( $output, $called_function_name ) ) {
              $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'input' ] = 'input';
              break;
            }
          }
        }

        foreach ( Vulnerable_Output::$OUTPUT_FUNCTIONS as $key => $value ) {
          foreach ( $value as $output ) {
            //note: PHP functions are not case sensitive
            if ( 0 === strcasecmp( $output, $called_function_name ) ) {
              $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'output' ] = 'output';
              break;
            }
          }
        }

        foreach ( Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value ) {
          foreach ( $value as $output ) {
            //note: PHP functions are not case sensitive
            if ( 0 === strcasecmp( $output, $called_function_name ) ) {
              $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'filter' ] = 'filter';
              break;
            }
          }
        }

        foreach ( Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value ) {
          foreach ( $value as $output ) {
            //note: PHP functions are not case sensitive
            if ( 0 === strcasecmp( $output, $called_function_name ) ) {
              $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'revert_filter' ] = 'revert filter';
              break;
            }
          }
        }
      }
    }

    for ( $i = 0, $count = count( $this->files_functions ); $i < $count; $i++ ) {
      for ( $j = 0, $jcount = count( $this->files_functions[ $i ][ 'called_functions' ] ); $j < $jcount; $j++ ) {
        if ( ('user defined' === $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'user_defined' ])
            || ('input' === $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'input' ])
            || ('output' === $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'output' ])
            || ('filter' === $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'filter' ])
            || ('revert filter' === $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'revert_filter' ])
        ) {
          $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'other' ] = 'not other';
        }
      }
    }

    for ( $i = 0, $count = count( $this->files_functions ); $i < $count; $i++ ) {
      for ( $j = 0, $jcount = count( $this->files_functions[ $i ][ 'called_functions' ] ); $j < $jcount; $j++ ) {
        for ( $k = 0, $count = count( $this->files_functions ); $k < $count; $k++ ) {
          if ( $this->files_functions[ $k ][ 'function_name' ] === $this->files_functions[ $i ][ 'called_functions' ][ $j ][ 'name' ] ) {
            $this->files_functions[ $k ][ 'executed' ] = 'executed';
          }
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
      $block_end_index = count( $this->files->files_tokens[ $file_name ] ) - 1;
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
          $i = $this->parse_do_while_do( $file_name, $function_name, $i );
        } elseif ( T_WHILE === $token[ $i ][ 0 ] ) {
          $i = $this->parse_do_while_do( $file_name, $function_name, $i );

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

//TODO T_CURLY_OPEN
//local and global variables
        } elseif ( ( T_VARIABLE === $token[ $i ][ 0 ] )
            || ( T_GLOBAL === $token[ $i ][ 0 ] )
            || (($this->is_variable( $file_name, $i ))
            || ($this->is_property( $file_name, $i ))) ) {
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

//Index of the start of non PHP code
    $block_end_index = $block_start_index;
    $token = $this->files->files_tokens[ $file_name ];
    do {
      $block_end_index++;
      if ( $block_end_index >= count( $token ) ) break;
    } while ( !(is_array( $token[ $block_end_index ] )
    && (( T_OPEN_TAG === $token[ $block_end_index ][ 0 ])
    || ( T_OPEN_TAG_WITH_ECHO === $token[ $block_end_index ][ 0 ] ))) );
    return( $block_end_index);
  }

  /**
   * Parse for loop. Currentely it only calls the function $this->main_parser.
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
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    } else {
      $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );
    }

    $block_start_index++;
    $this->main_parser( $file_name, $function_name, $block_start_index, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse foreach loop. Currentely it only calls the function $this->main_parser.
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
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
      $block_start_index++;
    } else {
      $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );
    }


    for ( $i = $block_start_index, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count - 1; $i++ ) {
      if ( ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) )
          && (T_AS === $this->files->files_tokens[ $file_name ][ $i ][ 0 ]) ) {
        $block_as_index = $i;
        break;
      }
    }

    $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $block_start_index, $block_as_index, null, null );

    if ( is_null( $expression[ 'variable_dependencies_index' ] ) ) {
      $this->parse_variable( $file_name, $function_name, $block_as_index + 1 );
    } else {
      if ( ( is_array( $this->files->files_tokens[ $file_name ][ $block_start_index ] ) )
          && ( ( $this->is_variable( $file_name, $block_start_index ) ) || ( $this->is_property( $file_name, $block_start_index ) ) ) ) {
        $v = $block_start_index;
        //$v is passed by reference
        $variable_before_as_name = $this->get_variable_property_complete_array_name( $file_name, $v );
      } else {
        //TODO
      }

      $variable_before_as_index = $this->get_variable_index( $variable_before_as_name, $function_name );

      $this->parse_as_vulnerability( $file_name, $function_name, $block_as_index + 1, $block_end_index, $variable_before_as_index );
    }
    return $block_end_index;
  }

  /**
   * Parse do...while loop. Currentely it only calls the function $this->main_parser.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
   */
  function parse_do_while_do( $file_name, $function_name, $block_start_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

//do..while
    if ( T_DO === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '{' );
      $block_end_index = $this->find_match( $file_name, $block_end_index, ';' );

//while
    } elseif ( T_WHILE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
//The alternate syntax
      if ( ':' === $this->files->files_tokens[ $file_name ][ $block_end_index + 1 ] ) {
        do {
          $block_end_index++;
        } while ( !(is_array( $this->files->files_tokens[ $file_name ][ $block_end_index ] )
        && ( T_ENDWHILE === $this->files->files_tokens[ $file_name ][ $block_end_index ][ 0 ] )) );
      }
    }

    $block_start_index++;
    $this->main_parser( $file_name, $function_name, $block_start_index, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse if conditional statement. Currentely it only calls the function $this->main_parser.
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

    if ( (T_IF === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ])
        || (T_ELSEIF === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ]) ) {

      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    } else {
      $block_end_index = $block_start_index + 1;
    }

    $aux = $block_end_index;
//The alternate syntax
    if ( ':' === $this->files->files_tokens[ $file_name ][ $block_end_index + 1 ] ) {
      $count = count( $this->files->files_tokens );
      do {
        $block_end_index++;
      } while ( !(is_array( $this->files->files_tokens[ $file_name ][ $block_end_index ] )
      && ( T_ENDIF === $this->files->files_tokens[ $file_name ][ $block_end_index ][ 0 ] )) );
    } elseif ( '{' === $this->files->files_tokens[ $file_name ][ $block_end_index + 1 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index + 1, '{' );
    }

    $block_start_index++;
    $this->main_parser( $file_name, $function_name, $block_start_index, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse switch conditional statement. Currentely it only calls the function $this->main_parser.
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
    if ( ':' === $this->files->files_tokens[ $file_name ][ $block_end_index + 1 ] ) {
      do {
        $block_end_index++;
      } while ( !(is_array( $this->files->files_tokens[ $file_name ][ $block_end_index ] )
      && ( T_ENDSWITCH === $this->files->files_tokens[ $file_name ][ $block_end_index ][ 0 ] )) );
    }

    $block_start_index++;
    $this->main_parser( $file_name, $function_name, $block_start_index, $block_end_index );

    return( $block_end_index);
  }

  /**
   * Parse include, include_once, require and require_once.
   * All of them are processed by calling the function $this->main_parser.
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

//if there is an '(' after the include, include_once, require, require_once
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

    $file_name = $file_path . $file_name_include;
    $file_name = realpath( dirname( $file_name ) ) . DIRECTORY_SEPARATOR . basename( $file_name );

//only parse the file if it is in the multi-dimensional array variable $files_tokens
//only analyze the included file if it has not been anayzed yet
    if ( in_array( $file_name, $this->files->files_tokens ) ) {

// get the ...ONCE attribute
      if ( ( T_INCLUDE_ONCE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] )
          || ( T_REQUIRE_ONCE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) ) {
        $once = 'true';
      } else {
        $once = 'false';
      }

// get the INCLUDE.../REQUIRE... attribute    
      if ( ( T_INCLUDE_ONCE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] )
          || ( T_INCLUDE === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) ) {
        $include_require = 'include';
      } else {
        $include_require = 'require';
      }

      $yes_include_require = false;
//store the include/require information int the multi-dimensional array variable $files_include_require
      for ( $i = 0, $count = count( $this->files_include_require ); $i < $count; $i++ ) {
//check if the included/required file has already been included
        if ( ( $file_name === $this->files_include_require[ $i ][ 'include_require_file_name' ] )
            && ($include_require === $this->files_include_require[ $i ][ 'include_require' ] )
            && ($once === $this->files_include_require[ $i ][ 'once' ] ) ) {
//the file has already been included/required once
          $this->files_include_require[ $i ][ 'number_of_calls' ] +=1;
//If is not a ...ONCE then it will be parsed every time
          if ( 'false' === $once ) {
            $this->files_include_require[ $i ][ 'number_of_calls_executed' ] +=1;
            $yes_include_require = true;
          }
          break;
        }
      }

//if this include/require has not yet been processed then add it to the multi-dimensional array variable $files_include_require
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

//only parse the included/required file if it has not yet been parsed or it is not a ...ONCE file
      if ( true === $yes_include_require ) {
        $this->main_parser( $file_name, null, null, null );
      }
    }
    return( $block_end_index);
  }

  /**
   * parse functions
   * 
   * TODO passing by reference
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

    $called_function_name = $this->get_function_method_name( $file_name, $block_start_index );

    if ( $this->is_method( $file_name, $block_start_index ) ) {
//it is an object user defined function
      $block_start_index+=2;
    }

//calculate the end token of the function call        
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index + 1, '(' );
    } else {
      $block_end_index = $this->find_token( $file_name, $block_start_index + 1, ';' );
    }
    $block_start_index++;

//get the index of the function in the multi-dimensional array $files_tokens
    $called_function_index = null;
// search for the code of the PHP user defined function
    for ( $i = 0, $count = count( $this->files_functions ); $i < $count; $i++ ) {
//note: user defined PHP functions are not case sensitive
      if ( 0 === strcasecmp( $called_function_name, $this->files_functions[ $i ][ 'function_name' ] ) ) {
        $called_function_index = $i;
// When the function is found in the the multi-dimensional array $this->files_functions
// there is no need to continue searching for more because there is only one function with the same name
        break;
      }
//there is no need for the else, because the function has to exist when arriving here
    }

    if ( !is_null( $called_function_index ) ) {
//found the code of the PHP user defined function
//so it is a PHP user defined function
      $called_function_file_name = $this->files_functions[ $called_function_index ][ 'file_name' ];

//if it is a user defined function test to see if it is already being parsed
//should not parse functions with recursivity because it will never stop
      $is_function_already_being_parsed = false;
      for ( $i = 0, $count = count( $this->files_functions_stack ); $i < $count; $i++ ) {
        if ( $called_function_name === $this->files_functions_stack[ $i ][ 'function_name' ] ) {
          $is_function_already_being_parsed = true;
          break;
        }
      }

//if the function is not already being parsed then parse it
      if ( false === $is_function_already_being_parsed ) {
//push the function to the stack
        $this->files_functions_stack[ ] = array(
          'function_name' => $called_function_name,
        );

        $this->parse_user_defined_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name );

//pop the function from the stack
//unset the $files_functions_stack but keep the indexes untouched
        unset( $this->files_functions_stack[ count( $this->files_functions_stack ) - 1 ] );
//normalize the indexes
        $this->files_functions_stack = array_values( $this->files_functions_stack );
      }

//all other functions that are not defined in the parsed PHP files, like echo, print, exit
    } else {
      $this->parse_other_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name );
    }

    return( $block_end_index);
  }

  /**
   * It is a user defined function so it is parsed
   * 
   * note: You define a function with parameters, you call a function with arguments.
   * 
   * @param string $file_name with the PHP file name of the calling function
   * @param string $function_name with the name of the function where the code is being executed, the calling function.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
   * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
   * @param string $called_function_name with the name of the function, the called function
   */
  function parse_user_defined_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name ) {
    
  }

  /**
   * If the function is one of the output functions it is checked for tainted variables that could cause a vulnerability.
   * 
   * note: You define a function with parameters, you call a function with arguments.
   * 
   * @param string $file_name with the PHP file name of the calling function
   * @param string $function_name with the name of the function where the code is being executed, the calling function.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
   * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
   * @param string $called_function_name with the name of the function, the called function
   */
  function parse_other_function_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name ) {
    
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

//calculate the end token of the return statement
    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
    } else {
      $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );
    }

    $block_start_index++;
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
   * parse the '=' token
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

//find the variable that is assigned something by searching backwards in the multi-dimensional array $files_tokens
    $variable_before_equal_name = null;
    $i = $block_start_index;

//get the name of the assigned variable or method proterty (the one before the '=' sign)
    do {
      if ( ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) )
          && (( $this->is_variable( $file_name, $i ) ) || ( $this->is_property( $file_name, $i ) )) ) {
        $v = $i;
//$v is passed by reference
        $variable_before_equal_name = $this->get_variable_property_complete_array_name( $file_name, $v );
      }
      $i--;
    } while ( ( 0 <= $i) && (is_null( $variable_before_equal_name )) );

    $variable_before_equal_index = $this->get_variable_index( $variable_before_equal_name, $function_name );
    $block_end_index = $this->end_of_php_line( $file_name, $block_start_index );

    $block_start_index++;
    $this->parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index );

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
   * @param string $variable_before_equal_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index ) {
    
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    //find the variable that is assigned something by searching backwards in the multi-dimensional array $files_tokens
    $variable_before_as_name = null;
    $i = $block_start_index;

    //get the name of the assigned variable or method proterty (the one before the AS token)
    do {
      if ( ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) )
          && (( $this->is_variable( $file_name, $i ) ) || ( $this->is_property( $file_name, $i ) )) ) {
        $v = $i;
        //$v is passed by reference
        $variable_before_as_name = $this->get_variable_property_complete_array_name( $file_name, $v );
      }
      $i--;
    } while ( ( 0 <= $i) && (is_null( $variable_before_as_name )) );

    $variable_before_as_index = $this->get_variable_index( $variable_before_as_name, $function_name );
    $block_end_index = $this->end_of_php_line( $file_name, $block_start_index );

    $block_start_index++;
    $this->parse_as_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index );

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
   * @param string $variable_before_as_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_as_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index ) {
    
  }

  /**
   * Parse variables and object properties
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $code_type = PHP_CODE;
    $function_name = $this->find_function_name_of_code( $file_name, $block_start_index );

    if ( T_GLOBAL === $this->files->files_tokens[ $file_name ][ $block_start_index ][ 0 ] ) {
      $variable_scope = 'global';
      $block_start_index++;
    } else {
      $variable_scope = 'local';
    }

    $block_end_index = $block_start_index;
    //$block_end_index is passed by reference
    $variable_name = $this->get_variable_property_complete_array_name( $file_name, $block_end_index );

    //If there is a function call inside the variable definition it should be executed
    $this->main_parser( $file_name, $function_name, $block_start_index + 1, $block_end_index );

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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    if ( '(' === $this->files->files_tokens[ $file_name ][ $block_start_index + 1 ] ) {
      $block_end_index = $this->find_match( $file_name, $block_start_index, '(' );
      $block_start_index++;
    } else {
      $block_end_index = $this->find_token( $file_name, $block_start_index, ';' );
    }

    $i = $this->parse_variable( $file_name, $function_name, $block_start_index + 1 );

    $v = $block_start_index + 1;
//$v is passed by reference
    $variable_name = $this->get_variable_property_complete_array_name( $file_name, $v );

    $variable_index = $this->get_variable_index( $variable_name, $function_name );

    $this->parse_unset_vulnerability( $block_end_index, $variable_index );

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
   * @param string $variable_index with the index of tokens the the multi-dimensional array $parser_variables
   */
  function parse_unset_vulnerability( $block_end_index, $variable_index ) {
    
  }

  /**
   * Find the start of the PHP line of code.
   * the start of PHP line is calculated by searching backward for the first occurrence of either ';', '}', '{', T_OPEN_TAG, T_OPEN_TAG_WITH_ECHO
   *
   * TODO search for a better algoritm
   * 
   * @param int $pointer with the index of the multi-dimensional array $files_tokens
   * @return int with the index of multi-dimensional associative array $files_tokens that corresponds to the start of the PHP line of code
   */
  function start_of_php_line( $file_name, $pointer ) {
    $is_start_of_line = false;

    do {
//search for the first occurrence of either ';', '}', '{'
      if ( ( ';' === $this->files->files_tokens[ $file_name ][ $pointer ] )
          || ( '}' === $this->files->files_tokens[ $file_name ][ $pointer ] )
          || ('{' === $this->files->files_tokens[ $file_name ][ $pointer ] ) ) {
        $is_start_of_line = true;

//search for the first occurrence of either T_OPEN_TAG, T_OPEN_TAG_WITH_ECHO
      } elseif
      ( ( T_OPEN_TAG === $this->files->files_tokens[ $file_name ][ $pointer ][ 0 ] )
          || ( T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[ $file_name ][ $pointer ][ 0 ] ) ) {
        $is_start_of_line = true;

//keep searching if nothing was found
      } elseif ( false === $is_start_of_line ) {
        $pointer--;
      }

//keep searching if nothing was found and it is not the start of the PHP file
    } while ( (false === $is_start_of_line) && (0 < $pointer) );

    return $pointer;
  }

  /**
   * Find the end of the PHP line of code
   * the end of PHP line is calculated by searching forward for the first occurrence of either ';', '}', '{', T_CLOSE_TAG
   * 
   * TODO search for a better algoritm
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param int $pointer with the index of the multi-dimensional array $files_tokens
   * 
   * @return int with the index of multi-dimensional associative array $iles_tokens that corresponds to the end of the PHP line of code
   */
  function end_of_php_line( $file_name, $pointer ) {
    $is_end_of_line = false;
    $count = count( $this->files->files_tokens[ $file_name ] ) - 1;

    do {
//search for the first occurrence of either ';', '}', '{'
      if ( ( ';' === $this->files->files_tokens[ $file_name ][ $pointer ] )
          || ( '}' === $this->files->files_tokens[ $file_name ][ $pointer ] )
          || ( '{' === $this->files->files_tokens[ $file_name ][ $pointer ] ) ) {
        $is_end_of_line = true;

//search for the first occurrence of either T_CLOSE_TAG
      } elseif ( T_CLOSE_TAG === $this->files->files_tokens[ $file_name ][ $pointer ][ 0 ] ) {
        $is_end_of_line = true;

//keep searching if nothing was found
      } elseif ( false === $is_end_of_line ) {
        $pointer++;
      }

//keep searching if nothing was found and it is not the end of the PHP file
    } while ( ( $is_end_of_line === false ) && ($count - 1 > $pointer) );

//if after the ';' it is the end of the PHP block then the end of the line is the end of the PHP block
    if ( ( ';' === $this->files->files_tokens[ $file_name ][ $pointer ] )
        && ( T_CLOSE_TAG === $this->files->files_tokens[ $file_name ][ $pointer + 1 ][ 0 ] ) ) {
      $pointer++;
    }

    return $pointer;
  }

  /**
   * Search for the matching end token of the open token passed as an argument.
   * The search ends when the matching token is found
   * There is a guarantee that a pair of tokens is found (or the end of the PHP file)
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $open_token with the open token, that can be a '(' or a '{'
   * 
   * @return int with the index of the matching close token in the multi-dimensional associative array $files_tokens
   */
  function find_match( $file_name, $block_start_index, $open_token ) {
//calculate the matching close token
    switch ( $open_token ) {
      case '(':
        $close_token = ')';
        break;
      case '{':
        $close_token = '}';
        break;
      case '[':
        $close_token = ']';
        break;

      default:
        return null;
        break;
    }

    $count_open = 0;
    $count_close = 0;

//search for the match by taking into account the number of pairs of matching tokens
    for ( $i = $block_start_index, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count; $i++ ) {
      if ( ( $open_token === $this->files->files_tokens[ $file_name ][ $i ] )
          || ((is_array( $this->files->files_tokens[ $file_name ][ $i ] )) && ('{' === $open_token) && (T_CURLY_OPEN === $this->files->files_tokens[ $file_name ][ $i ][ 0 ]) ) ) {
        $count_open++;
      } elseif ( $close_token === $this->files->files_tokens[ $file_name ][ $i ] ) {
        $count_close++;
//end searching when the number of pairs of matching tokens is 0
//this condition is tested only when a close token is found
        if ( 0 === $count_open - $count_close ) {
          break;
        }
      }
    }

//$i contains the index of the matching close token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
    return $i;
  }

  /**
   * Search for the next token passed as an argument in the multi-dimensional associative array $files_tokens.
   * If in between there are '(' '{' " ' it resumes the search only after the matching ')' '}' " '
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $token with the token
   * 
   * @return int with the index of the end token in the multi-dimensional associative array $files_tokens
   */
  function find_token( $file_name, $block_start_index, $token ) {
//search for the end of the function
    for ( $i = $block_start_index, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count; $i++ ) {
      if ( $this->files->files_tokens[ $file_name ][ $i ] === $token ) {
        break;
      }
//skip if a pair of (..) or {..} is found
      if ( ( '(' === $this->files->files_tokens[ $file_name ][ $i ] )
          || ( '{' === $this->files->files_tokens[ $file_name ][ $i ] )
          || ((is_array( $this->files->files_tokens[ $file_name ][ $i ] )) && (T_CURLY_OPEN === $this->files->files_tokens[ $file_name ][ $i ][ 0 ]) ) ) {
        if ( ((is_array( $this->files->files_tokens[ $file_name ][ $i ] )) && (T_CURLY_OPEN === $this->files->files_tokens[ $file_name ][ $i ][ 0 ]) ) ) {
          $i = $this->find_match( $file_name, $i, '{' );
        } else {
          $i = $this->find_match( $file_name, $i, $this->files->files_tokens[ $file_name ][ $i ] );
        }
      }
    }

//$i contains the index of the token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
    return $i;
  }

  function find_previous_containing_function_from_index( $file_name, $block_index ) {
    $function_name = null;
    $token = $this->files->files_tokens[ $file_name ];
    for ( $i = 0; $i < $block_index; $i++ ) {

      if ( ( T_ECHO === $token[ $i ][ 0 ] )
          || ( T_PRINT === $token[ $i ][ 0 ] )
          || ( T_EXIT === $token[ $i ][ 0 ] )
          || ($this->is_function( $file_name, $i ))
          || ($this->is_method( $file_name, $i )) ) {
//calculate the end token of the function call        
        $called_function_name = $this->get_function_method_name( $file_name, $i );

        if ( '(' === $this->files->files_tokens[ $file_name ][ $i + 1 ] ) {
          $function_end_index = $this->find_match( $file_name, $i + 1, '(' );
        } else {
          $function_end_index = $this->find_token( $file_name, $i + 1, ';' );
        }
        if ( ($block_index >= $i) && ($block_index <= $function_end_index) ) {
          $function_name = $called_function_name;
        }
        if ( $this->is_method( $file_name, $i ) ) {
//it is an object user defined function
          $i+=2;
        }
      }
    }

//$i contains the index of the token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
    return $function_name;
  }

  /**
   * Search for the name of the function from which the code in the multi-dimensional associative array $files_tokens belongs to.
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return string with the name of the function or the string 'function' in the case the code is from outside any function
   */
  function find_function_name_of_code( $file_name, $file_index ) {
//search for user defined functions in the multi-dimensional associative array $files_tokens
    if ( !empty( $this->files_functions ) ) {
      foreach ( $this->files_functions as $key => $value ) {
        if ( ( $value[ 'file_name' ] === $file_name)
            && ( $value[ 'file_tokens_start_index' ] <= $file_index)
            && ( $value[ 'file_tokens_end_index' ] >= $file_index) ) {
          return $value[ 'function_name' ];
        }
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
//search for user defined functions in the multi-dimensional associative array $files_tokens
    if ( !empty( $this->files_functions ) ) {
      foreach ( $this->files_functions as $key => $value ) {
        if ( ( $value[ 'file_name' ] === $file_name)
            && ( $value[ 'function_name' ] === $function_name) ) {
          return true;
        }
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
   * TODO objects of objects
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
      $token = $this->files->files_tokens[ $file_name ];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
      if ( ($file_index >= 2) && (T_OBJECT_OPERATOR === $token[ $file_index - 1 ][ 0 ] ) ) {
        $file_index = $file_index - 2;
      }

//method
      if ( ( T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $token[ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $token[ $file_index + 2 ][ 0 ] )
          && ( '(' === $token[ $file_index + 3 ][ 0 ] ) ) {
        return 'method';

//property
      } elseif ( ( T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $token[ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $token[ $file_index + 2 ][ 0 ] )
          && ( '(' != $token[ $file_index + 3 ][ 0 ] ) ) {
        return 'property';

//variable
      } elseif ( ( T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( '(' != $token[ $file_index + 1 ][ 0 ] ) ) {
        return 'variable';

//function
      } elseif ( ( T_STRING === $token[ $file_index ][ 0 ] )
          && ( '(' === $token[ $file_index + 1 ][ 0 ] ) ) {
        return 'function';

//function
      } elseif ( ( T_ECHO === $token[ $file_index ][ 0 ] )
          || (T_PRINT === $token[ $file_index ][ 0 ] )
          || (T_EXIT === $token[ $file_index ][ 0 ] ) ) {
        return 'function';
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  function get_function_method_index() {
    
  }

  /**
   * get the name of the php user defined function or an object method by parsing the multi-dimensional associative array $files_tokens
   * 
   * TODO objects of objects
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return string with the name of the php user defined function or the object method or 'variable' or 'property' or null
   */
  function get_function_method_name( $file_name, $file_index ) {
    $name = null;
//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
    if ( $file_index >= 0 ) {
      $token = $this->files->files_tokens[ $file_name ];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
      if ( ($file_index >= 2) && (T_OBJECT_OPERATOR === $token[ $file_index - 1 ][ 0 ] ) ) {
        $file_index = $file_index - 2;
      }

//method
      if ( ( T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $token[ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $token[ $file_index + 2 ][ 0 ] )
          && ( '(' === $token[ $file_index + 3 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ] . $token[ $file_index + 1 ][ 1 ] . $token[ $file_index + 2 ][ 1 ];
        return $name;

//property
      } elseif ( ( T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $token[ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $token[ $file_index + 2 ][ 0 ] )
          && ('(' != $token[ $file_index + 3 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ] . $token[ $file_index + 1 ][ 1 ] . $token[ $file_index + 2 ][ 1 ];
        return 'variable';

//variable
      } elseif ( (T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( '(' != $token[ $file_index + 1 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ];
        return 'variable';

//function
      } elseif ( ( T_STRING === $token[ $file_index ][ 0 ] )
          && ( '(' === $token[ $file_index + 1 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ];
        return $name;

//function
      } elseif ( ( T_ECHO === $token[ $file_index ][ 0 ] )
          || ( T_PRINT === $token[ $file_index ][ 0 ] )
          || ( T_EXIT === $token[ $file_index ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ];
        return $name;
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  /**
   * get the name of the php variable or an object property by parsing the multi-dimensional associative array $files_tokens
   *  
   * TODO objects of objects
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return string with the name of the php variable or the object property or 'function' or 'method' or null
   */
  function get_variable_property_name( $file_name, $file_index ) {
    $name = null;
//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
    if ( $file_index >= 0 ) {
      $token = $this->files->files_tokens[ $file_name ];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
      if ( ($file_index >= 2) && (T_OBJECT_OPERATOR === $token[ $file_index - 1 ][ 0 ] ) ) {
        $file_index = $file_index - 2;
      }

//method
      if ( ( T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $token[ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $token[ $file_index + 2 ][ 0 ] )
          && ( '(' === $token[ $file_index + 3 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ] . $token[ $file_index + 1 ][ 1 ] . $token[ $file_index + 2 ][ 1 ];
        return 'function';

//property
      } elseif ( ( T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( T_OBJECT_OPERATOR === $token[ $file_index + 1 ][ 0 ] )
          && ( T_STRING === $token[ $file_index + 2 ][ 0 ] )
          && ('(' != $token[ $file_index + 3 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ] . $token[ $file_index + 1 ][ 1 ] . $token[ $file_index + 2 ][ 1 ];
        return $name;

//variable
      } elseif ( (T_VARIABLE === $token[ $file_index ][ 0 ] )
          && ( '(' != $token[ $file_index + 1 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ];
        return $name;

//function
      } elseif ( ( T_STRING === $token[ $file_index ][ 0 ] )
          && ( '(' === $token[ $file_index + 1 ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ];
        return 'function';

//function
      } elseif ( ( T_ECHO === $token[ $file_index ][ 0 ] )
          || ( T_PRINT === $token[ $file_index ][ 0 ] )
          || ( T_EXIT === $token[ $file_index ][ 0 ] ) ) {
        $name = $token[ $file_index ][ 1 ];
        return 'function';
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  /**
   * get the name of the php variable or an object property by parsing the multi-dimensional associative array $files_tokens
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index passed by reference with the index of the variable in the multi-dimensional array $files_tokens
   * 
   * @return the name of the variable and in the $file_index parameter the last index of the variable in the multi-dimensional array $files_tokens
   */
  function get_variable_property_complete_array_name( $file_name, &$file_index ) {
    $variable_name = $this->get_variable_property_name( $file_name, $file_index );
    if ( ($this->is_variable( $file_name, $file_index )) || ($this->is_property( $file_name, $file_index )) ) {
      if ( $this->is_variable( $file_name, $file_index ) ) {
        $file_index++;
      } elseif ( $this->is_property( $file_name, $file_index ) ) {
        $file_index = $file_index + 3;
      }
      for ( $i = $file_index, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count - 1; $i++ ) {
        $add_index = 0;
        // test to see if it is an array variable
        if ( '[' === $this->files->files_tokens[ $file_name ][ $i ] ) {
          $block_end_index = $this->find_match( $file_name, $i, '[' );
          for ( $j = $i; $j < $block_end_index; $j++ ) {
            $add_index++;
            if ( is_array( $this->files->files_tokens[ $file_name ][ $j ] ) ) {
              $variable_name = $variable_name . $this->files->files_tokens[ $file_name ][ $j ][ 1 ];
            } else {
              $variable_name = $variable_name . $this->files->files_tokens[ $file_name ][ $j ];
            }
          }
          $variable_name = $variable_name . ']';
        } elseif ( is_array( $this->files->files_tokens[ $file_name ][ $file_index ] ) ) {
          // test to see if it is an object
          if ( $this->is_property( $file_name, $i - 1 ) || $this->is_method( $file_name, $i - 1 ) ) {
            $variable_name = $this->get_variable_property_complete_array_name( $file_name, $i );
            $add_index = 1;
          } else {
            break;
          }
        } else {
          break;
        }
        $i+=$add_index;
      }
      $file_index = $i - 1;
      return $variable_name;
    } else {
      return $variable_name;
    }
  }

  function get_object_name( $name ) {
    $prefix = explode( '->', $name, 2 );
    $object_name = $prefix[ 0 ];
    if ( $object_name === $name ) {
      $object_name = null;
    }

    return $object_name;
  }

  function get_object_property_index( $function_name, $property_name ) {
    $prefix = explode( '->', $property_name, 2 );
    $object_property_index = $this->get_variable_index( $prefix[ 0 ], $function_name );
    return $object_property_index;
  }

  /**
   * Search for the most recent apearence of the variable in the multi-dimensional associative array $parser_variables.
   * This is done by searching backwards the the multi-dimensional associative array $parser_variables.
   *
   * @param string $variable_name with the name of the variable
   * @param string $function_name with the name of the function where the code is being executed.
   * 
   * @return int with the index of the most recent apearence of the variable in the multi-dimensional associative array $parser_variables
   */
  function get_variable_index( $variable_name, $function_name ) {
    $count = count( $this->parser_variables );
    for ( $i = $count - 1; $i >= 0; $i-- ) {
//note: PHP functions are not case sensitive
      if ( ( $variable_name === $this->parser_variables[ $i ][ 'variable_name' ] )
          && (0 === strcasecmp( $this->parser_variables[ $i ][ 'function_name' ], $function_name ) ) ) {
        return $i;
      }
    }
    return null;
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

// The ending PHP tag is omitted. This is actually safer than including it.