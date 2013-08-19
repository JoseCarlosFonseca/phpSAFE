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

define( 'APP', 'phpSAFE - PHP Security Analysis For Everyone' );

require_once 'vulnerability_classification.php';
require_once 'class-vulnerable-input.php';
require_once 'class-vulnerable-output.php';
require_once 'class-vulnerable-filter.php';
require_once 'class-php-parser.php';

//TODO context checking
//(see http://wp.tutsplus.com/tutorials/creative-coding/data-sanitization-and-validation-with-wordpress/
//and http://codex.wordpress.org/Data_Validation
//and http://fieldguide.automattic.com/avoiding-xss/)
//
//TODO optimize variables by reducing the number of variables
//Use only input and output variables, and maybe variables that are filtered/unfiltered
//Do the vulnerability check on top of this
class PHP_SAFE extends PHP_Parser {

  /**
   * Multi-dimensional associative array with the PHP vulnerable variables attributes
   * @var array
   */
  protected $vulnerable_variables;

  /**
   * Multi-dimensional associative array with the PHP output variables attributes
   * @var array
   */
  protected $output_variables;

  /**
   * It is a user defined function so it is parsed
   * 
   * TODO deal with the global variables
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $start_index = $block_start_index;
    $end_index = $block_end_index;

    // if it is a user defined function then the code is parsed
    for ( $i = 0, $count = count( $this->files_functions ); $i < $count; $i++ ) {
      //note: PHP functions are not case sensitive
      if ( 0 === strcasecmp( $target_function_name, $this->files_functions[ $i ][ 'function_name' ] ) ) {
        $file_name = $this->files_functions[ $i ][ 'file_name' ];
        $block_start_index = $this->files_functions[ $i ][ 'file_tokens_start_index' ];
        $block_end_index = $this->files_functions[ $i ][ 'file_tokens_end_index' ];

        //add local variables (from the parameters of the function) based on the variables of the arguments
        $j_count = 0;
        for ( $j = $start_index; $j < $end_index; $j++ ) {
          $function_argument = null;
          if ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $j ][ 0 ] ) {
            $index = $j;
            //$index (the $files_tokens index) is passed by reference
            $function_argument_name = $this->get_variable_name( $file_name, $index );
            $function_parameter_name = $this->files_functions[ $i ][ 'function_parameters' ][ $j_count ];
            //add the variable name, variable used in PHP or outside PHP, input variable, the function name, the file name and the line number and the taint value, variable classification, and the $parserFileTokens array index
            //create a local variable with the name of the parameter and the contents of the argument
            $variable_index = $this->get_variable_index( $function_argument_name, $function_name );
            $j = $this->parse_variable( $file_name, $target_function_name, $j );
            $function_argument_index = $this->get_variable_index( $function_argument_name, $function_name );
            //If the variable is an object and it is tainted, then the contents of that variable are also tainted
            $prefix = explode( '->', $function_parameter_name, 2 );
            $object_variable_name = $prefix[ 0 ];

            $this->parser_variables[ $function_argument_index ][ 'variable_name' ] = $function_parameter_name;
            $this->parser_variables[ $function_argument_index ][ 'object_variable_name' ] = $object_variable_name;
            $this->parser_variables[ $function_argument_index ][ 'function_name' ] = $target_function_name;
            $this->parser_variables[ $function_argument_index ][ 'tainted' ] = $this->parser_variables[ $variable_index ][ 'tainted' ];
            //A variable used in an output function is an output variable
            $this->parser_variables[ $function_argument_index ][ 'output_variable' ] = OUTPUT_VARIABLE;
          }
          if ( ',' === $this->files->files_tokens[ $file_name ][ $j ] ) {
            $j_count++;
          }
        }
        $block_start_index = $this->find_match( $file_name, $block_start_index, '(' );
        $this->main_parser( $file_name, $target_function_name, $block_start_index, $block_end_index - 1 );
      }
    }

    //The function is not an output function, but it is not also defined in the code
    if ( $i === $count ) {
      for ( $j = $start_index; $j < $end_index; $j++ ) {
        if ( T_VARIABLE === $this->files->files_tokens[ $file_name ][ $j ][ 0 ] ) {
          $j = $this->parse_variable( $file_name, $target_function_name, $j );
        }
      }
    }

    //find the last file line number of the function
    $file_line_number = 1;
    for ( $j = $end_index; $j >= 0; $j-- ) {
      if ( is_array( $this->files->files_tokens[ $file_name ][ $j ] ) ) {
        $file_line_number = $this->files->files_tokens[ $file_name ][ $j ][ 2 ];
        break;
      }
    }

    //TODO deal here with the global variables
    //unset all the variables used within the function
    $count = count( $this->parser_variables );
    for ( $i = $count - 1; $i >= 0; $i-- ) {
      //note: PHP functions are not case sensitive
      if ( (0 === strcasecmp( $this->parser_variables[ $i ][ 'function_name' ], $target_function_name ) )
          && (EXIST === $this->parser_variables[ $i ][ 'exist_destroyed' ] ) ) {
        $variable_index = $this->get_variable_index( $this->parser_variables[ $i ][ 'variable_name' ], $target_function_name );
        //it the variable was not yet destroyed, then create a variable destroyed
        if ( EXIST === $this->parser_variables[ $i ][ 'exist_destroyed' ] ) {
          if ( $target_function_name === $this->parser_variables[ $i ][ 'variable_name' ] ) {
            //if the variable that is the return of the function, then a new variable is created
            //as an untainted variable of the calling function
            $new_function_name = $function_name;
            $tainted = $this->parser_variables[ $i ][ 'tainted' ];
            $exist_destroyed = EXIST;

            $this->parser_variables[ ] = array(
              'variable_name' => $this->parser_variables[ $i ][ 'variable_name' ],
              'object_variable_name' => $this->parser_variables[ $i ][ 'object_variable_name' ],
              'scope' => $this->parser_variables[ $i ][ 'scope' ],
              'variable_function' => $this->parser_variables[ $i ][ 'variable_function' ],
              'exist_destroyed' => $exist_destroyed,
              'code_type' => $this->parser_variables[ $i ][ 'code_type' ],
              'input_variable' => $this->parser_variables[ $i ][ 'input_variable' ],
              'output_variable' => $this->parser_variables[ $i ][ 'output_variable' ],
              'function_name' => $new_function_name,
              'file_name' => $this->parser_variables[ $i ][ 'file_name' ],
              'file_line_number' => $file_line_number,
              'tainted' => $tainted,
              'vulnerability_classification' => UNKNOWN,
              'file_tokens_start_index' => $end_index,
              'file_tokens_end_index' => $end_index,
              'variable_dependencies_index' => $i,
            );
          }

          $new_function_name = $this->parser_variables[ $i ][ 'function_name' ];
          $tainted = UNTAINTED;
          $exist_destroyed = DESTROYED;

          $this->parser_variables[ ] = array(
            'variable_name' => $this->parser_variables[ $i ][ 'variable_name' ],
            'object_variable_name' => $this->parser_variables[ $i ][ 'object_variable_name' ],
            'scope' => $this->parser_variables[ $i ][ 'scope' ],
            'variable_function' => $this->parser_variables[ $i ][ 'variable_function' ],
            'exist_destroyed' => $exist_destroyed,
            'code_type' => $this->parser_variables[ $i ][ 'code_type' ],
            'input_variable' => $this->parser_variables[ $i ][ 'input_variable' ],
            'output_variable' => $this->parser_variables[ $i ][ 'output_variable' ],
            'function_name' => $new_function_name,
            'file_name' => $this->parser_variables[ $i ][ 'file_name' ],
            'file_line_number' => $file_line_number,
            'tainted' => $tainted,
            'vulnerability_classification' => UNKNOWN,
            'file_tokens_start_index' => $end_index,
            'file_tokens_end_index' => $end_index,
            'variable_dependencies_index' => $i,
          );
        }
      }
    }
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    //test if it is one of the output functions
    //output functions with taintied variables originate vulnerabilities
    $vulnerability_classification = null;
    foreach ( Vulnerable_Output::$OUTPUT_FUNCTIONS as $key => $value ) {
      foreach ( $value as $output_function ) {
        //the name of the function is the same of any one from the $OUTPUT_FUNCTIONS
        //or it is an object method and the name after the -> is the same of any one from the $OUTPUT_FUNCTIONS
        if ( 0 === strcasecmp( $output_function, $target_function_name ) ) {//note: PHP functions are not case sensitive
          $vulnerability_classification = $key;
        }
      }
    }

    // if it is one of the output functions. It is not a user defined function, although it could be a WordPress function
    if ( !is_null( $vulnerability_classification ) ) {
      //get the variables of the arguments of the function
      for ( $i = $block_start_index; $i < $block_end_index; $i++ ) {
        if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
          //if it is a variable
          if ( ($this->is_variable( $file_name, $i )) || ($this->is_property( $file_name, $i )) ) {
            //add the variable name, variable used in PHP or outside PHP, input variable, the function name, the file name and the line number and the taint value, variable classification, and the $parserFileTokens array index
            //create a local variable with the name of the parameter and the contents of the argument
            $index = $i;
            //$index (the $files_tokens index) is passed by reference
            $output_variable_name = $this->get_variable_name( $file_name, $index );

            //If the variable is an object get the name of the object
            $prefix = explode( '->', $output_variable_name, 2 );
            $variable_index = $this->get_variable_index( $prefix[ 0 ], $function_name );
            $this->parse_variable( $file_name, $function_name, $i );
            $output_variable_index = $this->get_variable_index( $output_variable_name, $function_name );

            if ( is_null( $output_variable_index ) ) {
              continue;
            }

            //a variable used in an output function is an output variable
            $this->parser_variables[ $output_variable_index ][ 'output_variable' ] = OUTPUT_VARIABLE;

            //if the variable already existed the taint and vulnerability classification should be transferred to the current variable
            if ( !is_null( $variable_index ) ) {
              //if the variable is tainted, then we have a vulnerability
              if ( TAINTED === $this->parser_variables[ $variable_index ][ 'tainted' ] ) {
                $this->parser_variables[ $output_variable_index ][ 'tainted' ] = TAINTED;
                $this->parser_variables[ $output_variable_index ][ 'vulnerability_classification' ] = $vulnerability_classification;
              }
            }

//                        $this->debug('$start_index ' . $start_index . ' $output_variable_name ' . $output_variable_name . ' $variable_index ' . $variable_index . ' $output_variable_index ' . $output_variable_index . '<br />');
            $i = $index;

            //if it is a function or a method
          } elseif ( ($this->is_function( $file_name, $i )) || ($this->is_method( $file_name, $i - 2 )) ) {
            //in this case, an input function directely in an output function will be considered as a vulnerable variable with the same name of the function
            //test if it is one of the output functions
            $input_variable = null;
            foreach ( Vulnerable_Input::$INPUT_FUNCTIONS as $key => $value ) {//test if it is an input function
              foreach ( $value as $output_function ) {
                //note: PHP functions are not case sensitive
                if ( 0 === strcasecmp( $output_function, $this->get_variable_function_property_method_name( $file_name, $i ) ) ) {
                  $input_variable = INPUT_VARIABLE;
                  //check to see if it is an object user defined function
                  if ( $this->is_method( $file_name, $i - 2 ) ) {
                    $variable_name = $this->files->files_tokens[ $file_name ][ $i - 2 ][ 1 ] . $this->files->files_tokens[ $file_name ][ $i - 1 ][ 1 ] . $this->files->files_tokens[ $file_name ][ $i ][ 1 ];
                    $object_variable_name = $this->files->files_tokens[ $file_name ][ $i - 2 ][ 1 ];
                  } else {
                    $variable_name = $this->files->files_tokens[ $file_name ][ $i ][ 1 ];
                    $object_variable_name = null;
                  }
                  break;
                }
              }

              //add a new variable, which is the return value of the input function
              if ( !is_null( $input_variable ) ) {
                $this->parser_variables[ ] = array(
                  'variable_name' => $variable_name,
                  'object_variable_name' => $object_variable_name,
                  'scope' => 'local',
                  'variable_function' => 'function', //in fact, this is not a variable. It is the return value of a function (an input function)
                  'exist_destroyed' => EXIST,
                  'code_type' => PHP_CODE,
                  'input_variable' => $input_variable,
                  'output_variable' => OUTPUT_VARIABLE,
                  'function_name' => $function_name,
                  'file_name' => $file_name,
                  'file_line_number' => $this->files->files_tokens[ $file_name ][ $i ][ 2 ],
                  'tainted' => TAINTED,
                  'vulnerability_classification' => $vulnerability_classification,
                  'file_tokens_start_index' => $i,
                  'file_tokens_end_index' => $i + 2,
                  'variable_dependencies_index' => null );
                break;
              }
            }
            //if it is a usere defined function
            if ( $this->is_user_defined_function( $file_name, $this->files->files_tokens[ $file_name ][ $i ][ 1 ] ) ) {
              $this->parse_function( $file_name, $function_name, $i );
              //search for the return value of the function
              //the reutrn value used in an output function is an output variable
              $output_variable_index = $this->get_variable_index( $this->files->files_tokens[ $file_name ][ $i ][ 1 ], $function_name );

              if ( !is_null( $output_variable_index ) ) {
                $this->parser_variables[ $output_variable_index ][ 'output_variable' ] = OUTPUT_VARIABLE;
                //if the variable is tainted, then we have a vulnerability
                if ( TAINTED === $this->parser_variables[ $output_variable_index ][ 'tainted' ] ) {
                  $this->parser_variables[ $output_variable_index ][ 'vulnerability_classification' ] = $vulnerability_classification;
                }
              }
            }

            //continue to the next argument of the function
            continue;
          }
        }
      }
    }
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $block_start_index + 1, $block_end_index );

    // returns null if there is no variable
    $variable_index = $this->get_variable_index( $function_name, $function_name );
    if ( (!is_null( $variable_index )) && (EXIST === $this->parser_variables[ $variable_index ][ 'exist_destroyed' ] ) ) {
      //if the variable is tainted, then we have a vulnerability
      if ( $expression[ 'tainted' ] === TAINTED ) {
        $this->parser_variables[ $variable_index ][ 'tainted' ] = $expression[ 'tainted' ];
        $this->parser_variables[ $variable_index ][ 'vulnerability_classification' ] = $expression[ 'vulnerability_classification' ];
        $this->parser_variables[ $variable_index ][ 'variable_dependencies_index' ] = $expression[ 'variable_dependencies_index' ];
      }//else do nothing
    } else {
      //add a new variable, which is the return value of the input function
      $this->parser_variables[ ] = array(
        'variable_name' => $function_name,
        'object_variable_name' => null,
        'scope' => 'local',
        'variable_function' => 'function',
        'exist_destroyed' => EXIST,
        'code_type' => PHP_CODE,
        'input_variable' => REGULAR_VARIABLE,
        'output_variable' => REGULAR_VARIABLE,
        'function_name' => $function_name,
        'file_name' => $file_name,
        'file_line_number' => $this->files->files_tokens[ $file_name ][ $block_start_index ][ 2 ],
        'tainted' => $expression[ 'tainted' ],
        'vulnerability_classification' => $expression[ 'vulnerability_classification' ],
        'file_tokens_start_index' => $block_start_index,
        'file_tokens_end_index' => $block_end_index,
        'variable_dependencies_index' => $expression[ 'variable_dependencies_index' ] );
    }
  }

  /**
   * Parse an expression containing variables and functions.
   * Determines the attributes tainted, vulnerability_classification, variable_dependencies_index that will be returned
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * 
   * @return multi-dimensional associative array with the attributes tainted, vulnerability_classification, variable_dependencies_index
   */
  function parse_expression_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $tainted = UNTAINTED;
    $vulnerability_classification = null;
    $variable_dependencies_index = null;

    //look for variable protection in the right side of the equal sign
    for ( $i = $block_start_index; $i < $block_end_index; $i++ ) {
      //search for other variables after the equal sign
      $variable_tainted = UNTAINTED;
      $variable_vulnerability_classification = null;
      //it is a variable
      if ( $this->is_variable( $file_name, $i ) ) {
        $index = $i;
        //$index (the $files_tokens index) is passed by reference. When it is a function it returns the vlue 'function'
        $variable_name = $this->get_variable_name( $file_name, $index );
        //add the variable to the multi-dimensional associative array $parser_variables
        $this->parse_variable( $file_name, $function_name, $i );

        // $this->get_variable_index returns null if there is no variable
        $variable_index = $this->get_variable_index( $variable_name, $function_name );
        //add a variable dependency
        $variable_dependencies_index[ ] = $variable_index;

        //check if this variable is, in fact, an input function. In this case it should be an object user defined function, because an object starts with T_VARIABLE
        //if it is an object user defined function
        if ( 'function' === $variable_name ) {
          //test if it is one of the input functions
          //note: many input functions are user defined functions, namely wp functions
          $input_variable = null;
          if ( ($this->is_method( $file_name, $i )) || ($this->is_function( $file_name, $i )) ) {
            foreach ( Vulnerable_Input::$INPUT_FUNCTIONS as $key => $value ) {
              foreach ( $value as $output ) {
                //note: PHP functions are not case sensitive
                if ( 0 === strcasecmp( $output, $this->get_variable_function_property_method_name( $file_name, $i ) ) ) {
                  $input_variable = INPUT_VARIABLE;
                  break;
                }
              }
              if ( !is_null( $input_variable ) ) {
                break;
              }
            }
            if ( !is_null( $input_variable ) ) {
              //update the $input_variable value of the variable
              $variable_tainted = TAINTED;
            }
          }
        } else {
          //propagate the tainted attribute
          if ( TAINTED === $this->parser_variables[ $variable_index ][ 'tainted' ] ) {
            $variable_tainted = TAINTED;
          }
        }
        if ( TAINTED === $variable_tainted ) {
          $tainted = TAINTED;
        }
        $i = $index;

        //is a function or method
      } elseif ( ($this->is_function( $file_name, $i )) || ($this->is_method( $file_name, $i )) ) {
        $index = $this->parse_function( $file_name, $function_name, $i );

        //the return value of the function is a variable with the name of the function, so it is necessary to know the name of the function
        if ( $this->is_method( $file_name, $i ) ) {
          //it is an object user defined function
          $target_function_name = $this->get_variable_function_property_method_name( $file_name, $i );
          $block_start_index+=2;
        } else {
          //it is an user defined function
          $target_function_name = $this->get_variable_function_property_method_name( $file_name, $i );
        }

        //test if it is one of the input functions
        //note: many input functions are user defined functions, namely wp functions
        $input_variable = null;
        foreach ( Vulnerable_Input::$INPUT_FUNCTIONS as $key => $value ) {
          foreach ( $value as $output ) {
            //note: PHP functions are not case sensitive
            if ( 0 === strcasecmp( $output, $this->get_variable_function_property_method_name( $file_name, $i ) ) ) {
              $input_variable = INPUT_VARIABLE;
              break;
            }
          }
          if ( !is_null( $input_variable ) ) {
            break;
          }
        }

        //update the input_V_variable value of the variable
        if ( !is_null( $input_variable ) ) {
          $variable_tainted = TAINTED;
          $tainted = TAINTED;
        } else {
          //search for the return value of the function
          //it returns a value if the function is a user defined function with a return value
          // returns null if there is no variable
          $variable_index = $this->get_variable_index( $target_function_name, $function_name );
          if ( !is_null( $variable_index ) ) {
            //propagate the tainted attribute
            if ( TAINTED === $this->parser_variables[ $variable_index ][ 'tainted' ] ) {
              $tainted = TAINTED;
            }
            $variable_dependencies_index[ ] = $variable_index;

            //it may return null if it is a php function or a function which we have no code. In these cases search for the arguments
          } else {
            //The variable is tainted so we need to check if it has protection
            //get the variables of the arguments of the function
            $argument_end_index = $this->find_match( $file_name, $i + 1, '(' );
            for ( $j = $i + 1; $j < $argument_end_index; $j++ ) {
              if ( is_array( $this->files->files_tokens[ $file_name ][ $j ] ) ) {
                if ( $this->is_variable( $file_name, $j ) ) {//if it is a variable
                  //add the variable name, variable used in PHP or outside PHP, input variable, the function name, the file name and the line number and the taint value, variable classification, and the $parserFileTokens array index
                  //create a local variable with the name of the parameter and the contents of the argument
                  $jndex = $j;
                  //$jndex (the $files_tokens index) is passed by reference
                  $output_variable_name = $this->get_variable_name( $file_name, $jndex );
                  $variable_index = $this->get_variable_index( $output_variable_name, $function_name );
                  $this->parse_variable( $file_name, $function_name, $j );
                  $output_variable_index = $this->get_variable_index( $output_variable_name, $function_name );

                  $variable_filters = null;
                  if ( is_null( $output_variable_index ) ) {
                    continue;

                    //if the variable already existed the taint and vulnerability classification should be transferred to the current variable
                  } else {
                    $variable_filters = $this->get_variable_filters_and_revert_filters( $file_name, $j );
                    //if the variable is tainted, then we must check if the function is one of the filtering functions
                    if ( TAINTED === $this->parser_variables[ $output_variable_index ][ 'tainted' ] ) {
                      if ( $this->is_variable_filtered( $file_name, $j ) ) {
                        $variable_tainted = UNTAINTED;
                        $variable_vulnerability_classification = FILTERED;
                        if ( is_null( $vulnerability_classification ) ) {
                          $vulnerability_classification = FILTERED;
                        }
                      } else {
                        $variable_tainted = TAINTED;
                      }
                      if ( TAINTED === $variable_tainted ) {
                        $tainted = TAINTED;
                      }
                    }
                  }

                  if ( $variable_filters ) {
                    $output_variable_dependencies_index = array(
                      $output_variable_index => $variable_filters,
                    );
                  } else {
                    $output_variable_dependencies_index = $output_variable_index;
                  }
                  $variable_dependencies_index[ ] = $output_variable_dependencies_index;
//                        $this->debug('$start_index ' . $start_index . ' $output_variable_name ' . $output_variable_name . ' $variable_index ' . $variable_index . ' $output_variable_index ' . $output_variable_index . '<br />');
                  $j = $jndex;
                }
              }
            }
            $index = $argument_end_index;
          }
        }
        $i = $index;
      }
    }

    if ( is_null( $vulnerability_classification ) ) {
      $vulnerability_classification = UNKNOWN;
    }

    return( array(
      'tainted' => $tainted,
      'vulnerability_classification' => $vulnerability_classification,
      'variable_dependencies_index' => $variable_dependencies_index )
        );
  }

  /**
   * The variable at the left side of the '=' sign receives the attributes
   * tainted, vulnerability_classification, variable_dependencies_index of the variable at the right side of the '=' sign
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $variable_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $block_start_index + 1, $block_end_index );

    $this->parser_variables[ $variable_index ][ 'tainted' ] = $expression[ 'tainted' ];
    $this->parser_variables[ $variable_index ][ 'vulnerability_classification' ] = $expression[ 'vulnerability_classification' ];
    $this->parser_variables[ $variable_index ][ 'variable_dependencies_index' ] = $expression[ 'variable_dependencies_index' ];
  }

  /**
   * The variable at the right side of the AS token receives the attributes
   * tainted, vulnerability_classification, variable_dependencies_index of the variable at the left side of the AS token
   *  
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $variable_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_as_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $index = $block_start_index + 1;
    //$index (the $files_tokens index) is passed by reference. When it is a function it returns the vlue 'function'
    $new_variable_name = $this->get_variable_name( $file_name, $index );
    //add the variable to the multi-dimensional associative array $parser_variables
    $this->parse_variable( $file_name, $function_name, $block_start_index + 1 );

    // $this->get_variable_index return null if there is no variable
    $new_variable_index = $this->get_variable_index( $new_variable_name, $function_name );

    $this->parser_variables[ $new_variable_index ][ 'tainted' ] = $this->parser_variables[ $variable_index ][ 'tainted' ];
    $this->parser_variables[ $new_variable_index ][ 'vulnerability_classification' ] = $this->parser_variables[ $variable_index ][ 'vulnerability_classification' ];
    $this->parser_variables[ $new_variable_index ][ 'variable_dependencies_index' ][ ] = $variable_index;
  }

  /**
   * Extracts the variable information from the multi-dimensional array $files_tokens 
   * and stores it in the multi-dimensional associative array $parser_variables
   * Makes a distinction between regular and input variables
   * Taints the input variables
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

//        $this->debug('OLA 1 !!! $variable_name ' . $variable_name . '<br />');
    if ( !is_null( $variable_name ) && ($variable_name != 'function') ) {
      $line_number = $this->files->files_tokens[ $file_name ][ $block_start_index ][ 2 ];

      //regular variables are by default safe
      $output_variable = REGULAR_VARIABLE;

      //regular variables are by default safe
      $input_variable = REGULAR_VARIABLE;
      $tainted = UNTAINTED;

      //search for input vulnerable variables
      foreach ( Vulnerable_Input::$INPUT_VARIABLES as $key => $value ) {
        //search for PHP reserved variables
        foreach ( $value as $input_array_var ) {
//                        $this->debug('$input_array_var: ' . $input_array_var . ' - $token[$i][1]: ' . $token[$i][1] . '<br />');
          //if it is a PHP reserved variables
          if ( $this->get_variable_function_property_method_name( $file_name, $block_start_index ) === $input_array_var ) {
            $input_variable = INPUT_VARIABLE;
            $tainted = TAINTED;
//                                $this->debug('$variable_name: '.$variable_name.'<br />');
            break;
          }
        }
      }

      //find if the variable already exists. In this case the variable is updated
      //If the variable is an object and it is tainted, then the contents of that variable are also tainted
      $prefix = explode( '->', $variable_name, 2 );
      if ( $prefix[ 0 ] === $variable_name ) {
        $object_variable_name = null;
      } else {
        $object_variable_name = $prefix[ 0 ];
      }
      $variable_name_index = $this->get_variable_index( $prefix[ 0 ], $function_name );

      // if it is a variable process it. Otherwise leave this function 
      if ( !is_null( $variable_name_index ) ) {
        //If the variable already exists in the scope and is tainted, then this should be reflected in the current usage of the variable
        if ( TAINTED === $this->parser_variables[ $variable_name_index ][ 'tainted' ] ) {
          $tainted = TAINTED;
        }
      }
//            $this->debug('OLA 2 !!! $variable_name ' . $variable_name . ' $tainted '.$tainted.'<br />');
      // if it is a variable process it. Otherwise leave this function 
      if ( (is_null( $variable_name_index ))
          || ((!is_null( $variable_name_index ))
          && (($this->parser_variables[ $variable_name_index ][ 'file_tokens_start_index' ] != $block_start_index)
          && ($this->parser_variables[ $variable_name_index ][ 'file_tokens_end_index' ] != $block_end_index))) ) {
        //add the variable name, variable used in PHP or outside PHP, input variable?, the function name, the file name and the line number and the taint value, variable classification, and the $parserFileTokens array index
        //                $this->debug('OLA 3 !!! $variable_name ' . $variable_name . ' $line_number ' . $line_number . ' $block_start_index ' . $block_start_index . '<br />');               
        $this->parser_variables[ ] = array(
          'variable_name' => $variable_name,
          'object_variable_name' => $object_variable_name,
          'scope' => $variable_scope,
          'variable_function' => 'variable',
          'exist_destroyed' => EXIST,
          'code_type' => $code_type,
          'input_variable' => $input_variable,
          'output_variable' => $output_variable,
          'function_name' => $function_name,
          'file_name' => $file_name,
          'file_line_number' => $line_number,
          'tainted' => $tainted,
          'vulnerability_classification' => UNKNOWN,
          'file_tokens_start_index' => $block_start_index,
          'file_tokens_end_index' => $block_end_index,
          'variable_dependencies_index' => null );
      }

      //If the variable already exists in the scope the new variable depends on it and it is not in the same PHP line
      if ( ($variable_name_index) && ($this->start_of_php_line( $file_name, $block_start_index ) > $this->start_of_php_line( $file_name, $this->parser_variables[ $variable_name_index ][ 'file_tokens_end_index' ] )) ) {
        $newVariableNameIndex = $this->get_variable_index( $variable_name, $function_name );
        //do not add a dependency if it already exists
        $match = false;
        if ( is_array( $this->parser_variables[ $newVariableNameIndex ][ 'variable_dependencies_index' ] ) ) {
          foreach ( $this->parser_variables[ $newVariableNameIndex ][ 'variable_dependencies_index' ] as $key => $value ) {
            if ( $variable_name_index === $value ) {
              $match = true;
              break;
            }
          }
        }
        if ( false === $match ) {
          $this->parser_variables[ $newVariableNameIndex ][ 'variable_dependencies_index' ][ ] = $variable_name_index;
        }
      }

      //if the variable is used as a single code (maybe inside HTML code) and is tainted, then we may have a vulnerability
      if ( TAINTED === $tainted ) {
        $variable_name_index = $this->get_variable_index( $variable_name, $function_name );
        //obtain the line of code where the variable is located
        $start_of_php_line_index = $this->start_of_php_line( $file_name, $block_start_index );
        $end_of_php_line_index = $this->end_of_php_line( $file_name, $block_start_index );

        //if the start and the end of the line are PHP_OPEN_TAG and PH_CLOSE_TAG
        if ( ((T_OPEN_TAG === $this->files->files_tokens[ $file_name ][ $start_of_php_line_index ][ 0 ] )
            || (T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[ $file_name ][ $start_of_php_line_index ][ 0 ] ))
            && (T_CLOSE_TAG === $this->files->files_tokens[ $file_name ][ $end_of_php_line_index ][ 0 ] ) ) {
          $is_single_code = true;
          for ( $i = $start_of_php_line_index; $i < $end_of_php_line_index; $i++ ) {
            //it is considered as a single code if it has no loops nor conditional structures
            if ( (T_FOR === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_FOREACH === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_DO === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_WHILE === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_ENDWHILE === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_ELSEIF === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_ELSE === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_IF === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] )
                || (T_SWITCH === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) ) {
              $is_single_code = false;
              break;
            }
          }
          if ( true === $is_single_code ) {//vulnerabilityClassification is XSS
            $this->parser_variables[ $variable_name_index ][ 'vulnerability_classification' ] = XSS;
            $this->parser_variables[ $variable_name_index ][ 'output_variable' ] = OUTPUT_VARIABLE;
          }
        }
      }
    }
  }

  /**
   * Parses unset.
   * When the variable is unset, PHP destroys the variable.
   * For the vulnerability detection it is the same as being UNTAINTED
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $function_argument_index with the index of tokens the the multi-dimensional array $parser_variables
   */
  function parse_unset_vulnerability( $block_end_index, $function_argument_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $this->parser_variables[ $function_argument_index ][ 'tainted' ] = UNTAINTED;
    $this->parser_variables[ $function_argument_index ][ 'exist_destroyed' ] = DESTROYED;
    $this->parser_variables[ $function_argument_index ][ 'vulnerability_classification' ] = UNKNOWN;
  }

  /**
   * Get the protections of the variable that is an argument of a function, by order of appearence
   * 
   * TODO allowing more stuff than just function1(function2(var))
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
   * 
   * @return array of the name of the filtering functions
   */
  function get_variable_filters( $file_name, $block_end_index ) {
    $variable_protection_functions = null;
    $i = $block_end_index - 1;
    do {
      if ( '(' === $this->files->files_tokens[ $file_name ][ $i ] ) {
        $i--;
        continue;
      }
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        if ( T_STRING === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          $found_variable_filter = false;
          //test if it is one of the filtering functions                    
          foreach ( Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $this->files->files_tokens[ $file_name ][ $i ][ 1 ] ) ) {
                $variable_protection_functions[ ] = $output;
                $found_variable_filter = true;
                break;
              }
            }
            if ( $found_variable_filter ) {
              break;
            }
          }
        } else {
          return $variable_protection_functions;
        }
      }
      $i--;
    } while ( $i > 0 );
    return $variable_protection_functions;
  }

  /**
   * Get the protections and the revert protections of the variable that is an argument of a function, by order of appearence
   * 
   * TODO allowing more stuff than just function1(function2(var))
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
   * 
   * @return array of the name of the filtering functions
   */
  function get_variable_filters_and_revert_filters( $file_name, $block_end_index ) {
    $variable_protection_functions = null;
    $i = $block_end_index - 1;
    do {
      if ( '(' === $this->files->files_tokens[ $file_name ][ $i ] ) {
        $i--;
        continue;
      }
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        if ( T_STRING === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          $found_variable_filter = false;
          //test if it is one of the filtering functions                    
          foreach ( array_merge( Vulnerable_Filter::$VARIABLE_FILTERS, Vulnerable_Filter::$REVERT_VARIABLE_FILTERS ) as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $this->get_variable_function_property_method_name( $file_name, $i ) ) ) {
                $variable_protection_functions[ ] = $output;
                $found_variable_filter = true;
                break;
              }
            }
            if ( $found_variable_filter ) {
              break;
            }
          }
        } else {
          return $variable_protection_functions;
        }
      }
      $i--;
    } while ( $i > 0 );
    return $variable_protection_functions;
  }

  /**
   * Check if the variable that is an argument of a function is being protected by that function
   * 
   * TODO allowing more stuff than just function1(function2(var))
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
   * 
   * @return bool true if the variable is protected and false if the variable is not protected
   */
  function is_variable_filtered( $file_name, $block_end_index ) {
    $i = $block_end_index - 1;
    do {
      if ( '(' === $this->files->files_tokens[ $file_name ][ $i ] ) {
        $i--;
        continue;
      }
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        if ( T_STRING === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          //test if it is one of the filtering functions                    
          foreach ( Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $this->get_variable_function_property_method_name( $file_name, $i ) ) ) {
                return true;
              }
            }
          }
        }
        else return false;
      }
      $i--;
    } while ( $i > 0 );
    return false;
  }

  /**
   * Get the protections of the variable that is an argument of a function, by order of appearence
   * 
   * TODO allowing more stuff than just function1(function2(var))
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
   * 
   * @return array of the name of the filtering functions
   */
  function get_variable_revert_filters( $file_name, $block_end_index ) {
    $variable_protection_functions = null;
    $i = $block_end_index - 1;
    do {
      if ( '(' === $this->files->files_tokens[ $file_name ][ $i ] ) {
        $i--;
        continue;
      }
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        if ( T_STRING === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          $found_variable_filter = false;
          //test if it is one of the filtering functions                    
          foreach ( Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $this->files->files_tokens[ $file_name ][ $i ][ 1 ] ) ) {
                $variable_protection_functions[ ] = $output;
                $found_variable_filter = true;
                break;
              }
            }
            if ( $found_variable_filter ) {
              break;
            }
          }
        } else {
          return $variable_protection_functions;
        }
      }
      $i--;
    } while ( $i > 0 );
    return $variable_protection_functions;
  }

  /**
   * Check if the variable that is an argument of a function is being protected by that function
   * 
   * TODO allowing more stuff than just function1(function2(var))
   *
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
   * 
   * @return bool true if the variable is protected and false if the variable is not protected
   */
  function is_variable_revert_filtered( $file_name, $block_end_index ) {
    $i = $block_end_index - 1;
    do {
      if ( '(' === $this->files->files_tokens[ $file_name ][ $i ] ) {
        $i--;
        continue;
      }
      if ( is_array( $this->files->files_tokens[ $file_name ][ $i ] ) ) {
        if ( T_STRING === $this->files->files_tokens[ $file_name ][ $i ][ 0 ] ) {
          //test if it is one of the filtering functions                    
          foreach ( Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $this->files->files_tokens[ $file_name ][ $i ][ 1 ] ) ) {
                return true;
              }
            }
          }
        }
        else return false;
      }
      $i--;
    } while ( $i > 0 );
    return false;
  }

  /**
   * gets the name of the variable by parsing the multi-dimensional associative array $files_tokens
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $file_index passed by reference with the index of the variable in the multi-dimensional array $files_tokens
   * 
   * @return the name of the variable and in the $file_index parameter the last index of the variable in the multi-dimensional array $files_tokens
   */
  function get_variable_name( $file_name, &$file_index ) {
    if ( ($this->is_variable( $file_name, $file_index )) || ($this->is_property( $file_name, $file_index )) ) {
      $variable_name = $this->get_variable_function_property_method_name( $file_name, $file_index );
      if ( $this->is_variable( $file_name, $file_index ) ) {
        $file_index++;
      } else {
        $file_index = $file_index + 3;
      }
      for ( $i = $file_index, $count = count( $this->files->files_tokens[ $file_name ] ); $i < $count - 1; $i++ ) {
        $add_index = 0;
        // test to see if it is an array variable
        if ( '[' === $this->files->files_tokens[ $file_name ][ $i ] ) {
          $variable_name = $variable_name . $this->files->files_tokens[ $file_name ][ $i ];
          if ( is_array( $this->files->files_tokens[ $file_name ][ $i + 1 ] ) ) {
            $variable_name = $variable_name . $this->files->files_tokens[ $file_name ][ $i + 1 ][ 1 ] . $this->files->files_tokens[ $file_name ][ $i + 2 ];
            $add_index = 2;
          } else {
            $variable_name = $variable_name . $this->files->files_tokens[ $file_name ][ $i + 1 ];
            $add_index = 1;
          }
        } elseif ( is_array( $this->files->files_tokens[ $file_name ][ $file_index ] ) ) {
          if ( $this->is_property( $file_name, $i - 1 ) || $this->is_method( $file_name, $i - 1 ) ) {// test to see if it is an object
            $variable_name = $this->get_variable_function_property_method_name( $file_name, $i );
            $add_index = 1;
            if ( $this->is_method( $file_name, $i - 1 ) ) {
              //it is not a variable. It is a user defined object function
              $variable_name = 'function';
              break;
            }
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
    } elseif ( ($this->is_function( $file_name, $file_index )) || ($this->is_method( $file_name, $file_index )) ) {
      return 'function';
    }
    return null;
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
   * creates the multi-dimensional associative array with the PHP vulnerable variables
   */
  function set_vulnerable_variables() {
    for ( $i = 0, $count = count( $this->parser_variables ); $i < $count; $i++ ) {

      $variable = $this->parser_variables[ $i ];
      if ( (UNKNOWN != $variable[ 'vulnerability_classification' ] )
          && (FILTERED != $variable[ 'vulnerability_classification' ] ) ) {
        //add $parser_variables index
        $parser_variables_with_index = array_merge( array( 'index' => $i ), $this->parser_variables[ $i ] );
        $this->vulnerable_variables[ ] = $parser_variables_with_index;
      }
    }
  }

  /**
   * creates the multi-dimensional associative array with the PHP output variables
   */
  function set_output_variables() {
    for ( $i = 0, $count = count( $this->parser_variables ); $i < $count; $i++ ) {

      $variable = $this->parser_variables[ $i ];
      if ( (OUTPUT_VARIABLE === $variable[ 'output_variable' ] ) ) {
        //add $parser_variables index
        $parser_variables_with_index = array_merge( array( 'index' => $i ), $this->parser_variables[ $i ] );
        $this->output_variables[ ] = $parser_variables_with_index;
      }
    }
  }

  /**
   * gets the multi-dimensional associative array with the PHP vulnerable variable attributes
   * 
   * @return the multi-dimensional associative array vulnerableVariables
   */
  function get_vulnerable_variables() {
    return $this->vulnerable_variables;
  }

  /**
   * gets the multi-dimensional associative array with the PHP output variable attributes
   * 
   * @return the multi-dimensional associative array outputVariables
   */
  function get_output_variables() {
    return $this->output_variables;
  }

}

