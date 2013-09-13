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
   * note: You define a function with parameters, you call a function with arguments.
   * 
   * @param string $file_name with the PHP file name of the calling function
   * @param string $function_name with the name of the function where the code is being executed, the calling function.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $called_function_start_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
   * @param string $called_function_end_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
   * @param string $called_function_name with the name of the function, the called function
   * @param int $called_function_index with the index name of the function, the called function
   */
  function parse_user_defined_function_method_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    //found the code of the PHP user defined function
    $called_function_file_name = $this->files_functions[ $called_function_index ][ 'file_name' ];
    $called_function_start_index = $this->files_functions[ $called_function_index ][ 'file_tokens_start_index' ];
    $called_function_end_index = $this->files_functions[ $called_function_index ][ 'file_tokens_end_index' ];

    /*
     *  add local variables (from the parameters of the function) based on the variables of the arguments
     */
    $first_called_function_variable_index = count( $this->parser_variables );
    $parameter_number = 0;
    $max_parameter_number = count( $this->files_functions[ $called_function_index ][ 'function_parameters' ] );
    for ( $i = $block_start_index + 1; $i < $block_end_index; $i++ ) {

      //get the argument of the call of the function
      $next_argument_index = $this->find_token( $file_name, $i, ',' );
      if ( $next_argument_index > $block_end_index ) {
        $next_argument_index = $block_end_index;
      }

      //the argument may be an expression, instead of a single variable
      $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $i, $next_argument_index, null, null );
      $called_function_parameter_name = $this->files_functions[ $called_function_index ][ 'function_parameters' ][ $parameter_number ][ 'parameter_name' ];

      //If the variable is an object and it is tainted, then the contents of that variable are also tainted
      //so get the object part of the property
      $object_variable_name = $this->get_object_name( $called_function_parameter_name );

      //create a local variable of the called function with the name of the parameter and the contents of the argument
      $this->parser_variables[ ] = array(
        'variable_name' => $called_function_parameter_name,
        'object_variable_name' => $object_variable_name,
        'scope' => 'local',
        'variable_function' => 'variable',
        'exist_destroyed' => EXIST,
        'code_type' => PHP_CODE,
        'input_variable' => REGULAR_VARIABLE,
        'output_variable' => REGULAR_VARIABLE,
        'function_name' => $called_function_name,
        'file_name' => $called_function_file_name,
        'file_line_number' => $this->files_functions[ $called_function_index ][ 'function_parameters' ][ $parameter_number ][ 'file_line_number' ],
        'tainted' => $expression[ 'tainted' ],
        'vulnerability_classification' => $expression[ 'vulnerability_classification' ],
        'file_tokens_start_index' => $this->files_functions[ $called_function_index ][ 'file_tokens_start_index' ],
        'file_tokens_end_index' => $this->files_functions[ $called_function_index ][ 'file_tokens_start_index' ],
        'variable_dependencies_index' => $expression[ 'variable_dependencies_index' ],
        'variable_dependencies_index' => null,
      );

      $i = $next_argument_index;
      $parameter_number++;

      //if all the parameters have been parsed or
      //if the function definition has less parameters than there are arguments continue with the existing arguments
      if ( ($next_argument_index === $block_end_index) || ( $parameter_number >= $max_parameter_number ) ) {
        break;
      }
    }

    /*
     * the variables of the parameters of the called function are already created so
     * parse the contents of the called function
     * if the function returns a value, a variable for the return value is created with the name of the called function
     * 
     */
    //skip the name of the called function
    $called_function_start_index = $this->find_match( $called_function_file_name, $called_function_start_index, '(' );
    $this->main_parser( $called_function_file_name, $called_function_name, $called_function_start_index, $called_function_end_index );

    /*
     * destroy the local variables
     * 
     */
    //find the file line number of the function call
    $calling_function_file_line_number = $this->files->files_tokens[ $file_name ][ $block_start_index - 1 ][ 2 ];

    //find the last file line number of the called function
    $called_function_file_line_number = $this->files_functions[ $called_function_index ][ 'file_end_line_number' ];

    //create a calling function variable from the variable of the return of the called function
    //create calling function variables from the global variables used in the called function
    //destroy all the variables used within the function
    //search for the variables used in the called function
    $count = count( $this->parser_variables );
    for ( $i = $count - 1; $i >= $first_called_function_variable_index; $i-- ) {

      //note: PHP functions are not case sensitive
      if ( (0 === strcasecmp( $this->parser_variables[ $i ][ 'function_name' ], $called_function_name ) )
          && ( $called_function_file_name === $this->parser_variables[ $i ][ 'file_name' ])
          && (EXIST === $this->parser_variables[ $i ][ 'exist_destroyed' ] ) ) {

        //a variable used in the called function was found
        //search if a variable of the called function with the same name was already destroyed
        $variable_index = $this->get_variable_index( $called_function_file_name, $this->parser_variables[ $i ][ 'variable_name' ], $called_function_name );

        //it the variable was not yet destroyed, then destroy it by creating a new variable destroyed
        if ( EXIST === $this->parser_variables[ $variable_index ][ 'exist_destroyed' ] ) {

          //test if the variable is the return of the called function
          if ( $called_function_name === $this->parser_variables[ $i ][ 'variable_name' ] ) {
            //if the variable is the return of the function, then it is updated
            $this->parser_variables[ $i ][ 'function_name' ] = $function_name;
            $this->parser_variables[ $i ][ 'file_name' ] = $file_name;
            $this->parser_variables[ $i ][ 'file_tokens_start_index' ] = $calling_function_file_line_number;
            $this->parser_variables[ $i ][ 'file_line_number' ] = $block_start_index;
            $this->parser_variables[ $i ][ 'file_tokens_end_index' ] = $block_end_index;
            continue;
          } elseif ( 'global' === $this->parser_variables[ $i ][ 'scope' ] ) {
            //if it is a global variable then create a new variable in the calling function scope

            $global_variable_index = $this->get_variable_index( $file_name, $this->parser_variables[ $i ][ 'variable_name' ], $function_name );
            if ( $global_variable_index ) {
              $scope = $this->parser_variables[ $global_variable_index ][ 'scope' ];
            } else {
              $scope = 'local';
            }

            $this->parser_variables[ ] = array(
              'variable_name' => $this->parser_variables[ $i ][ 'variable_name' ],
              'object_variable_name' => $this->parser_variables[ $i ][ 'object_variable_name' ],
              'scope' => $scope,
              'variable_function' => $this->parser_variables[ $i ][ 'variable_function' ],
              'exist_destroyed' => EXIST,
              'code_type' => $this->parser_variables[ $i ][ 'code_type' ],
              'input_variable' => $this->parser_variables[ $i ][ 'input_variable' ],
              'output_variable' => $this->parser_variables[ $i ][ 'output_variable' ],
              'function_name' => $function_name,
              'file_name' => $file_name,
              'file_line_number' => $calling_function_file_line_number,
              'tainted' => $this->parser_variables[ $i ][ 'tainted' ],
              'vulnerability_classification' => $this->parser_variables[ $i ][ 'vulnerability_classification' ],
              'file_tokens_start_index' => $block_start_index,
              'file_tokens_end_index' => $block_end_index,
              'variable_dependencies_index' => array( $i ),
              'variable_filters_or_revert_filters' => null,
            );
          }

          //destroy the variable of the called function
          $this->parser_variables[ ] = array(
            'variable_name' => $this->parser_variables[ $i ][ 'variable_name' ],
            'object_variable_name' => $this->parser_variables[ $i ][ 'object_variable_name' ],
            'scope' => $this->parser_variables[ $i ][ 'scope' ],
            'variable_function' => $this->parser_variables[ $i ][ 'variable_function' ],
            'exist_destroyed' => DESTROYED,
            'code_type' => $this->parser_variables[ $i ][ 'code_type' ],
            'input_variable' => $this->parser_variables[ $i ][ 'input_variable' ],
            'output_variable' => $this->parser_variables[ $i ][ 'output_variable' ],
            'function_name' => $called_function_name,
            'file_name' => $this->parser_variables[ $i ][ 'file_name' ],
            'file_line_number' => $called_function_file_line_number,
            'tainted' => UNTAINTED,
            'vulnerability_classification' => UNKNOWN,
            'file_tokens_start_index' => $called_function_end_index,
            'file_tokens_end_index' => $called_function_end_index,
            'variable_dependencies_index' => array( $i ),
            'variable_filters_or_revert_filters' => null,
          );
        }
      }
    }
  }

  /**
   * If the called function is one of the output functions it is checked for tainted variables that could cause a vulnerability
   * If the caled function is not one of the output functions nothing is done
   * The called function is not really parsed because there is no source code
   * 
   * TODO functions that have arguments that are not variables, like functions or expressions
   * 
   * note: You define a function with parameters, you call a function with arguments.
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed, the calling function.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $called_function_name with the name of the function, the called function
   */
  function parse_other_function_method_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    for ( $i = 0, $count = count( $this->used_functions ); $i < $count; $i++ ) {
      if ( 0 === strcasecmp( $this->used_functions[ $i ][ 'name' ], $called_function_name ) ) {
        ('none' === $this->used_functions[ $i ][ 'vulnerability' ] ? $vulnerability_classification = null : $vulnerability_classification = $this->used_functions[ $i ][ 'vulnerability' ]);
        ('not output' === $this->used_functions[ $i ][ 'output' ] ? $output_variable_attribute = REGULAR_VARIABLE : $output_variable_attribute = OUTPUT_VARIABLE);
        ('not filter' === $this->used_functions[ $i ][ 'filter' ] ? $is_filtering_function = false : $is_filtering_function = true);
        ('not revert filter' === $this->used_functions[ $i ][ 'revert_filter' ] ? $is_revert_filtering_function = false : $is_revert_filtering_function = true);
        ('not input' === $this->used_functions[ $i ][ 'input' ] ? $input_function_variable = REGULAR_VARIABLE : $input_function_variable = INPUT_VARIABLE);
        break;
      }
    }

    //it is an input function
    if ( INPUT_VARIABLE === $input_function_variable ) {
      //add a new variable, which is the return value of the input function
      $variable_name = $called_function_name;
      //If the variable is an object and it is tainted, then the contents of that variable are also tainted
      //so get the object part of the property
      $object_variable_name = $this->get_object_name( $variable_name );

      $this->parser_variables[ ] = array(
        'variable_name' => $variable_name,
        'object_variable_name' => $object_variable_name,
        'scope' => 'local',
        'variable_function' => 'function', //in fact, this is not a variable. It is the return value of a function (an input function)
        'exist_destroyed' => EXIST,
        'code_type' => PHP_CODE,
        'input_variable' => $input_function_variable,
        'output_variable' => REGULAR_VARIABLE,
        'function_name' => $function_name,
        'file_name' => $file_name,
        'file_line_number' => $this->files->files_tokens[ $file_name ][ $block_start_index - 1 ][ 2 ],
        'tainted' => TAINTED,
        'vulnerability_classification' => UNKNOWN,
        'file_tokens_start_index' => $block_start_index,
        'file_tokens_end_index' => $block_start_index,
        'variable_dependencies_index' => null,
        'variable_filters_or_revert_filters' => null,
      );
    }

    $current_variable_index = count( $this->parser_variables );

    $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $output_variable_attribute, $vulnerability_classification );

    if ( $is_filtering_function ) {
      for ( $i = $current_variable_index, $count = count( $this->parser_variables ); $i < $count; $i++ ) {
        if ( (0 === strcasecmp( $this->parser_variables[ $i ][ 'file_name' ], $file_name ))
            && (0 === strcasecmp( $this->parser_variables[ $i ][ 'function_name' ], $function_name ) ) ) {
          if ( TAINTED === $this->parser_variables[ $i ][ 'tainted' ] ) {
            //untaint the original variable, because it is filtered
            $this->parser_variables[ $i ][ 'tainted' ] = UNTAINTED;
            $this->parser_variables[ $i ][ 'vulnerability_classification' ] = FILTERED;
          }
          $this->parser_variables[ $i ][ 'variable_filters_or_revert_filters' ][ ] = $called_function_name;
        }
      }
    }

    if ( $is_revert_filtering_function ) {
      for ( $i = $current_variable_index, $count = count( $this->parser_variables ); $i < $count; $i++ ) {
        if ( (0 === strcasecmp( $this->parser_variables[ $i ][ 'file_name' ], $file_name ))
            && (0 === strcasecmp( $this->parser_variables[ $i ][ 'function_name' ], $function_name ) ) ) {
          //TODO revert filter actions
          $this->parser_variables[ $i ][ 'variable_filters_or_revert_filters' ][ ] = $called_function_name;
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

    $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $block_start_index + 1, $block_end_index, null, null );

    // returns null if there is no variable resulting from the return of this function
    $variable_index = $this->get_variable_index( $file_name, $function_name, $function_name );
    if ( !is_null( $variable_index ) ) {
      //if there is already a return value variable we just update it if the new variable is tainted
      //if the variable is tainted, then we have a vulnerability
      if ( $expression[ 'tainted' ] === TAINTED ) {
        $this->parser_variables[ $variable_index ][ 'tainted' ] = TAINTED;
        $this->parser_variables[ $variable_index ][ 'vulnerability_classification' ] = $expression[ 'vulnerability_classification' ];
        $this->parser_variables[ $variable_index ][ 'variable_dependencies_index' ] = $expression[ 'variable_dependencies_index' ];
      }//else do nothing
    } else {
      //add a new variable, which is the return value of the input function
      //If the variable is an object and it is tainted, then the contents of that variable are also tainted
      //so get the object part of the property
      $object_variable_name = $this->get_object_name( $function_name );
      $this->parser_variables[ ] = array(
        'variable_name' => $function_name,
        'object_variable_name' => $object_variable_name,
        'scope' => 'local',
        'variable_function' => 'function',
        'exist_destroyed' => EXIST,
        'code_type' => PHP_CODE,
        'input_variable' => REGULAR_VARIABLE,
        'output_variable' => REGULAR_VARIABLE,
        'function_name' => $function_name,
        'file_name' => $file_name,
        'file_line_number' => $this->files->files_tokens[ $file_name ][ $block_start_index - 1 ][ 2 ],
        'tainted' => $expression[ 'tainted' ],
        'vulnerability_classification' => $expression[ 'vulnerability_classification' ],
        'file_tokens_start_index' => $block_start_index,
        'file_tokens_end_index' => $block_end_index,
        'variable_dependencies_index' => $expression[ 'variable_dependencies_index' ],
        'variable_filters_or_revert_filters' => null,
      );
    }
  }

  /**
   * Parse an expression containing variables and functions, recursively.
   * Determines the attributes tainted, vulnerability_classification, variable_dependencies_index that will be returned
   * 
   * @param string $file_name with the PHP file name that is going to be parsed
   * @param string $function_name with the name of the function where the code is being executed.
   * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
   * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
   * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
   * @param string $output_variable_attribute with the attribute OUTPUT_VARIABLE or null, if the expression belongs to an output function or not
   * @param string $vulnerability_classification with the vulnerability classification attribute or null, if the expression belongs to an output function or not
   * 
   * @return multi-dimensional associative array with the attributes tainted, vulnerability_classification, variable_dependencies_index
   */
  function parse_expression_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $output_variable_attribute, $vulnerability_classification ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );


    $current_variable_index = count( $this->parser_variables );

    for ( $i = $block_start_index; $i < $block_end_index; $i++ ) {

      /*
       * it is a variable or a property
       * add the variable and propagate the taint and vulnerability classification, if it is the case
       * 
       */
      if ( ( $this->is_variable( $file_name, $i ) ) || ( $this->is_property( $file_name, $i ) ) ) {

        // add the variable to the multi-dimensional associative array $parser_variables
        $index = $this->parse_variable_property( $file_name, $function_name, $i );
        $i = $index;

        /*
         * it is a function or a method
         * 
         */
      } elseif ( ($this->is_function( $file_name, $i )) || ($this->is_method( $file_name, $i )) ) {
        // parse the function, which will add the existing variables to the multi-dimensional associative array $parser_variables
        $index = $this->parse_function_method( $file_name, $function_name, $i );
        $i = $index;
      } else {
        //if it is not a variable, property, function, method continue
      }
    }

    /*
     * update variable attributes
     * 
     */
    $tainted = UNTAINTED;
    $variable_dependencies_index = null;
    for ( $j = $current_variable_index, $count = count( $this->parser_variables ); $j < $count; $j++ ) {
      if ( (0 === strcasecmp( $this->parser_variables[ $j ][ 'file_name' ], $file_name ))
          && (0 === strcasecmp( $this->parser_variables[ $j ][ 'function_name' ], $function_name ) ) ) {
        //it is a user defined function with a return value
        //if the code is from an output function then the variable is an output variable
        if ( OUTPUT_VARIABLE === $output_variable_attribute ) {
          $this->parser_variables[ $j ][ 'output_variable' ] = OUTPUT_VARIABLE;
        }
        //propagate the tainted attribute
        if ( TAINTED === $this->parser_variables[ $j ][ 'tainted' ] ) {
          $tainted = TAINTED;
          // if it is also an output variable we have a vulnerability
          if ( (OUTPUT_VARIABLE === $output_variable_attribute) && (!is_null( $vulnerability_classification )) ) {
            $this->parser_variables[ $j ][ 'vulnerability_classification' ] = $vulnerability_classification;
          }
        }

        $variable_dependencies_index[ ] = $j;
      }
    }

    if ( ( is_null( $vulnerability_classification ) ) || (UNTAINTED === $tainted) ) {
      $vulnerability_classification = UNKNOWN;
    }

//    echo 'OUTPUT expression $tainted '.$tainted.' $vulnerability_classification '.$vulnerability_classification.' $variable_dependencies_index '.$variable_dependencies_index.'<br />';
    return( array(
      'tainted' => $tainted,
      'vulnerability_classification' => $vulnerability_classification,
      'variable_dependencies_index' => $variable_dependencies_index,
        ) );
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
   * @param string $variable_before_equal_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, null, null );

    //update the atributes of the variable in the left side of the '='
    $this->parser_variables[ $variable_before_equal_index ][ 'tainted' ] = $expression[ 'tainted' ];
    $this->parser_variables[ $variable_before_equal_index ][ 'vulnerability_classification' ] = $expression[ 'vulnerability_classification' ];
    $this->parser_variables[ $variable_before_equal_index ][ 'variable_dependencies_index' ] = $expression[ 'variable_dependencies_index' ];
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
   * @param string $variable_before_as_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
   * 
   * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
   */
  function parse_foreach_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $index = $block_start_index;
    //$index (the $files_tokens index) is passed by reference. When it is a function it returns the vlue 'function'
    $variable_after_as_name = $this->get_variable_property_complete_array_name( $file_name, $index );

    //add the variable to the multi-dimensional associative array $parser_variables
    $this->parse_variable_property( $file_name, $function_name, $block_start_index );

    // $this->get_variable_index return null if there is no variable
    $variable_after_as_index = $this->get_variable_index( $file_name, $variable_after_as_name, $function_name );

    if ( !is_null( $variable_before_as_index ) ) {
      $this->parser_variables[ $variable_after_as_index ][ 'tainted' ] = $this->parser_variables[ $variable_before_as_index ][ 'tainted' ];
      $this->parser_variables[ $variable_after_as_index ][ 'vulnerability_classification' ] = $this->parser_variables[ $variable_before_as_index ][ 'vulnerability_classification' ];
      $this->parser_variables[ $variable_after_as_index ][ 'variable_dependencies_index' ][ ] = $variable_before_as_index;
    } else {
      $this->parser_variables[ $variable_after_as_index ][ 'tainted' ] = UNTAINTED;
      $this->parser_variables[ $variable_after_as_index ][ 'vulnerability_classification' ] = UNKNOWN;
      $this->parser_variables[ $variable_after_as_index ][ 'variable_dependencies_index' ][ ] = null;
    }
  }

  /**
   * Extract the variable information from the multi-dimensional array $files_tokens 
   * and store it in the multi-dimensional associative array $parser_variables
   * Make a distinction between regular and input variables
   * Taint input variables
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
  function parse_variable_property_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type ) {
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    if ( !is_null( $variable_name ) && ($variable_name != 'function') ) {
      //get the variable name even if it is preceded by a '&'
      if ( '&' === $this->files->files_tokens[ $file_name ][ $block_start_index ] ) {
        $block_start_index++;
      }

      $line_number = $this->files->files_tokens[ $file_name ][ $block_start_index ][ 2 ];

      //regular variables are by default safe
      $output_variable = REGULAR_VARIABLE;

      //regular variables are by default safe
      $input_variable = REGULAR_VARIABLE;
      $tainted = UNTAINTED;
      $short_variable_name = $this->get_variable_property_name( $file_name, $block_start_index );
      //search for input vulnerable variables
      foreach ( Vulnerable_Input::$INPUT_VARIABLES as $key => $value ) {
        //search for PHP reserved variables
        foreach ( $value as $input_array_var ) {
          //if it is a PHP reserved variables
          if ( $short_variable_name === $input_array_var ) {
            $input_variable = INPUT_VARIABLE;
            $tainted = TAINTED;
            //leave outter foreach
            break 2;
          }
        }
      }

      //find if the variable already exists. In this case the variable is updated
      //If the variable is an object and it is tainted, then the contents of that variable are also tainted
      $object_variable_name = $this->get_object_name( $variable_name );
      $variable_name_index = $this->get_object_property_index( $file_name, $function_name, $variable_name );

      // if it is a variable process it. Otherwise leave this function 
      if ( !is_null( $variable_name_index ) ) {
        //If the variable already exists in the scope and is tainted, then this should be reflected in the current usage of the variable
        if ( TAINTED === $this->parser_variables[ $variable_name_index ][ 'tainted' ] ) {
          $tainted = TAINTED;
        }
        $variable_scope = $this->parser_variables[ $variable_name_index ][ 'scope' ];
      }
      if ( (is_null( $variable_name_index ))
          || ((!is_null( $variable_name_index ))
          && (($this->parser_variables[ $variable_name_index ][ 'file_tokens_start_index' ] != $block_start_index)
          && ($this->parser_variables[ $variable_name_index ][ 'file_tokens_end_index' ] != $block_end_index))) ) {

        //add the variable name, variable used in PHP or outside PHP, input variable?, the function name, the file name and the line number and the taint value, variable classification, and the $parserFileTokens array index
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
          'variable_dependencies_index' => null,
          'variable_filters_or_revert_filters' => null,
        );
      }

      //If the variable already exists in the scope the new variable depends on it and it is not in the same PHP line
      if ( (!is_null( $variable_name_index )) && ($this->start_of_php_line( $file_name, $block_start_index ) > $this->start_of_php_line( $file_name, $this->parser_variables[ $variable_name_index ][ 'file_tokens_end_index' ] )) ) {
        $newVariableNameIndex = $this->get_variable_index( $file_name, $variable_name, $function_name );
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
        $variable_name_index = $this->get_variable_index( $file_name, $variable_name, $function_name );
        //obtain the line of code where the variable is located
        $start_of_php_line_index = $this->start_of_php_line( $file_name, $block_start_index );
        $end_of_php_line_index = $this->end_of_php_line( $file_name, $block_start_index );

        //if the start and the end of the line are PHP_OPEN_TAG and PH_CLOSE_TAG
        if ( ((T_OPEN_TAG === $this->files->files_tokens[ $file_name ][ $start_of_php_line_index ][ 0 ] )
            || (T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[ $file_name ][ $start_of_php_line_index ][ 0 ] ))
            && (T_CLOSE_TAG === $this->files->files_tokens[ $file_name ][ $end_of_php_line_index ][ 0 ] ) ) {
          $is_single_code = true;
          for ( $i = $start_of_php_line_index; $i < $end_of_php_line_index; $i++ ) {
            $token = $this->files->files_tokens[ $file_name ][ $i ][ 0 ];
            //it is considered as a single code if it has no loops nor conditional structures
            if ( (T_FOR === $token )
                || (T_FOREACH === $token )
                || (T_DO === $token )
                || (T_WHILE === $token )
                || (T_ENDWHILE === $token )
                || (T_ELSEIF === $token )
                || (T_ELSE === $token )
                || (T_IF === $token )
                || (T_SWITCH === $token )
                || ('=' === $this->files->files_tokens[ $file_name ][ $i ] ) ) {
              $is_single_code = false;
              break;
            }
          }

          //vulnerabilityClassification is XSS
          if ( true === $is_single_code ) {
            if ( TAINTED === $this->parser_variables[ $variable_name_index ][ 'tainted' ] ) {
              $this->parser_variables[ $variable_name_index ][ 'vulnerability_classification' ] = XSS;
            }
            $this->parser_variables[ $variable_name_index ][ 'output_variable' ] = OUTPUT_VARIABLE;
          }
        }
      }
    }
  }

  /**
   * Parse unset.
   * When the variable is unset, PHP destroys the variable.
   * For the vulnerability detection it is the same as being UNTAINTED
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
    $this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

    $this->parser_variables[ $variable_index ][ 'tainted' ] = UNTAINTED;
    $this->parser_variables[ $variable_index ][ 'exist_destroyed' ] = DESTROYED;
    $this->parser_variables[ $variable_index ][ 'vulnerability_classification' ] = UNKNOWN;
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
          $function_name = $this->files->files_tokens[ $file_name ][ $i ][ 1 ];
          foreach ( Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $function_name ) ) {
                $variable_protection_functions[ ] = $output;
                $found_variable_filter = true;
                //leave outter foreach
                break 2;
              }
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
    $previous_containing_function = $this->find_previous_containing_function_from_index( $file_name, $block_end_index );
    if ( !is_null( $previous_containing_function ) ) {
      $found_variable_filter = false;
      foreach ( array_merge( Vulnerable_Filter::$VARIABLE_FILTERS, Vulnerable_Filter::$REVERT_VARIABLE_FILTERS ) as $key => $value ) {
        foreach ( $value as $output ) {
          //note: PHP functions are not case sensitive
          if ( 0 === strcasecmp( $output, $previous_containing_function ) ) {
            $variable_protection_functions = $output;
            $found_variable_filter = true;
            break 2;
          }
        }
      }
    }
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
    $previous_containing_function = $this->find_previous_containing_function_from_index( $file_name, $block_end_index );
    if ( !is_null( $previous_containing_function ) ) {
      foreach ( Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value ) {
        foreach ( $value as $output ) {
          //note: PHP functions are not case sensitive
          if ( 0 === strcasecmp( $output, $previous_containing_function ) ) {
            return $output;
          }
        }
      }
    }
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
          $function_name = $this->files->files_tokens[ $file_name ][ $i ][ 1 ];
          foreach ( Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $function_name ) ) {
                $variable_protection_functions[ ] = $output;
                $found_variable_filter = true;
                break 2;
              }
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
          $function_name=$this->files->files_tokens[ $file_name ][ $i ][ 1 ];
          foreach ( Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value ) {
            foreach ( $value as $output ) {
              //note: PHP functions are not case sensitive
              if ( 0 === strcasecmp( $output, $function_name ) ) {
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
   * creates the multi-dimensional associative array with the PHP vulnerable variables
   */
  function set_vulnerable_variables() {
    for ( $i = 0, $count_parser_variables = count( $this->parser_variables ); $i < $count_parser_variables; $i++ ) {

      //remove duplicate vulnerable variables
      $exist = false;
      for ( $j = 0, $count_vulnerable_variables = count( $this->vulnerable_variables ); $j < $count_vulnerable_variables; $j++ ) {
        if ( ($this->parser_variables[ $i ][ 'variable_name' ] === $this->vulnerable_variables[ $j ][ 'variable_name' ])
            && ($this->parser_variables[ $i ][ 'file_name' ] === $this->vulnerable_variables[ $j ][ 'file_name' ])
            && ($this->parser_variables[ $i ][ 'file_line_number' ] === $this->vulnerable_variables[ $j ][ 'file_line_number' ]) ) {
          $exist = true;
          break;
        }
      }
      if ( $exist === true ) {
        continue;
      }

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

// The ending PHP tag is omitted. This is actually safer than including it.