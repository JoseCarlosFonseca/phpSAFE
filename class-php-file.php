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

    // new
    /**
     * Indexed array with de file names (to scan and includes)
     * @var array
     */
    public $files_tokens_names;
    // new

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
    // Change PN
    // stores if a token is an array or a string. 2-dimensions, file\_name (integer) and index (integer) 
    public $files_tokens_is_array;
    // To.
    // Change PN, 17-10-2014
    // stores the matching end token of the open token passed as an argument. 2-dimensions, file\_name (integer) and index (integer) 
    // open; (, [, {
    public $find_match_array;
    public $find_match_array_;
    // To.


    public $time_start;

    /**
     * Constructor that call all the functions that perform the static analysis looking for vulnerabilities
     * 
     * TODO check if PHP variables inside HTML code are double quoted
     * TODO dynamically created content
     * 
     * @param string $file_name with the PHP file name that is going to be parsed
     */
    function __construct($file_name) {
        $this->parser_file_name = realpath($file_name);
        //$this->time_start = microtime(true);
        //add the start PHP file and all the PHP files to the multi-dimensional array $files_tokens
        $this->include_php_files($this->parser_file_name);
    }

    function find_match($file_name, $block_start_index, $open_token) {
//calculate the matching close token
        switch ($open_token) {
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
        $ISA = $this->files_tokens_is_array[$file_name];
        for ($i = $block_start_index, $count = count($this->files_tokens[$file_name]); $i < $count; $i++) {
            $t = $this->files_tokens[$file_name][$i];
            if (( $open_token === $t ) || (($ISA[$i]) && ('{' === $open_token) && (T_CURLY_OPEN === $t[0]) )) {
                //if (( $open_token === $this->files->files_tokens[$file_name][$i] ) || ((is_array($this->files->files_tokens[$file_name][$i])) && ('{' === $open_token) && (T_CURLY_OPEN === $this->files->files_tokens[$file_name][$i][0]) )) {
                $count_open++;
                //} elseif ($close_token === $this->files->files_tokens[$file_name][$i]) {
            } elseif ($close_token === $t) {
                $count_close++;
//end searching when the number of pairs of matching tokens is 0
//this condition is tested only when a close token is found
                if (0 === $count_open - $count_close) {
                    break;
                }
            }
        }

//$i contains the index of the matching close token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
        return $i;
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
    function include_php_files($file_name) {
        $file_name = realpath(dirname($file_name)) . DIRECTORY_SEPARATOR . basename($file_name);

        if ($count = $this->php_file_tokens($file_name)) {
            // Change: last
            $index_file = $file_name; // count($this->files_tokens)-1;
            $index_file = count($this->files_tokens) - 1;
            //To.
            //echo "<p>$index_file</p>";
            //TODO use include_paths()
            $file_path = dirname($file_name) . DIRECTORY_SEPARATOR;


            //Change PN: files_tokens_is_array
            //$this->files_tokens_is_array [$i $time_start = microtime(true);
            for ($i = 0, $count; $i < $count; $i++) {
                $this->files_tokens_is_array[$index_file][$i] = is_array($this->files_tokens[$index_file][$i]);
            }
            // To. 
//            $k=0;
//             $ISA = $this->files_tokens[$index_file]['ISA'];
//             $token = $this->files_tokens[$index_file];
//             $this->time_start = microtime(true);
//             for ($i = 0, $count; $i < $count; $i++) {
//                if (is_array($token[$i])) $k++;
//            }
//            $time = microtime(true) - $this->time_start;
//            $s = sprintf('%01.6f', $time);
//            echo "<p>Time <b>is_array</b>: $s / $count</p>";
//            
//            
//             $this->time_start = microtime(true);
//             for ($i = 0, $count; $i < $count; $i++) {
//                if ($ISA[$i]) $k++;
//            }
//            $time = microtime(true) - $this->time_start;
//            $s = sprintf('%01.6f', $time);
//            echo "<p>Time <b>ISA</b>: $s / $count</p>";




            $ISA = $this->files_tokens_is_array[$index_file];
            $token = $this->files_tokens[$index_file];
            //find T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE within the $files_tokens[$file_name]
            $c2 = $count - 1;
            for ($i = 0; $i < $count; $i++) {
                $t0 = $token[$i][0];

                // find_match 
                if (!$ISA[$i]) {
                    if (($t0 === '(') || ($t0 === '[') || ($t0 === '{')) {
                        $this->find_match_array["$index_file#$i#$t0"] = $this->find_match($index_file, $i, $t0);
                        // $x = $this->find_match_array[$index_file][$i];
                        // echo "<p>$i $x $t0</p>";
                    }
                } else {
                    // T_FUNCTION  T_STRING ( ..... )
                    //  não faz sentido !!
//                     if (T_IF  === $t0){
//                          $this->find_match_array[$index_file][$i] = $this->find_match($index_file, $i+1, $t0);
//                        $x = $this->find_match_array[$index_file][$i];
//                        echo "<p>$i $x $t0</p>";
//                     }
                    // T_FUNCTION fn (){
//                    $ia = $i;
//                    while (($i < $block_end_index) && ( $tokens[$i] != ')')) {
//                        $i++;
//                    }
//                    if (T_FUNCTION === $t0) {
//                        
//                        $this->find_match_array[$index_file][$i] = $this->find_match($index_file, $i+4, '{');
//                        $id = $this->find_match_array[$index_file][$i];
//                        echo "<p>$t0 T_FUNCTION $i - $id </p>";
//                    }
                    // To.
                } // find_match

                if (( $ISA[$i] ) //if (( is_array($token[$i]) ) 
                        && ( ( T_INCLUDE === $t0 ) || ( T_INCLUDE_ONCE === $t0 ) || ( T_REQUIRE === $t0 ) || ( T_REQUIRE_ONCE === $t0 ) )) {
                    //if (( is_array($token[$i]) )   && ( ( T_INCLUDE === $token[$i][0] ) || ( T_INCLUDE_ONCE === $token[$i][0] ) || ( T_REQUIRE === $token[$i][0] ) || ( T_REQUIRE_ONCE === $token[$i][0] ) )) {
                    $file_name_include = null;

                    // it may have a '( ... )'
                    if (( '(' === $token[$i + 1] ) && ( T_CONSTANT_ENCAPSED_STRING === $token[$i + 2][0] ) && ( ')' === $token[$i + 3] )) {
                        //TODO deal with concatenation
                        $file_name_include = $token[$i + 2][1];
                        $i+=3;

                        // it may have a ';' at the end 
                        //} elseif ((is_array($token[$i + 1]) )
                    } elseif (( $ISA[$i + 1] ) && ( T_CONSTANT_ENCAPSED_STRING === $token[$i + 1][0] ) && ( ';' === $token[$i + 2] )) {
                        //TODO deal with concatenation
                        $file_name_include = $token[$i + 1][1];
                        $i+=2;
                    } else {
                        //TODO deal with dynamic includes
                        continue;
                    }
                    if (('"' === substr($file_name_include, 0, 1) ) || ("'" === substr($file_name_include, 0, 1) )) {
                        $file_name_include = $file_path . substr($file_name_include, 1, -1);
                    } else {
                        $file_name_include = $file_path . $file_name_include;
                    }

                    //only analyze the included file if it has not been anayzed yet
                    //if ( !in_array( $file_name_include, $this->files_tokens ) ) {
                    if (!in_array($file_name_include, $this->files_tokens_names)) {
                        //recursive call to itself
                        //  echo " $file_name_include ";
                        $this->include_php_files($file_name_include);
                    }
                }
                // }
            }
        }
//        echo ".........";
//        die();
    }

    /**
     * Reads the contents of the file, gets the PHP tokens and cleans them removing whitespace and comments.
     * The outcome is stored in the multi-dimensional array $files_tokens with the array of PHP tokens.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     */
    function php_file_tokens($file_name) {
        $file_name = realpath(dirname($file_name)) . DIRECTORY_SEPARATOR . basename($file_name);

        if ((file_exists($file_name) ) && (is_file($file_name))) {
            $file_contents = file_get_contents($file_name);

            // Change to indexed array
            $this->files_tokens_names[] = $file_name;
            // Same index
            //echo "<p>x $file_name</p>";
            if (isset($this->files_tokens)) {
                $file_name = count($this->files_tokens);
            } else {
                $file_name = 0;
            }
            $this->files_tokens[$file_name] = token_get_all($file_contents);
            // To.
            // echo "<p>x $file_name</p>";
            //Remove whitespaces and comments
            foreach ($this->files_tokens[$file_name] as $key => $token) {
                if (( is_array($token) ) && ( ( T_WHITESPACE === $token[0] ) || ( T_COMMENT === $token[0] ) )) {
                    //unset the token but keep the indexes untouched
                    unset($this->files_tokens[$file_name][$key]);
                }
            }

            //normalize the indexes. returns all the values from the array and indexes the array numerically.
            $this->files_tokens[$file_name] = array_values($this->files_tokens[$file_name]);

            return(count($this->files_tokens[$file_name]));
        } else {
            return 0;
        }
    }

}

// The ending PHP tag is omitted. This is actually safer than including it.