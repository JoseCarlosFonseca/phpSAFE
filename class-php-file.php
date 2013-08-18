<?php

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
     * Calls all the functions that perform the static analysis looking for vulnerabilities
     * 
     * TODO check if PHP variables inside HTML code are double quoted
     * TODO dynamically created content
     * 
     * @param string $file_name with the PHP file name that is going to be parsed
     */
    function __construct($file_name) { //constructor that calls everything needed to parse the PHP file
        $this->parser_file_name = realpath($file_name);

        $this->include_php_files($this->parser_file_name); //adds the start PHP file and all the PHP files to the multi-dimensional array $files_tokens
    }

    /**
     * Calls the function parsePhpFile to get the PHP tokens from the PHP file
     * into the multi-dimensional array $files_tokens
     * Then looks for included and required PHP files and recursively includes them
     * 
     * TODO deal with dynamic includes. At least build a warning mechanism
     * 
     * @param string $file_name with the PHP file name that is going to be parsed
     */
    function include_php_files($file_name) {
        $file_name = realpath($file_name);
        $this->php_file_tokens($file_name);
        $file_path = dirname($file_name) . DIRECTORY_SEPARATOR; //TODO use include_paths()
        if ($this->files_tokens[$file_name]) {
            //find T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE within the $files_tokens[$file_name]
            for ($i = 0, $count = count($this->files_tokens[$file_name]); $i < $count; $i++) {
                if (is_array($this->files_tokens[$file_name][$i])) {
                    if (( $this->files_tokens[$file_name][$i][0] == T_INCLUDE) or
                            ( $this->files_tokens[$file_name][$i][0] == T_INCLUDE_ONCE) or
                            ( $this->files_tokens[$file_name][$i][0] == T_REQUIRE) or
                            ( $this->files_tokens[$file_name][$i][0] == T_REQUIRE_ONCE)) {
                        $file_name_include = null;
                        if (( $this->files_tokens[$file_name][$i + 1] == '(') and
                                ( $this->files_tokens[$file_name][$i + 2][0] == T_CONSTANT_ENCAPSED_STRING) and
                                ( $this->files_tokens[$file_name][$i + 3] == ')')) {
                            $file_name_include = $this->files_tokens[$file_name][$i + 2][1]; //TODO deal with dynamic includes
                            $i+=3;
                        } elseif ((is_array($this->files_tokens[$file_name][$i + 1]) ) and
                                ( $this->files_tokens[$file_name][$i + 1][0] == T_CONSTANT_ENCAPSED_STRING) and
                                ( $this->files_tokens[$file_name][$i + 2] == ';')) {
                            $file_name_include = $this->files_tokens[$file_name][$i + 1][1]; //TODO deal with dynamic includes
                            $i+=2;
                        }
                        if ((substr($file_name_include, 0, 1) == '"') or
                                (substr($file_name_include, 0, 1) == "'")) {
                            $file_name_include = substr($file_name_include, 1, -1);
                        }
                        //only analyze the included file if it has not been anayzed yet
                        $included_files_count = 0;
                        foreach ($this->files_tokens as $j => $k) {
                            if ($j == $file_path . $file_name_include) {
                                $included_files_count++;
                            }
                        }
                        if ($included_files_count == 0) {
                            $this->include_php_files($file_path . $file_name_include); //recursive call to itself
                        }
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
    function php_file_tokens($file_name) {
        $file_name = realpath($file_name);
        if (file_exists($file_name)) {
            $file_contents = file_get_contents($file_name);
            $this->files_tokens[$file_name] = token_get_all($file_contents);
            //Remove whitespaces and comments
            for ($i = 0, $count = count($this->files_tokens[$file_name]); $i < $count; $i++) {
                if (is_array($this->files_tokens[$file_name][$i])) {
                    if (( $this->files_tokens[$file_name][$i][0] == T_WHITESPACE) or
                            ( $this->files_tokens[$file_name][$i][0] == T_COMMENT)) {
                        unset($this->files_tokens[$file_name][$i]); //unset the token but keep the indexes untouched
                    }
                }
            }
            $this->files_tokens[$file_name] = array_values($this->files_tokens[$file_name]); //normalize the indexes
        }
        else
            $this->files_tokens[$file_name] = null;
    }

}


