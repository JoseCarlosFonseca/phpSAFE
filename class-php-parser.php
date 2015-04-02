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
 * 
 * 
 */
require_once 'class-php-file.php';

class PHP_Parser {

    protected $count_find_match = 0;

    /**
     * The parser debug2 html formated data
     * Append data progressively
     * @var boolean
     */
    protected $parser_debug2_flag = false;

    /**
     * The parser debug2 html formated data
     * Adds data at the end of the analysis.
     * @var boolean
     */
    // write 
    protected $parser_debug2_flag_file = false;

    /**
     * The parser debug counter
     * @var int
     */
    protected $parser_debug2_counter = 0;

    /**
     * Parser debug2 html text
     * @var string
     */
    protected $parser_debug2_text = "";

    /**
     * The parser debug counter
     * @var fstream
     */
    protected $parser_debug2_file_stream;
    protected $parser_debug2_file_path = './output/';

    /**
     * 
     * @var array
     */
    protected $function_count;

    /**
     * The object of the class Php_File
     * @var Php_File class object
     */
    public $files;

    /**
     * Multi-dimensional associative array with the PHP user defined functions
     * @var array
     */
    protected $files_functions;
    protected $files_functions_lookup;
    /*
     * array 1D [file_name + class(es)_name + function_name] -  integers (index of) 
     */
    protected $used_functions_lookup; // PN 2014-10-19

    /*
     * array 2-D [file_name][$i] - integers (index of)
     * 
     * To use tabling
     */
    protected $start_of_php_line_lookup; // PN 2014-10-20

    /*
     * array 2-D [file_name][$i] - integers (index of)
     * 
     * To use tabling
     */
    protected $end_of_php_line_lookup; // PN 2014-10-20

    /*
     * array 2-D [file_name][$i] - integers (index of)
     * 
     * To use tabling
     */
    //protected $find_match_T_FUNCTION;

    /*
     * array 3D
     * find_token_lookup[$file_name][$block_start_index][$token]
     * 
     * 
     */
    protected $find_token_lookup;

    /*
     * 
     * array 2D
     * find_previous_containing_function_from_index_lookup[$file_name][$block_index]
     * 
     */
    protected $find_previous_containing_function_from_index_lookup;

    /*
     * 
     * array 2D
     * $get_function_method_name_lookup[$file_name][$file_index]
     * 
     */
    protected $get_function_method_name_lookup;

    /*
     * array 2D
     * 
     * get_variable_property_name_lookup[$file_name][$file_index]
     * 
     */
    protected $get_variable_property_name_lookup;

    /*
     * array 2D
     * 
     * get_variable_property_complete_array_name_lookup[$file_name][$file_index]
     * 
     */
    protected $get_variable_property_complete_array_name_lookup;


    /*
     * array 2-D [file_name][$i] - integers (index of)
     * 
     * To use tabling
     */
    protected $find_function_name_of_code_lookup;

    /**
     * Multi-dimensional associative array with the PHP user defined functions
     * @var 
     */
    /*
     * array 2-D [file_name][$i] - integers (index of) ???
     * 
     * To use tabling
     */
    protected $check_variable_function_property_method_lookup;
    protected $start_time;   // PN
    protected $time_execution_of = 0;   // PN  to gauge for function in currently in tests
    protected $count_execution = 0;

    /**
     * 
     * @var 
     */
    protected $main_parser_level = -1;   // PN

    /**
     * Array
     * @var 
     */
    protected $main_parser_levels;   // PN

    /**
     * Multi-dimensional associative array with all the functions used in the code
     * @var array
     */
    protected $used_functions;

    /**
     * Multi-dimensional array with the PHP user defined functions stack
     * This is used to test for recursive functions, so they are not parsed more than once at a time
     * @var array
     */
    protected $functions_stack;

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
    //protected $parser_variables_user_functions;
    protected $parser_variables_user_functions_lookup;

    /**
     * 2-dimensional associative, index array with the PHP variable attributes
     * [$file_name$variable_name$function_name][index]
     * @var array
     */
    protected $parser_variables_lookup;

    /**
     * .... 
     * @var file stream
     */
    protected $text_file_stream;   //PN   see $file_debug = 1;   //PN
    protected $file_debug = 0;   //PN
    protected $echo_debug = 0;   //PN

    /**
     * echo parser variables 
     * @var boolean
     */
    protected $html_table_visible = false;
    protected $echo_output_variables = true;
    protected $echo_parser_variables = true;
    protected $echo_parser_variables_with_dependencies = false;
    protected $echo_parser_variables_lookup = false;
    protected $echo_file_functions = true;
    protected $echo_used_functions = true;
    protected $echo_files_include_require = true;
    protected $echo_vulnerable_variables_with_dependencies = true;
    protected $echo_vulnerable_variables_tree = false; // not implemented
    protected $file_write_output_variables = false;
    protected $file_write_parser_variables = false;
    protected $csv_write_parser_variables = false;
    protected $file_write_parser_variables_lookup = false;
    protected $file_write_parser_variables_with_dependencies = false;
    protected $file_write_file_functions = false;
    protected $file_write_used_functions = false;
    protected $file_write_files_include_require = false;
    protected $file_write_tokens_array_of_arrays = false;
    protected $file_write_vulnerable_variables_with_dependencies = false;
    protected $file_write_vulnerable_variables_tree = false;

    /**
     * .... with the PHP variable attributes
     * @var string
     */
    protected $threshold_time_php_tag = 1;    // PN

    function echo_h1($text, $color) {
        echo "<h1 style='color:$color;'>$text</h1>";
    }

    // parse function including parametres dependencies 

    /**
     * adds item to then $parser_variables_lookup two-dimensional associative array
     *       
     * @param type $key string union of the $file_name, $variable_name and $function_name
     * @param type $index integer index of the $parser_variables that is being inserted 
     */
    function add_parser_variables_lookup($file_name, $variable_name, $function_name, $index) {
        // if the does not exists insert it with the index 0 else insert with the last index + 1
        // hash table with collisions stored in the 2nd dimension
        $function_name = strtoupper($function_name);
        $key = "$file_name#$variable_name#$function_name";
        $this->parser_variables_lookup["$key"][] = $index;
    }

    /**
     * 
     * @param type $file_name
     * @param type $variable_name
     * @param type $function_name
     * @param type $index
     * @return null
     */
    function delete_variable_index_with_lookup($file_name, $variable_name, $function_name, $index) {
        // echo "<p style='color:brown'>function delete_variable_index_with_lookup($file_name, $variable_name, $function_name, $index)<p>";
        $function_name = strtoupper($function_name);
        $key = "$file_name#$variable_name#$function_name";

        if (isset($this->parser_variables_lookup["$key"])) {
            $c = count($this->parser_variables_lookup["$key"]);
            for ($i = 0; $i < $c; $i++) {
                if (isset($this->parser_variables_lookup["$key"][$i])) {
                    if ($index === $this->parser_variables_lookup["$key"][$i]) {
                        // if only one, delete all item $key, else delete the item [$key][$i]
                        if ($c === 1) {
                            unset($this->parser_variables_lookup["$key"]);
                            //$this->echo_h1("DELETE $key $index c($c) = 1", "red");
                            // $c2 = 0;
                        } else {
                            //$this->echo_h1("DELETE $key $index c($c) > 1", "blue");
                            unset($this->parser_variables_lookup["$key"][$i]);
                            // normalize, delete unsset items
                            //$this->parser_variables_lookup["$key"] = array_values($this->parser_variables_lookup["$key"]);
                            //$c2 = count($this->parser_variables_lookup["$key"]);
                        }
                        // echo "<hr /><h2 style='color:brown'>$key - count: $c/$c2, index: $index </h2>";
                        return;
                    }
                }
            }
        }
    }

    function show_parser_variables() {
        $this->show_variables($this->parser_variables, 'Parser Variables', $this->echo_parser_variables, "ParserVariables.html", $this->file_write_parser_variables);
        if ($this->csv_write_parser_variables)
            $this->show_variables_csv($this->parser_variables, 'CSV - Parser Variables', "ParserVariables.csv");
    }

    function show_file_functions() {
        $this->show_variables($this->files_functions, 'File Functions', $this->echo_file_functions, "FileFunctions.html", $this->file_write_file_functions);
    }

    function show_used_functions() {
        $this->show_variables($this->used_functions, 'Used Functions', $this->echo_used_functions, "UsedFunctions.html", $this->file_write_used_functions);
    }

    function show_files_include_require() {
        $this->show_variables($this->files_include_require, 'Files Include Require', $this->echo_file_functions, "FilesIncludeRequire.html", $this->file_write_files_include_require);
    }

// function
// PN

    function execution_time($time_start, $text) {
        $time_end = microtime(true);
        $time = $time_end - $time_start;
        $s = sprintf('%01.2f', $time);
        echo "<p>Time <b>$text</b>: $s</p>";
    }

    // PN    
    function array_data_token_html_td($token, $cor) {

        if (is_array($token)) {
            //$token_name = is_array($token) ? $token[0] : null;
            //$token_data = is_array($token) ? $token[1] : $token;
            $type = token_name($token[0]);
            $value = $token[1];
            $value = htmlspecialchars($value);
            $line = $token[2];
            $s = "<td>$type</td><td>$line</td><th style='color:$cor'><quote>$value<quote></th>";
        } else {
            $type = $token;
            $s = "<td></td><td></td><td style='color:$cor'>$type</td>";
        }
        return($s);
    }

    function write_tokens_array_of_arrays($html_file_name, $files_files_tokens, $orientation = 'P') {
        //PN - print tokens in a HTML table 
        $f = fopen($html_file_name, "wt");
        $s = "<style> table, td, th {text-align:center; padding:2px; border: 1px solid black;border-collapse: collapse;}</style>";
        $jQuery = <<<_END
  <script src="jquery.js"></script>
    <script>
      $(document).ready(function() {
        $("td").mouseover(function() {
          if (this.innerText)
             $("td:contains(" + this.innerText + ")").css("background-color", "orange");
        });
        $("td").mouseout(function() {
          if (this.innerText)
            $("td:contains(" + this.innerText + ")").css("background-color", "white");
        });
        $("th").mouseover(function() {
          if (this.innerText)
           $("th:contains(" + this.innerText + ")").css("background-color", "orange");
        });
        $("th").mouseout(function() {
          if (this.innerText)
            $("th:contains(" + this.innerText + ")").css("background-color", "white");
        });
      });
    </script>
_END;
        fprintf($f, "%s", $jQuery);
        fprintf($f, "%s", $s);
        foreach ($files_files_tokens as $key => $token) {
            $file = $this->files->files_tokens_names[$key];
            echo "<h2><a href='$file'>$file</a></h2>";

            $tokens = $files_files_tokens[$key];
            $s = "<p>$file</p><table><tr><th>#</th><th>name</th><th>value</th><th>line</tr>" . "\n";
            fprintf($f, "%s", $s);
            for ($k = 0; $k < count($tokens); $k++) {
                //foreach ($tokens as $key => $token) {
                // token_name($token[0]);
                if (is_array($token[$k])) {
                    $name = token_name($token[$k][0]);
                    $value = $token[$k][1];
                    $value = htmlspecialchars($value);
                    $line = $token[$k][2];

                    $s = "<tr>   <td style='text-align:right'>$k</td>  <td>$name</td>   <td>$value</td>    <td>$line</td></tr>" . "\n";
                    fprintf($f, "%s", $s);
                } else {
                    $value = $token[$k];
                    $s = "<tr>   <td style='text-align:right;'>$k</td>  <td></td>  <td style='color:blue;'>$value</td>   <td></td></tr>" . "\n";
                    fprintf($f, "%s", $s);
                }
            }
            $s = "</table>" . "\n";
            fprintf($f, $s);
        }
        fclose($f);
    }

    /**
     * 
     * @param string $file_name
     * @param type $line
     * @param type $lines
     * @return string
     */
    function get_lines_of_code($file_name, $variable_name, $line, $lines) {
        //$end_index = end_of_php_line($file_name, $end_index);
        $file_name = realpath(dirname($file_name)) . DIRECTORY_SEPARATOR . basename($file_name);
        $text_lines = "<table>";
        if ((file_exists($file_name) ) && (is_file($file_name))) {
            $file_contents = file_get_contents($file_name);
            $convert = preg_split('/\r\n|\r|\n/', $file_contents);
            //$convert = explode("\n", $file_contents); //create array separate by new line
            $a = ($line - $lines >= 0 ) ? $line - $lines : 0;
            $b = ($line + $lines < count($convert)) ? $line + $lines : count($convert) - 1;
            $text_lines .= "<tr><th>File</th><td>$file_name</td></tr>";
            $text_lines .= "<tr><th>Line</th><td>$line</td></tr>";
            for ($i = $a; $i < $b; $i++) {
                $text_line = htmlentities($convert[$i]); //write value by index
                //if ($i == $line)
                $text_line = str_replace($variable_name, "<span style='color:red;'>$variable_name</span>", $text_line);
                //echo "<p>$variable_name <br>$text_line</p>";
                $text_lines .= "<tr><td>$i</td><td>$text_line</td></tr>";
            }
        } else {
            $text_lines .= "<tr><td>Cannot read the file.</td></tr>";
        }
        $text_lines .= "</table>";
        return $text_lines;
    }

    function show_variable_dependencies($variables, $index, $i) {
        if (!isset($variables[$index]))
            return "x";

        $variable = $variables[$index];
        $name = $variable['name'];
        $line = $variable['line'];
        $destroy = $variable['exist_destroyed'];
        $tainted = $variable['tainted'];
        $vulnerability = $variable['vulnerability'];
        $parser_file_base_name = basename($this->files->files_tokens_names[0]);
        $file_name = $this->files->files_tokens_names [$variable['file']];
        $lines_of_code = $this->get_lines_of_code($file_name, $name, $line, 2);
        $file_name = basename($this->files->files_tokens_names [$variable['file']]);
        $file_name_title = $file_name . " (Entry file: $parser_file_base_name)";
        $base_dir = $this->files->files_tokens_names [$variable['file']];  //dirname($this->files->files_tokens_names[0]);


        if ($tainted == 'tainted') {
            $color = " style='color:red;'";
            $tainted = "<td $color>$tainted</td>";
        } else {
            $color = "";
        }
        if ($destroy == 'destroyed') {
            $color1 = " style='color:blue;' ";
        } else {
            $color1 = "";
        }

        $di = $variable['dependencies_index'];
        if (is_array($di))
            $dep_title = "<th>Dependencies</th>";
        else
            $dep_title = "";
        //$html = "<table><tr><th>index</th><th>name</th><th>line</th><th $color1>destroy</th><th>dependencies</th></tr><tr><td>$index</td><td $color>$name</td><td>$line</td><td>$destroy</td>";
        $html = "<table><tr><th>#index</th><th>Code</th><th>Entry File</th><th>Tainted</th>$dep_title</tr>";
        $html .= "<tr><td $color>$index</td><td title='$file_name_title'>$lines_of_code </td><td title='$base_dir'>$file_name</td>$tainted";

        if (is_array($di)) {
            foreach ($di as $index => $index_variable) {
                $html2 = $this->show_variable_dependencies($variables, $index_variable, $i);
                if ($html2 != "") {
                    $html .= "<td>$html2</td>";
                }
            }
        }
        $html .= "</table>" . "\n";
        return $html;
    }
    function show_vulnerable_variables_with_dependencies_($vulnerable, $variables, $text, $echo_html, $html_file_name, $write_in_file) {
        if (!isset($variables))
            return;

        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $html_file_name);
        $c = count($variables);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}" . PHP_EOL;
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}" . "\n";
        $html = "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>" . "\n";
        $html .= "<h1 style='color:black;'>$text</h1>" . "\n";
        $html .= "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $c</p>" . "\n";
        $display = 'none';
        if ($this->html_table_visible) {
            $display = 'block';
        }
        $html .= "<table id='$id' style='display:$display;border:none;'>" . "\n";

        $count = count($variables);
        if ($count > 0) {

            $html = "";
            $number = 0;
            for ($i = 0; $i < $count; $i++) {
                //$variables[$i][''];
                if (($vulnerable == false) || ((UNKNOWN != $variables[$i]['vulnerability'] ) && (FILTERED != $variables[$i]['vulnerability'] ))) {
                    $number ++;

                    $name = $variables[$i]['name'];
                    $vulnerability = $variables[$i]['vulnerability'];
                    $tainted = $variables[$i]['tainted'];
                    $html .= "<h1> $number . Name: <span style='color:maroon;'>$name</span>  - Vulnerability: $vulnerability</h1>";

                    $deps = $this->show_variable_dependencies($variables, $i, $number);
                    //echo $deps . '<br>';
                    $html .= $deps . "\n";
                }
            }
        } // count

        if ($echo_html) {
            echo $html;
        }
        if ($write_in_file) {
            // the PHP parser file
            $parser_file_base_name = basename($this->files->files_tokens_names[0]);
            $s = './output/' . $parser_file_base_name . '_' . $html_file_name;
            $fs = fopen($s, "wt");
            if ($fs != null) {
                fprintf($fs, $html);
                fclose($fs);
                echo "<p><a href='$s'>$text</a></p>" . "\n";
            }
        }
    }

    /**
     * 
     * @param type $html_file_name
     * @param type $echo_html
     * @param type $write_in_file
     */
    function show_parser_variables_lookup() {
        return $this->show_parser_variables_lookup_("Parser variables lookup", $this->echo_parser_variables_lookup, "ParserVariablesLookup.html", $this->file_write_parser_variables_lookup);
    }

    function show_parser_variables_lookup_($text, $echo_html, $html_file_name, $write_in_file) {
        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $html_file_name);
        $c = count($this->parser_variables_lookup);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}" . PHP_EOL;
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}" . "\n";
        $html = "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>" . "\n";
        $html .= "<h1 style='color:black;'>$text</h1>" . "\n";
        $html .= "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $c</p>" . "\n";

        $html .= $this->show_parser_variables_lookup_2($id);
        if ($echo_html) {
            echo $html;
        }
        if ($write_in_file) {
            // the PHP parser file
            $parser_file_base_name = basename($this->files->files_tokens_names[0]);
            $s = './output/' . $parser_file_base_name . '_' . $html_file_name;
            $fs = fopen($s, "wt");
            if ($fs != null) {
                fprintf($fs, $html);
                fclose($fs);
                echo "<p><a href='$s'>$text</a></p>" . "\n";
            }
        }
        return $html;
    }

    function show_parser_variables_lookup_2($id) {
        if (!isset($this->parser_variables_lookup))
            return null;

        $display = 'none';
        if ($this->html_table_visible)
            $display = 'block';
        $html = "<table id='$id' style='display:$display;border:none;'>";

        $c0 = 0;
        $c = 0;
        $html .= "<tr><th>#</th><th>key 1</th><th>indexes</th></tr>";

        foreach ($this->parser_variables_lookup as $k => $v_array) {
            $c2 = count($v_array);
            $html .= "<tr><td>$c0</td><td style='vertical-align:top;'>$k <br/> ($c2)</td><td>";
            $html .= "<table>" . "\n";
            $html .= "<tr><th>#</th><th>key</th><th>index</th><th>exist_destroyed</th><th>line</th></tr>" . "\n";
            $c0++;
            foreach ($v_array as $k2 => $index) {
                $ed = $this->parser_variables[$index]['exist_destroyed'];
                $line = $this->parser_variables[$index]['line'];
                $dep = "";
                $dependencies_index = $this->parser_variables[$index]['dependencies_index'];
                if (isset($dependencies_index)) {
                    $dep = "<table><tr>";
                    foreach ($dependencies_index as $dep_index) {
                        $dep .= "<td>$dep_index<td>";
                    }
                    $dep .= "</tr></table>";
                }
                $html .= "<tr><td>$c</td><td>$k2</td><td>$index</td><td>$ed</td><td>$line</td><td>$dep</td></tr>" . "\n";
                $c++;
            }
            $html .= "</table>" . "\n";
            $html .= "</td></tr>" . "\n";
        }
        $html .= '</table>' . "\n";

        return $html;
    }

    function show_variables_csv($variables, $text, $csv_file_name) {
        if (!isset($variables))
            return;
        $id = str_replace(" ", "", $csv_file_name);
        $id = str_replace(".", "", $csv_file_name);
        $count = count($variables);
        if ($count > 0) {
            $variable = $variables[0];
            $csv = '#';
            foreach ($variable as $key => $value) {
                $csv .= ";$key";
            }
            $csv .= "\n";
            for ($i = 0; $i < $count; $i++) {
                $variable = $variables[$i];
                $csv .= "$i";
                foreach ($variable as $value) {
                    if (is_array($value)) {
                        foreach ($value as $data) {
                            if (is_array($data)) {
                                foreach ($data as $p) {
                                    $csv .= ";$p";
                                }
                            } else {
                                $csv .= ";$data";
                            }
                        }
                    } else {
                        $csv .= ";$value";
                    }
                }
                $csv .= "\n";
            }
        } // count

        $parser_file_base_name = basename($this->files->files_tokens_names[0]);
        $s = './output/' . $parser_file_base_name . '_' . $csv_file_name;
        $csv = $s . '-' . $text . "\n" . $csv;
        $fs = fopen($s, "wt");
        if ($fs != null) {
            fprintf($fs, $csv);
            fclose($fs);
            echo "<p><a href='$s'>$text</a></p>" . "\n";
        }
    }

    function show_variables($variables, $text, $echo_html, $html_file_name, $write_in_file) {
        if (!isset($variables))
            return;

        $html = <<<_END
 <script src="jquery.js"></script>
    <script>
      $(document).ready(function() {
        $("td").mouseover(function() {
          if (this.innerText)
             $("td:contains(" + this.innerText + ")").css("background-color", "orange");
        });
        $("td").mouseout(function() {
          if (this.innerText)
            $("td:contains(" + this.innerText + ")").css("background-color", "white");
        });
        $("th").mouseover(function() {
          if (this.innerText)
           $("th:contains(" + this.innerText + ")").css("background-color", "orange");
        });
        $("th").mouseout(function() {
          if (this.innerText)
            $("th:contains(" + this.innerText + ")").css("background-color", "white");
        });
      });
    </script>
_END;

        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $html_file_name);
        $c = count($variables);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}";
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}";
        $html .= "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
        $html .= "<h1 style='color:black;'>$text</h1>";
        $html .= "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $c</p>";
        $display = 'none';
        if ($this->html_table_visible)
            $display = 'block';

        if ($text == 'Vulnerable Variables')
            $display = 'block';

        $html .= "<table id='$id' style='display:$display;border:none;'>";

        $count = count($variables);
        if ($count > 0) {
            $variable = $variables[0];
            $html .= '<tr><th>#</th>';
            foreach ($variable as $key => $value) {
                $html .= "<th>$key</th>";
            }
            $html .= '</tr><tr>' . "\n";

            for ($i = 0; $i < $count; $i++) {
                //for ($i = 967; $i < $count-200; $i++) {
                $variable = $variables[$i];
                $html .= '<tr>';
                $html .= "<td>$i</td>";
                foreach ($variable as $value) {
                    if (is_array($value)) {
                        $html .= "<td><table><tr>";
                        foreach ($value as $data) {
                            if (is_array($data)) {
                                // parameters
                                $html .= "<td><table><tr>";
                                foreach ($data as $p) {
                                    $html .= "<td>$p</td>";
                                }
                                $html .= "</tr></table></td>";
                            } else {
                                $html .= "<td>$data</td>";
                            }
                        }
                        $html .= "</tr></table></td>";
                    } else {
                        if ($value === 'tainted')
                            $style = "style='color:red;'";
                        else
                            $style = "";
                        $html .= "<td $style>$value</td>";
                    }
                }
                $html .= '<tr>' . "\n";
            }
            $html .= '</table>' . "\n";
        } // count
        if ($echo_html) {
            echo $html;
        }
        if ($write_in_file) {
            // the PHP parser file
            $parser_file_base_name = basename($this->files->files_tokens_names[0]);
            $s = './output/' . $parser_file_base_name . '_' . $html_file_name;
            $fs = fopen($s, "wt");
            if ($fs != null) {
                fprintf($fs, $html);
                fclose($fs);
                echo "<p><a href='$s'>$text</a></p>" . "\n";
            }
        }
    }

    /**
     * Constructor that call all the functions that perform the static analysis looking for vulnerabilities
     * 
     * TODO check if PHP variables inside HTML code are double quoted
     * TODO dynamically created content
     * 
     * @param string $file_name with the PHP file name that is going to be parsed
     */

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

     * new
     *  
     * $ISA[] - replaces calls to is_array() function
     * 
     *
     *   */
    function main_parser($file_name, $function_name, $block_start_index, $block_end_index) {
        //$this->debug(sprintf("%s:%s:<span style='color:blue;'>%s</span> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');
        //$this->main_parser_level++;
        //$this->debug("<b><span style='color:blue;'>Before main for</span></b>: " . $file_name . ' - <b>' . $block_start_index . ' - ' . $block_end_index . '</b><br />');
        if ($this->parser_debug2_flag)
            $this->debug2("Before main for($file_name, $block_start_index, $block_end_index)", 'Before main for($file_name, $block_start_index, $block_end_index)');

        if (is_null($file_name)) {
            //point to the first php file
            reset($this->files->files_tokens);
            $file_name = key($this->files->files_tokens);
        }
        if (is_null($block_start_index)) {
            $block_start_index = 0;
        }
        if (is_null($block_end_index)) {
            $block_end_index = count($this->files->files_tokens[$file_name]) - 1;
        }

        if (is_null($function_name)) {
            //the main function of the PHP code
            $function_name = 'function';
        }

        if ($this->parser_debug2_flag)
            $this->debug2("main_parser($file_name, $function_name, $block_start_index, $block_end_index)", 'main_parser($file_name, $function_name, $block_start_index, $block_end_index)');

        $tokens = $this->files->files_tokens[$file_name];
        $ISA = $this->files->files_tokens_is_array[$file_name];  // PN
        //search every FileTokens
        for ($i = $block_start_index; $i < $block_end_index; $i++) {
            //Array tokens   
            //$time_start = microtime(true);
            //if (is_array($tokens[$i])) {   // JF
            if ($ISA[$i]) {   // PN
                // PN
                //  $type = token_name($tokens[$i][0]);
                $token = $tokens[$i][0];
                //is non PHP code
                if (T_INLINE_HTML === $token) {
                    $i = $this->parse_non_php($file_name, $function_name, $i);

                    //Loops: T_FOR T_FOREACH T_IF T_WHILE T_SWITCH
                } elseif (T_FOR === $token) {
                    $i = $this->parse_for($file_name, $function_name, $i);
                } elseif (T_FOREACH === $token) {
                    $i = $this->parse_foreach($file_name, $function_name, $i);
                } elseif (T_DO === $token) {
                    $i = $this->parse_do_while_do($file_name, $function_name, $i);
                } elseif (T_WHILE === $token) {
                    $i = $this->parse_do_while_do($file_name, $function_name, $i);

                    //Conditionals: T_IF
                } elseif (( T_IF === $token ) || ( T_ELSE === $token ) || ( T_ELSEIF === $token)) {
                    $i = $this->parse_if($file_name, $function_name, $i);

                    //Conditionals: T_SWITCH
                } elseif (T_SWITCH === $token) {
                    $i = $this->parse_switch($file_name, $function_name, $i);

                    //TODO T_GOTO
                    //T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE
                } elseif (( T_INCLUDE === $token ) || ( T_INCLUDE_ONCE === $token ) || ( T_REQUIRE === $token ) || ( T_REQUIRE_ONCE === $token )) {
                    $i = $this->parse_include_require($file_name, $function_name, $i);

                    //Output
                } elseif (( T_ECHO === $token ) || ( T_PRINT === $token ) || ( T_EXIT === $token ) || ( T_INT_CAST === $token ) || ( T_DOUBLE_CAST === $token ) || ( T_STRING_CAST === $token ) || ( T_ARRAY_CAST === $token ) || ( T_OBJECT_CAST === $token ) || ( T_BOOL_CAST === $token ) || ( T_UNSET_CAST === $token )) {
                    $output_function = $this->parse_function_method($file_name, $function_name, $i);
                    $i = $output_function[0];

                    //function call
                } elseif (($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) {
                    $function_method = $this->parse_function_method($file_name, $function_name, $i);
                    $i = $function_method[0];
                    //function definition should be skipped because it is executed when called in the PHP code
                } elseif (T_FUNCTION === $token) {
                    //skip this token
                    $i = $this->find_match($file_name, $i, '{');
                    //function return
                } elseif (T_RETURN === $token) {
                    $i = $this->parse_return($file_name, $function_name, $i);

                    //TODO T_CURLY_OPEN
                    //local and global variables
                } elseif (( T_VARIABLE === $token ) || ( T_GLOBAL === $token ) || ( T_CONST === $token ) || (($this->is_variable($file_name, $i)) || ($this->is_property($file_name, $i)))) {
                    $i = $this->parse_variable_property($file_name, $function_name, $i);
                    //T_AND_EQUAL T_CONCAT_EQUAL T_DIV_EQUAL T_MINUS_EQUAL T_MOD_EQUAL T_MUL_EQUAL T_OR_EQUAL T_PLUS_EQUAL T_XOR_EQUAL T_SL_EQUAL T_SR_EQUAL
                    //$this->echo_h1("is $i", "green");
                } elseif (( T_AND_EQUAL === $token ) || ( T_CONCAT_EQUAL === $token ) || ( T_DIV_EQUAL === $token ) || ( T_MINUS_EQUAL === $token ) || ( T_MOD_EQUAL === $token) || ( T_MUL_EQUAL === $token ) || ( T_OR_EQUAL === $token ) || ( T_PLUS_EQUAL === $token ) || ( T_XOR_EQUAL === $token ) || ( T_SL_EQUAL === $token) || ( T_SR_EQUAL === $token )) {
                    $i = $this->parse_equal($file_name, $function_name, $i);
                    //T_UNSET
                } elseif (T_UNSET === $token) {
                    $i = $this->parse_unset($file_name, $function_name, $i);
                }
            } else {     //Non array tokens
                // PN
                //  $type = $tokens[$i];
                //PN
                if ('=' === $tokens[$i]) {
                    $i = $this->parse_equal($file_name, $function_name, $i);
                }
            }
        } // for
    }

    function __construct($file_name) {
        $this->files = new Php_File($file_name);
        //$this->execution_time($time_start, "new Php_File"); 
        $this->start_time = microtime(true);

        //only analyze the file if the file exists
        if (!is_null($this->files->files_tokens)) {

            if ($this->parser_debug2_flag) {
                //$this->parser_debug2_file_stream = fopen(basename($file_name) . "_debug.html", "wt");
                $s = "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
            }
            if ($this->parser_debug2_flag_file) {
                $s = "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
                $this->parser_debug2_file_stream = fopen($this->parser_debug2_file_path . basename($file_name) . "_debug.html", "wt");
                fprintf($this->parser_debug2_file_stream, "%s", $s);
                fprintf($this->parser_debug2_file_stream, "%s", "<table>");
                $ss = $this->parser_debug2_file_path . basename($file_name) . "_debug.html";
                echo "<p><a href='$ss'>$ss</a></p>";
            }

            //add all the user defined functions to the multi-dimensional array $filesFunctions
            $this->include_all_php_files_functions();
            if ($this->echo_debug === 1) {
                echo "Total functions: " . (count($this->files_functions) - 1);
            }
            
            //Timezone added by Zé, because of error message 02/04/2015
            date_default_timezone_set('Europe/Lisbon');
            
            $s = date('Y-m-d_H_i_s', time());
            $s .= '-' . gethostname();
            $s = "";  //./output/
             if ($this->file_debug === 1) {
                $this->text_file_stream = fopen('./output/' . basename($file_name) . "_functions_call.html", "wt");
            }
            if ($this->file_write_tokens_array_of_arrays) {
                $s = './output/' . basename($file_name) . "_Tokens_array_of_arrays" . ".html";
                $this->write_tokens_array_of_arrays($s, $this->files->files_tokens);
                echo "<p><a href='$s'>files_tokens</a></p>";
            }
            if ($this->file_debug === 1) {
                fprintf($this->text_file_stream, "%s", $s);
                fprintf($this->text_file_stream, "%s", '<table>');
            }
            if ($this->echo_debug === 1) {
                echo '<table>';
            }
             $s = "<head>" . "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>" . "</head>";

            if ($this->echo_debug === 1) {
                echo $s;
            }

            if ($this->file_debug === 1) {
                fprintf($this->text_file_stream, "%s", $s);
                fflush($this->text_file_stream);
            }
            $ef = 0;
            if ($this->echo_debug === 1) {
                $ef++;
            }
            if ($this->file_debug === 1) {
                $ef++;
            }

            $geral_time_start = microtime(true);
            //parse all the functions that are not executed
             for ($i = (count($this->files_functions) - 1); $i > 0; $i--) {
                if (('not executed' === $this->files_functions[$i]['executed'] ) && ('function' != $this->files_functions[$i]['name'] )) {
                    //if(true) {
                    $file_name = $this->files_functions[$i]['file'];
                    $block_start_index = $this->files_functions[$i]['start_index'];
                    $block_start_index = $this->find_token($file_name, $block_start_index, '{');
                    $block_end_index = $this->files_functions[$i]['end_index'];
                    //parse the PHP files and searches for vulnerabilities. Adds the variables to the multi-dimensional array $parser_variables
                    $time_start = microtime(true);
                    $this->main_parser($file_name, $this->files_functions[$i]['name'], $block_start_index, $block_end_index);

                    if ($ef > 0) {
                        $time_end = microtime(true);
                        $time = $time_end - $time_start;

                        $ss = sprintf("%8.3f", $this->pn_count_function_get_variable_index / 1000.0);
                        $ss2 = sprintf("%8.4f", $this->time_function_get_variable_index);
                        $ss = "<tr><td>pn_count_function_get_variable_index</td><td>$ss K</td><td>$ss2 seg</td></tr>";
                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }

                        $ss = $this->files_functions[$i]['name'];
                        $ss = "<tr><th>level: $this->main_parser_level</th><td>$ss</td></tr>";
                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }
                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }
                        $callf = "";

                        $hours = $time / 60 / 60;
                        $minutes = ($time - floor($hours) * 60 * 60) / 60;
                        $seconds = ($time - floor($hours) * 60 * 60 - floor($minutes) * 60);
                        $times = floor($hours) . ':' . floor($minutes) . ':' . floor($seconds);

                        if ($time > 60) {
                            $cor = 'red';
                        } elseif ($time > 30) {
                            $cor = 'blue';
                        } else {
                            $cor = 'black';
                        }
                        $mu = intval(memory_get_usage() / 1024.0 / 1024.0);

                        $na = count($this->files_functions);
                        $nb = count($this->files->files_tokens);
                        $nc = count($this->used_functions);
                        $nd = count($this->functions_stack);
                        // array 2-dims
                        $cf = count($this->files_functions[$i]['called_functions']);
                        $pv = count($this->parser_variables);
                        $pd = count($this->parser_debug);

                        $pd = count($this->parser_debug);
                        $ss = "called functions: $cf /parser_variables: $pv /parser_debug: $pd /$na/$nb/$nc/$nd";

                        $ss = "<tr><td>$callf</td><td>Mb: $mu</td><th><span style='color:$cor;'>$i</span></th><td>" . $this->files_functions[$i]['name'] .
                                "</td><td>$times</td><td style='text-align:right;color:$cor;'>" . sprintf('%01.2f', $time) .
                                "</td><td>$ss</td></tr>";

                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        flush();
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }
                    }
                } else {
                    if ($ef > 0) {
                        $ss = $this->files_functions[$i]['name'];
                        $ss = "<tr><th>$i</th><td>$ss</td><td>not executed</td></tr>";

                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }
                    }
                }
            }
            if ($ef > 0) {
                $time_end = microtime(true);
                $time = $time_end - $geral_time_start;

                $hours = $time / 60 / 60;
                $minutes = ($time - floor($hours) * 60 * 60) / 60;
                $seconds = ($time - floor($hours) * 60 * 60 - floor($minutes) * 60);
                $times = floor($hours) . ':' . floor($minutes) . ':' . floor($seconds);

                $s = "<tr><th colspan='3' style='text-align:right;'>$times</b></th><th>" . sprintf('%01.2f', $time) . "</th></tr>";

                if ($this->echo_debug === 1) {
                    echo $s;
                }
                if ($this->file_debug === 1) {
                    fprintf($this->text_file_stream, "%s", $s);
                }
            }

            $this->main_parser(null, null, null, null);

            if ($ef > 0) {
                $ss = sprintf("%8.3f", $this->pn_count_function_get_variable_index / 1000.0);
                $ss2 = sprintf("%8.4f", $this->time_function_get_variable_index);
                $ss = "<tr><td>pn_count_function_get_variable_index</td><td>$ss K</td><td>$ss2 seg</td></tr>";

                if ($this->echo_debug === 1) {
                    echo $ss;
                }
                if ($this->file_debug === 1) {
                    fprintf($this->text_file_stream, "%s", $ss);
                    fflush($this->text_file_stream);
                    fprintf($this->text_file_stream, "%s", '</table>');
                }
                echo '</table>';
            }

            //add the vulnerable variables to the multi-dimensional array $vulnerable_variables
            $this->set_vulnerable_variables();
            //add the output variables to the multi-dimensional array $output_variables
            $this->set_output_variables();

            if ($this->parser_debug2_flag) {
                $s = "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
                echo "$s<h1>Debug table</h1><table>$this->parser_debug2_text</table>";
                if ($this->parser_debug2_flag_file) {
                    fprintf($this->parser_debug2_file_stream, "%s", "$s<h1>Debug table</h1><table>$this->parser_debug2_text</table>");
                    fclose($this->parser_debug2_file_stream);
                }
            }
        } // for
        $time = $this->time_execution_of;
        $timeg = microtime(true) - $this->start_time;
        $perc = 0;
        if ($timeg > 0) {
            $perc = $time / (1.0 * $timeg) * 100.0;
        }
        $P = $perc;

        $perc = sprintf('%01.3f', $perc);
        $time = sprintf('%01.4f', $time);
        $timeg = sprintf('%01.5f', $timeg);

        $s = "<h2>End of analysis</h2>";
        if ($this->echo_debug === 1) {
            echo $s;
        }

        if ($this->file_debug === 1) {
            fprintf($this->text_file_stream, "%s", $s);
            fclose($this->text_file_stream);
        }
    }

    /**
     * For all the PHP files included in the multi-dimensional array $files_tokens
     * calls the function includePhpFilesFunctions that adds the user defined functions
     * to the multi-dimensional array $filesFunctions.
     */
    function include_all_php_files_functions() {
//loop through all the PHP file names
        foreach ($this->files->files_tokens as $file_name => $dummy) {
            $this->include_php_files_functions($file_name);
        }
        for ($i = 0, $count = count($this->files_functions); $i < $count; $i++) {
            for ($j = 0, $jcount = count($this->files_functions[$i]['called_functions']); $j < $jcount; $j++) {
                $called_function_name = $this->files_functions[$i]['called_functions'][$j]['name'];
                //add the function to the $used_functions array
                $this->add_used_functions($called_function_name);
            }
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
    function include_php_files_functions($file_name) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("include_php_files_functions($file_name)", 'include_php_files_functions($file_name)');

        $called_functions = null;
        for ($i = 0, $count = count($this->files->files_tokens[$file_name]); $i < $count; $i++) {
            //generate an array of the function calls

            if (( T_ECHO === $this->files->files_tokens[$file_name][$i][0] ) || ( T_PRINT === $this->files->files_tokens[$file_name][$i][0] ) || ( T_EXIT === $this->files->files_tokens[$file_name][$i][0] ) || ( T_INT_CAST === $this->files->files_tokens[$file_name][$i][0] ) || ( T_DOUBLE_CAST === $this->files->files_tokens[$file_name][$i][0] ) || ( T_STRING_CAST === $this->files->files_tokens[$file_name][$i][0] ) || ( T_ARRAY_CAST === $this->files->files_tokens[$file_name][$i][0] ) || ( T_OBJECT_CAST === $this->files->files_tokens[$file_name][$i][0] ) || ( T_BOOL_CAST === $this->files->files_tokens[$file_name][$i][0] ) || ( T_UNSET_CAST === $this->files->files_tokens[$file_name][$i][0] ) || ($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) {
                //calculate the end token of the function call        
                $called_function_name = $this->get_function_method_name($file_name, $i);
                $i = $this->get_variable_property_function_method_last_index($file_name, $i);

                $called_functions[] = array(
                    'name' => $called_function_name,
                    'line' => $this->files->files_tokens[$file_name][$i][2]
                );
            } elseif (T_FUNCTION === $this->files->files_tokens[$file_name][$i][0]) {
                //skip this token
                $i = $this->find_match($file_name, $i, '{'); // JF
            }
        }
        //find the last file line number of the called function
        $file_end_function_line = 0;
        for ($k = $count - 1; $k >= 0; $k--) {
            if (is_array($this->files->files_tokens[$file_name][$k])) {
                $file_end_function_line = $this->files->files_tokens[$file_name][$k][2];
                break;
            }
        }

        //Add the function data to the Multi-dimensional associative array $filesFunctions
        $this->files_functions[] = array(
            'name' => 'function',
            'file' => $file_name,
            'executed' => 'executed',
            'start_line' => 0,
            'end_line' => $file_end_function_line,
            'start_index' => 0,
            'end_index' => $count - 1,
            'parameters' => null,
            'called_functions' => $called_functions,
            'start_parameter_index' => -1, // new PN
            'end_parameter_index' => -1, // new PN
        );

        // Change PN
        $key = strtoupper("function");
        $this->files_functions_lookup["$key"] = count($this->files_functions) - 1;
        // To.

        for ($i = 0, $count = count($this->files->files_tokens[$file_name]); $i < $count; $i++) {
            $file_token_start_function_index = 0;
            $file_token_end_function_index = 0;
            $file_start_function_line = 0;
            $file_end_function_line = 0;
            $function_name = null;

            //Start of a function definition
            if (is_array($this->files->files_tokens[$file_name][$i]) && (T_FUNCTION === $this->files->files_tokens[$file_name][$i][0] )) {
                $file_token_start_function_index = $i;
                $function_name = $this->get_function_method_name($file_name, $i + 1);
                $i = $this->get_variable_property_function_method_last_index($file_name, $i + 1);

                $file_start_function_line = $this->files->files_tokens[$file_name][$i][2];

                $file_token_end_function_index = $this->find_match($file_name, $i, '{');

                //generate an array of the function parameters
                $function_parameters = null; //some functions may have no parameters
                $file_token_function_start_parameter_index = $this->find_token($file_name, $i, '(');
                $file_token_function_end_parameter_index = $this->find_match($file_name, $file_token_function_start_parameter_index, '(');
                for ($j = $file_token_function_start_parameter_index; $j < $file_token_function_end_parameter_index; $j++) {
                    if (( $this->is_variable($file_name, $j)) || ( $this->is_property($file_name, $j))) {
                        $function_parameters[] = array(
                            'parameter_name' => $this->files->files_tokens[$file_name][$j][1],
                            'line' => $this->files->files_tokens[$file_name][$j][2],
                        );
                    }
                }

                $called_functions = null;
                //generate an array of the function calls
                for ($j = $file_token_function_start_parameter_index; $j < $file_token_end_function_index; $j++) {
                    $token = $this->files->files_tokens[$file_name][$j][0];
                    if (( T_ECHO === $token) || ( T_PRINT === $token ) || ( T_EXIT === $token ) || ( T_INT_CAST === $token) || ( T_DOUBLE_CAST === $token ) || ( T_STRING_CAST === $token ) || ( T_ARRAY_CAST === $token ) || ( T_OBJECT_CAST === $token ) || ( T_BOOL_CAST === $token) || ( T_UNSET_CAST === $token ) || ($this->is_function($file_name, $j)) || ($this->is_method($file_name, $j))) {
                        //calculate the end token of the function call        
                        $called_function_name = $this->get_function_method_name($file_name, $j);
                        $called_functions[] = array(
                            'name' => $called_function_name,
                            'line' => $this->files->files_tokens[$file_name][$j][2],
                        );
                        $j = $this->get_variable_property_function_method_last_index($file_name, $j);
                    } elseif (T_FUNCTION === $token) {
                        //skip this token
                        $j = $this->find_match($file_name, $j, '{');
                    }
                }

                //find the last file line number of the called function
                $file_end_function_line = $file_start_function_line;
                for ($k = $file_token_end_function_index; $k >= 0; $k--) {
                    if (is_array($this->files->files_tokens[$file_name][$k])) {
                        $file_end_function_line = $this->files->files_tokens[$file_name][$k][2];
                        break;
                    }
                }

                //Add the function data to the Multi-dimensional associative array $filesFunctions
                $this->files_functions[] = array(
                    'name' => $function_name,
                    'file' => $file_name,
                    'executed' => 'not executed',
                    'start_line' => $file_start_function_line,
                    'end_line' => $file_end_function_line,
                    'start_index' => $file_token_start_function_index,
                    'end_index' => $file_token_end_function_index,
                    'parameters' => $function_parameters,
                    'called_functions' => $called_functions,
                    'start_parameter_index' => $file_token_function_start_parameter_index, // new PN
                    'end_parameter_index' => $file_token_function_end_parameter_index, // new PN
                );
                // Change PN
                $key = strtoupper($function_name);
                $this->files_functions_lookup["$key"] = count($this->files_functions) - 1;
                // To.
                //unset the $functionParameters array but keep the indexes untouched
                unset($function_parameters);
            }
        }

        for ($i = 0, $count = count($this->files_functions); $i < $count; $i++) {
            for ($j = 0, $jcount = count($this->files_functions[$i]['called_functions']); $j < $jcount; $j++) {
                $called_function_name = strtoupper($this->files_functions[$i]['called_functions'][$j]['name']);
                // class name: TODO method complete name 
                $key = strtoupper($called_function_name);
                if (isset($this->files_functions_lookup["$key"])) {
                    $k = $this->files_functions_lookup["$key"];
                    $this->files_functions[$k]['executed'] = 'executed';
                }
            }
        }
    }

    /**
     * Add used functions to the Multi-dimensional associative array with all the functions used in the code.
     *
     * @param string $called_function_name with the name of the function
     */
    function add_used_functions($called_function_name) {
        //add the function to the $used_functions array
        $count = count($this->used_functions);
        $key = strtoupper($called_function_name);
        if (isset($this->used_functions_lookup["$key"]))
            $i = $this->used_functions_lookup["$key"];
        else
            $i = $count;

        if ($i === $count) {
            $function_user_defined = 'not user defined';
            if (isset($this->files_functions_lookup["$key"]))
                $function_user_defined = 'user defined';

            $function_input = 'not input';
            foreach (Vulnerable_Input::$INPUT_FUNCTIONS as $key => $value) {
                //foreach ($INPUT_FUNCTIONS as $key => $value) {
                foreach ($value as $output) {
                    //note: PHP functions are not case sensitive
                    if (0 === strcasecmp($output, $called_function_name)) {
                        $function_input = 'input';
                        break;
                    }
                }
            }
            $function_output = 'not output';
            $vulnerability = 'none';
            foreach (Vulnerable_Output::$OUTPUT_FUNCTIONS as $key => $value) {
                //foreach ($OUTPUT_FUNCTIONS as $key => $value) {
                foreach ($value as $output) {
                    //note: PHP functions are not case sensitive
                    if (0 === strcasecmp($output, $called_function_name)) {
                        $function_output = 'output';
                        $vulnerability = $key;
                        break;
                    }
                }
            }

            $function_filter = 'not filter';
            foreach (Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value) {
                //foreach ($VARIABLE_FILTERS as $key => $value) {
                foreach ($value as $output) {
                    //note: PHP functions are not case sensitive
                    if (0 === strcasecmp($output, $called_function_name)) {
                        $function_filter = 'filter';
                        break;
                    }
                }
            }

            $function_revert_filter = 'not revert filter';
            foreach (Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value) {
                //foreach ($REVERT_VARIABLE_FILTERS as $key => $value) {
                foreach ($value as $output) {
                    //note: PHP functions are not case sensitive
                    if (0 === strcasecmp($output, $called_function_name)) {
                        $function_revert_filter = 'revert filter';
                        break;
                    }
                }
            }

            $function_other = 'other';
            if (('user defined' === $function_user_defined) || ('input' === $function_input) || ('output' === $function_output) || ('filter' === $function_filter) || ('revert filter' === $function_revert_filter)
            ) {
                $function_other = 'not other';
            }

            $this->used_functions[] = array(
                'name' => $called_function_name,
                'user_defined' => $function_user_defined,
                'input' => $function_input,
                'output' => $function_output,
                'vulnerability' => $vulnerability,
                'filter' => $function_filter,
                'revert_filter' => $function_revert_filter,
                'other' => $function_other,
            );
            // Change 
            $key = strtoupper($called_function_name);
            $this->used_functions_lookup["$key"] = count($this->used_functions) - 1;
            // To.
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
    function parse_non_php($file_name, $function_name, $block_start_index) {
        //$t = microtime(true);
        //echo "<p>parse_non_php($file_name, $function_name, $block_start_index)</p>";
        //$this->count_execution ++;
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_non_php($file_name, $function_name, $block_start_index)", 'parse_non_php($file_name, $function_name, $block_start_index)');

//Index of the start of non PHP code
        $block_end_index = $block_start_index;
        $token = $this->files->files_tokens[$file_name];
        do {
            $block_end_index++;
            if ($block_end_index >= count($token))
                break;
        } while (!(is_array($token[$block_end_index]) && (( T_OPEN_TAG === $token[$block_end_index][0]) || ( T_OPEN_TAG_WITH_ECHO === $token[$block_end_index][0] ))));
//$this->time_execution_of += microtime(true) - $t;
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
    function parse_for($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_for($file_name, $function_name, $block_start_index)", 'parse_for($file_name, $function_name, $block_start_index)');

        $block_start_index++;
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index]) {
            $block_end_index = $this->find_match($file_name, $block_start_index, '(');
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }

        $block_start_index++;
        $this->main_parser($file_name, $function_name, $block_start_index, $block_end_index);

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
    function parse_foreach($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_foreach($file_name, $function_name, $block_start_index)", 'parse_foreach($file_name, $function_name, $block_start_index)');

        $block_start_index++;
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index]) {
            $block_end_index = $this->find_match($file_name, $block_start_index, '(');
            $block_start_index++;
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }


        for ($i = $block_start_index, $count = count($this->files->files_tokens[$file_name]); $i < $count - 1; $i++) {
            if (( is_array($this->files->files_tokens[$file_name][$i]) ) && (T_AS === $this->files->files_tokens[$file_name][$i][0])) {
                $block_as_index = $i;
                break;
            }
        }

        $expression = $this->parse_expression_vulnerability($file_name, $function_name, $block_start_index, $block_as_index, null, null);

        if (is_null($expression['dependencies_index'])) {
            $this->parse_variable_property($file_name, $function_name, $block_as_index + 1);
        } else {
            //skip '(' characters
            while ('(' === $this->files->files_tokens[$file_name][$block_start_index]) {
                $block_start_index++;
            }
            if (!is_array($this->files->files_tokens[$file_name][$block_start_index])) {
                //TODO other characters that may exist
            }

            if (( $this->is_variable($file_name, $block_start_index) ) || ( $this->is_property($file_name, $block_start_index) )) {
                $v = $block_start_index;
                //$v is passed by reference, NO
                //$variable_before_as_name = $this->get_variable_property_complete_array_name($file_name, $v);
                $ra = $this->get_variable_property_complete_array_name($file_name, $v);
                $variable_before_as_name = $ra[0];
                $v = $ra[1];
            } elseif (( $this->is_function($file_name, $block_start_index) ) || ( $this->is_method($file_name, $block_start_index) )) {
                //TODO
                $v = $block_start_index;
                //$v is passed by reference
                //$variable_before_as_name = $this->get_variable_property_complete_array_name($file_name, $v);
                $ra = $this->get_variable_property_complete_array_name($file_name, $v);
                $variable_before_as_name = $ra[0];
                $v = $ra[1];
            } else {
                //TODO
            }

            $variable_before_as_index = $this->get_variable_index($file_name, $variable_before_as_name, $function_name);

            $this->parse_foreach_vulnerability($file_name, $function_name, $block_as_index + 1, $block_end_index, $variable_before_as_index);
        }
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
    function parse_foreach_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index) {
        
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
    function parse_do_while_do($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_do_while_do($file_name, $function_name, $block_start_index)", 'parse_do_while_do($file_name, $function_name, $block_start_index)');

//do..while
        if (T_DO === $this->files->files_tokens[$file_name][$block_start_index][0]) {
            //$block_end_index = $this->find_match($file_name, $block_start_index, '{'); // JF
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '{'); // PN
            $block_end_index = $this->end_of_php_line($file_name, $block_end_index);
//while
        } elseif (T_WHILE === $this->files->files_tokens[$file_name][$block_start_index][0]) {
            //$block_end_index = $this->find_match($file_name, $block_start_index, '('); // JF
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN
            // XXXXXXXXXXX +1,add
//The alternate syntax
            if (':' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
                do {
                    $block_end_index++;
                } while (!(is_array($this->files->files_tokens[$file_name][$block_end_index]) && ( T_ENDWHILE === $this->files->files_tokens[$file_name][$block_end_index][0] )));
            }
        }

        $block_start_index++;
        $this->main_parser($file_name, $function_name, $block_start_index, $block_end_index);

        return( $block_end_index);
    }

    /**
     * Parse if conditional statement. Currentely it only calls the function $this->main_parser.
     * 
     * TODO parse differently the flow of the IF, ELSE, ELSEIF
     * 
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_if($file_name, $function_name, $block_start_index) {
        // $this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_if($file_name, $function_name, $block_start_index)", 'parse_if($file_name, $function_name, $block_start_index)');

        if ((T_IF === $this->files->files_tokens[$file_name][$block_start_index][0]) || (T_ELSEIF === $this->files->files_tokens[$file_name][$block_start_index][0])) {
// XXXXXXXXXXX +1,add
            // $block_end_index = $this->find_match($file_name, $block_start_index, '('); /JF
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN
        }
        // T_ELSE
        else {
            $block_end_index = $block_start_index;
        }

        //The alternate syntax
        if (':' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
            do {
                $block_end_index++;
            } while (!(is_array($this->files->files_tokens[$file_name][$block_end_index]) && ( T_ENDIF === $this->files->files_tokens[$file_name][$block_end_index][0] )));

            //if structure with {..}
        } elseif ('{' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
            $block_end_index = $this->find_match($file_name, $block_end_index + 1, '{');

            //if structure with just one line of code
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_end_index + 1);
        }
        $block_start_index++;

//        $ss = "<tr><th style='color:red;'>b:[$block_start_index, $block_end_index]</th></tr>";
//        echo $ss;
//        fprintf($this->text_file_stream, "%s", $ss);
//        fflush($this->text_file_stream);

        $this->main_parser($file_name, $function_name, $block_start_index, $block_end_index);

//        $ss = "<tr><th style='color:red;'>a:[$block_start_index, $block_end_index]</th></tr>";
//        echo $ss;
//        fprintf($this->text_file_stream, "%s", $ss);
//        fflush($this->text_file_stream);
        //$this->debug(' $block_end_index ' . $block_end_index . "<br />");
        if ($this->parser_debug2_flag)
            $this->debug2("parse_if - block_end_index($block_end_index)", 'parse_if - block_end_index($block_end_index');

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
    function parse_switch($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_switch($file_name, $function_name, $block_start_index)", 'parse_switch($file_name, $function_name, $block_start_index)');

        //$block_end_index = $this->find_match($file_name, $block_start_index, '('); // JF 
        $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN 
//The alternate syntax
        if (':' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
            do {
                $block_end_index++;
            } while (!(is_array($this->files->files_tokens[$file_name][$block_end_index]) && ( T_ENDSWITCH === $this->files->files_tokens[$file_name][$block_end_index][0] )));
        }

        $block_start_index++;
        $this->main_parser($file_name, $function_name, $block_start_index, $block_end_index);

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
    function parse_include_require($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_include_require($file_name, $function_name, $block_start_index)", 'parse_include_require($file_name, $function_name, $block_start_index)');

        $block_end_index = $this->end_of_php_line($file_name, $block_start_index);

//if there is an '(' after the include, include_once, require, require_once
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
            $file_name_include = $this->files->files_tokens[$file_name][$block_start_index + 2][1];
        } else {
            $file_name_include = $this->files->files_tokens[$file_name][$block_start_index + 1][1];
        }


//TODO use include_paths()  
        //Change PN
        //$file_path = dirname($file_name) . DIRECTORY_SEPARATOR;
        // get file name
        $file_path = dirname($this->files->files_tokens_names[$file_name]) . DIRECTORY_SEPARATOR;
        // To.

        if (('"' === substr($file_name_include, 0, 1) ) || ("'" === substr($file_name_include, 0, 1) )) {
            $file_name_include = substr($file_name_include, 1, -1);
        }
        $file_name_include = $file_path . $file_name_include;
        $file_name_include = realpath(dirname($file_name_include)) . DIRECTORY_SEPARATOR . basename($file_name_include);

        //echo "<hr />";
        // Change PN
        foreach ($this->files->files_tokens_names as $key => $fln) {
            //foreach ($this->files->files_tokens as $key => $token) {
            // To.
//only parse the file if it is in the multi-dimensional array variable $files_tokens
//only analyze the included file if it has not been anayzed yet
            //echo "<p>##################path:  $file_path <br/> file_name: $file_name  file_name_include: $file_name_include = $key / $fln</p>";
            //Change PN
            //if ($file_name_include === $key) {
            if ($file_name_include === $fln) {
                // To.
// get the ...ONCE attribute
// get the INCLUDE.../REQUIRE... attribute    
                $token = $this->files->files_tokens[$file_name][$block_start_index][0];
                if (T_INCLUDE_ONCE === $token) {
                    $once = 'true';
                    $include_require = 'include';
                } elseif (T_REQUIRE_ONCE === $token) {
                    $once = 'true';
                    $include_require = 'require';
                } elseif (T_INCLUDE === $token) {
                    $once = 'false';
                    $include_require = 'include';
                } elseif (T_REQUIRE === $token) {
                    $once = 'false';
                    $include_require = 'require';
                }

                $parse_again = false;
//store the include/require information int the multi-dimensional array variable $files_include_require
                for ($i = 0, $count = count($this->files_include_require); $i < $count; $i++) {
//check if the included/required file has already been included
                    if (( $file_name_include === $this->files_include_require[$i]['include_require_file_name'] ) && ($include_require === $this->files_include_require[$i]['include_require'] )) {
//the file has already been included/required once
                        $this->files_include_require[$i]['number_of_calls'] +=1;
//If is not a ...ONCE then it will be parsed every time
                        if ('false' === $once) {
                            $this->files_include_require[$i]['number_of_calls_executed'] +=1;
                            $parse_again = true;
                        }
                        break;
                    }
                }

//if this include/require has not yet been processed then add it to the multi-dimensional array variable $files_include_require
                if ($count === $i) {
                    $this->files_include_require[] = array(
                        'include_require_file_name' => $file_name_include,
                        'include_require' => $include_require,
                        'number_of_calls' => 1,
                        'number_of_calls_executed' => 1
                    );
                    $parse_again = true;
                }

//only parse the included/required file if it has not yet been parsed or it is not a ...ONCE file
                if (true === $parse_again) {
                    // Change PN
                    //$this->main_parser($file_name_include, null, null, null);
                    // Pass the number not the file name
                    $this->main_parser($key, null, null, null);
                    // To.
                }
                break; //do not need to continue searching
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
    function parse_function_method($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:<b><span style='color:orange;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_function_method($file_name, $function_name, $block_start_index)", 'parse_function_method($file_name, $function_name, $block_start_index)');

        $called_function_name = $this->get_function_method_name($file_name, $block_start_index);
        $block_start_index = $this->get_variable_property_function_method_last_index($file_name, $block_start_index);

        //calculate the end token of the function call        
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '(');
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }
        $block_start_index++;


        $called_function_index = null;
        // old
        //get the index of the function in the multi-dimensional array $files_tokens
        // search for the code of the PHP user defined function
//    for ($i = 0, $count = count($this->files_functions); $i < $count; $i++) {
//      //note: user defined PHP functions are not case sensitive
//      if (0 === strcasecmp($called_function_name, $this->files_functions[$i]['name'])) {
//        $called_function_index = $i;
//        // When the function is found in the the multi-dimensional array $this->files_functions
//        // there is no need to continue searching for more because there is only one function with the same name
//        break;
//      }
//      //there is no need for the else, because the function has to exist when arriving here
//    }
        //old
        // Change 
        $called_function_name_upper = strtoupper($called_function_name);
        if (isset($this->files_functions_lookup["$called_function_name_upper"]))
            $called_function_index = $this->files_functions_lookup["$called_function_name_upper"];
        // To.
//    if ($called_function_index != $called_function_inde)
//      echo "$called_function_index != $called_function_inde <br>";


        $used_function_index = null;
        if (!is_null($called_function_index)) {
            //found the code of the PHP user defined function
            //so it is a PHP user defined function
            //if it is a user defined function test to see if it is already being parsed
            //should not parse functions with recursivity because it will never stop
            //if the function is not already being parsed then parse it
            if ((!is_array($this->functions_stack)) || (!in_array($called_function_index, $this->functions_stack))) {
                //push the function to the stack
                $this->functions_stack[] = $called_function_index;
                $used_function_index = $this->parse_user_defined_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index);
                //pop the function from the stack
                //unset the $files_functions_stack but keep the indexes untouched
                unset($this->functions_stack[count($this->functions_stack) - 1]);
                //normalize the indexes
                $this->functions_stack = array_values($this->functions_stack);
            } else {
                //the function is already being executed
            }
            //all other functions that are not defined in the parsed PHP files, like echo, print, exit
        } else {
            // fprintf($this->text_file_stream, "\t%s n","Other");
            //fflush($this->text_file_stream);
            $used_function_index = $this->parse_other_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name);
        }

        //   return( $block_end_index);
        return( array($block_end_index, $called_function_name, $used_function_index));
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
    function parse_user_defined_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index) {
        
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
    function parse_other_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name) {
        
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
    function parse_return($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_return($file_name, $function_name, $block_start_index)", 'parse_return($file_name, $function_name, $block_start_index)');

//calculate the end token of the return statement
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
            //$block_end_index = $this->find_match($file_name, $block_start_index, '('); //JF
            // XXXXXXXXXXX +1,add
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }

        $block_start_index++;

        $this->parse_return_vulnerability($file_name, $function_name, $block_start_index, $block_end_index);

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
    function parse_return_vulnerability($file_name, $function_name, $block_start_index, $block_end_index) {
        
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
    function parse_equal($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:<b><span style='color:magenta;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_equal($file_name, $function_name, $block_start_index)", 'parse_equal($file_name, $function_name, $block_start_index)');

        //find the variable that is assigned something by searching backwards in the multi-dimensional array $files_tokens
        $variable_before_equal_name = null;
        $i = $block_start_index;

        //get the name of the assigned variable or method proterty (the one before the '=' sign)
        do {
            if (( is_array($this->files->files_tokens[$file_name][$i]) ) && (( $this->is_variable($file_name, $i) ) || ( $this->is_property($file_name, $i) ))) {
                $v = $i;
                //$v is passed by reference
                //$variable_before_equal_name = $this->get_variable_property_complete_array_name($file_name, $v);
                $ra = $this->get_variable_property_complete_array_name($file_name, $v);
                $variable_before_equal_name = $ra[0];
                $v = $ra[1];
            }
            $i--;
        } while (( 0 <= $i) && (is_null($variable_before_equal_name)));

        $variable_before_equal_index = $this->get_variable_index($file_name, $variable_before_equal_name, $function_name);
        $block_end_index = $this->end_of_php_line($file_name, $block_start_index);

        $block_start_index++;
        $this->parse_equal_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index);

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
    function parse_equal_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index) {
        
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
    function parse_variable_property($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:<span style='color:brown;'>%s</span> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_variable_property($file_name, $function_name, $block_start_index)", 'parse_variable_property($file_name, $function_name, $block_start_index)');


        $code_type = PHP_CODE;
        $function_name = $this->find_function_name_of_code($file_name, $block_start_index);

        if (T_GLOBAL === $this->files->files_tokens[$file_name][$block_start_index][0]) {
            $variable_scope = 'global';
            $block_start_index++;
        } else {
            $variable_scope = 'local';
        }

        //skip constant definitions
        if (T_CONST === $this->files->files_tokens[$file_name][$block_start_index][0]) {
            $block_start_index++;
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
            return( $block_end_index);
        }

        $block_end_index = $block_start_index;
        //$block_end_index is passed by reference
        //$variable_name = $this->get_variable_property_complete_array_name($file_name, $block_end_index);
        $ra = $this->get_variable_property_complete_array_name($file_name, $block_end_index);
        $variable_name = $ra[0];
        $block_end_index = $ra[1];

        if ($block_end_index > $block_start_index + 1) {
            //If there is a function call inside the variable definition it should be executed
            $this->main_parser($file_name, $function_name, $block_start_index + 1, $block_end_index);
        }

        $this->parse_variable_property_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type);

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
    function parse_variable_property_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type) {
        
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
    function parse_unset($file_name, $function_name, $block_start_index) {
        //$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag) {
            $this->debug2("parse_unset($file_name, $function_name, $block_start_index)", 'parse_unset($file_name, $function_name, $block_start_index)');
        }

        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
            //$block_end_index = $this->find_match($file_name, $block_start_index, '('); // JF
            // XXXXXXXXXXX +1,add
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '(');  // PN
            $block_start_index++;
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }

        $i = $this->parse_variable_property($file_name, $function_name, $block_start_index + 1);

        $v = $block_start_index + 1;
//$v is passed by reference
        //$variable_name = $this->get_variable_property_complete_array_name($file_name, $v);
        $ra = $this->get_variable_property_complete_array_name($file_name, $v);
        $variable_name = $ra[0];
        $v = $ra[1];

        $variable_index = $this->get_variable_index($file_name, $variable_name, $function_name);
        $this->parse_unset_vulnerability($block_end_index, $variable_index);
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
    function parse_unset_vulnerability($block_end_index, $variable_index) {
        
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
    function start_of_php_line($file_name, $pointer) {
        //$time_start = microtime(true);
        // Change PN
        if (isset($this->start_of_php_line_lookup[$file_name][$pointer])) {
            //$this->count_find_match ++;
            return $this->start_of_php_line_lookup[$file_name][$pointer];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
        $index = $pointer;

        $is_start_of_line = false;
        do {
//search for the first occurrence of either ';', '}', '{'
            if (( ';' === $this->files->files_tokens[$file_name][$pointer] ) || ( '}' === $this->files->files_tokens[$file_name][$pointer] ) || ('{' === $this->files->files_tokens[$file_name][$pointer] )) {
                $is_start_of_line = true;

//search for the first occurrence of either T_OPEN_TAG, T_OPEN_TAG_WITH_ECHO
            } elseif
            (( T_OPEN_TAG === $this->files->files_tokens[$file_name][$pointer][0] ) || ( T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[$file_name][$pointer][0] )) {
                $is_start_of_line = true;

//keep searching if nothing was found
            } elseif (false === $is_start_of_line) {
                $pointer--;
            }

//keep searching if nothing was found and it is not the start of the PHP file
        } while ((false === $is_start_of_line) && (0 < $pointer));

        //$this->time_execution_of += microtime(true) - $time_start;
        //table the value
        $this->start_of_php_line_lookup[$file_name][$index] = $pointer;
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
    function end_of_php_line($file_name, $pointer) {
        //$time_start = microtime(true);
        // Change PN
        if (isset($this->end_of_php_line_lookup[$file_name][$pointer])) {
            //$this->count_find_match ++;
            return $this->end_of_php_line_lookup[$file_name][$pointer];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
        $index = $pointer;

        $is_end_of_line = false;
        $count = count($this->files->files_tokens[$file_name]) - 1;

        do {
            //search for the first occurrence of either ';', '}', '{'
            if (( ';' === $this->files->files_tokens[$file_name][$pointer] ) || ( '}' === $this->files->files_tokens[$file_name][$pointer] ) || ( '{' === $this->files->files_tokens[$file_name][$pointer] )) {
                $is_end_of_line = true;
            } elseif (T_CLOSE_TAG === $this->files->files_tokens[$file_name][$pointer][0]) {  //search for the first occurrence of either T_CLOSE_TAG
                $is_end_of_line = true;
            } elseif (false === $is_end_of_line) {                                              //keep searching if nothing was found
                $pointer++;
            }

//keep searching if nothing was found and it is not the end of the PHP file
        } while (( $is_end_of_line === false ) && ($count - 1 > $pointer));

//if after the ';' it is the end of the PHP block then the end of the line is the end of the PHP block
        if (( ';' === $this->files->files_tokens[$file_name][$pointer] ) && ( T_CLOSE_TAG === $this->files->files_tokens[$file_name][$pointer + 1][0] )) {
            $pointer++;
        }

        //$this->time_execution_of += microtime(true) - $time_start;
        // table the value
        $this->end_of_php_line_lookup[$file_name][$index] = $pointer;
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
    function find_match($file_name, $block_start_index, $open_token) {

        if ($open_token === '(') {
            $close_token = ')';
        } elseif ($open_token === '{') {
            $close_token = '}';
        } elseif ($open_token === '[') {
            $close_token = ']';
        } else {
            $this->echo_h1("find_match($file_name, $block_start_index, $open_token)", 'red');
            return null;
        }
        $key = "$file_name#$block_start_index#$open_token";
        if (isset($this->files->find_match_array["$key"])) {
            //$this->count_find_match ++;
            return $this->files->find_match_array["$key"];
        }

        $count_open = 0;
        $count_close = 0;

//search for the match by taking into account the number of pairs of matching tokens
        $ISA = $this->files->files_tokens_is_array[$file_name];
        for ($i = $block_start_index, $count = count($this->files->files_tokens[$file_name]); $i < $count; $i++) {
            $t = $this->files->files_tokens[$file_name][$i];
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
        //echo "<p>$key $i</p>";
        $this->files->find_match_array["$key"] = $i;
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
    function find_token($file_name, $block_start_index, $token) {
        //$time_start = microtime(true);
        // Change PN
        if (isset($this->find_token_lookup[$file_name][$block_start_index][$token])) {
            return $this->find_token_lookup[$file_name][$block_start_index][$token];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
//search for the end of the function
        for ($i = $block_start_index, $count = count($this->files->files_tokens[$file_name]); $i < $count; $i++) {
            if ($this->files->files_tokens[$file_name][$i] === $token) {
                break;
            }
//skip if a pair of (..) or {..} is found
            if (( '(' === $this->files->files_tokens[$file_name][$i] ) || ( '{' === $this->files->files_tokens[$file_name][$i] ) || ((is_array($this->files->files_tokens[$file_name][$i])) && (T_CURLY_OPEN === $this->files->files_tokens[$file_name][$i][0]) )) {
                if (((is_array($this->files->files_tokens[$file_name][$i])) && (T_CURLY_OPEN === $this->files->files_tokens[$file_name][$i][0]))) {
                    $i = $this->find_match($file_name, $i, '{');
                } else {
                    $i = $this->find_match($file_name, $i, $this->files->files_tokens[$file_name][$i]);
                }
            }
        }
        // table the value
        $this->find_token_lookup[$file_name][$block_start_index][$token] = $i;
//$i contains the index of the token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
        return $i;
    }

    /**
     * Search for the function .
     * If in between there are '(' '{' " ' it resumes the search only after the matching ')' '}' " '
     *  
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $token with the token
     * 
     * @return int with the index of the end token in the multi-dimensional associative array $files_tokens
     */
    function find_previous_containing_function_from_index($file_name, $block_index) {
        // Change PN
        if (isset($this->find_previous_containing_function_from_index_lookup[$file_name][$block_index])) {
            return $this->find_previous_containing_function_from_index_lookup[$file_name][$block_index];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
        $function_name = null;
        $token = $this->files->files_tokens[$file_name];
        for ($i = 0; $i < $block_index; $i++) {

            if (( T_ECHO === $token[$i][0] ) || ( T_PRINT === $token[$i][0] ) || ( T_EXIT === $token[$i][0] ) || ( T_INT_CAST === $token[$i][0] ) || ( T_DOUBLE_CAST === $token[$i][0] ) || ( T_STRING_CAST === $token[$i][0] ) || ( T_ARRAY_CAST === $token[$i][0] ) || ( T_OBJECT_CAST === $token[$i][0] ) || ( T_BOOL_CAST === $token[$i][0] ) || ( T_UNSET_CAST === $token[$i][0] ) || ($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) {
//calculate the end token of the function call        
                $called_function_name = $this->get_function_method_name($file_name, $i);
                $i = $this->get_variable_property_function_method_last_index($file_name, $i);

                if ('(' === $this->files->files_tokens[$file_name][$i + 1]) {
                    $function_end_index = $this->find_match($file_name, $i + 1, '(');
                } else {
                    $function_end_index = $this->end_of_php_line($file_name, $i);
                }
                if (($block_index >= $i) && ($block_index <= $function_end_index)) {
                    $function_name = $called_function_name;
                }
                if ($this->is_method($file_name, $i)) {
//it is an object user defined function
                    $i+=2;
                }
            }
        }
        // table the value
        $this->find_previous_containing_function_from_index_lookup[$file_name][$block_index] = $function_name;
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
    function find_function_name_of_code($file_name, $file_index) {
        // Change PN
        if (isset($this->find_function_name_of_code_lookup[$file_name][$file_index])) {
            //$this->count_find_match ++;
            return $this->find_function_name_of_code_lookup[$file_name][$file_index];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
        //search for user defined functions in the multi-dimensional associative array $files_tokens
        $function_name = 'function';
        if (!empty($this->files_functions)) {
            foreach ($this->files_functions as $key => $value) {
                if (( $value['file'] === $file_name) && ( $value['start_index'] <= $file_index) && ( $value['end_index'] >= $file_index)) {
                    $function_name = $value['name'];
                    //do not return here, because there may be a function definition inside a function definition
                }
            }
        }
        //table the value
        $this->find_function_name_of_code_lookup[$file_name][$file_index] = $function_name;
        return $function_name;
    }

    /**
     * return true if the function is a php user defined function and false otherwise
     *  
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function that is going to be searched
     * 
     * @return boolean with true if the token is a php user defined function and false otherwise
     */
    function is_user_defined_function($file_name, $function_name) {
        // Change PN
        if (isset($this->is_user_defined_function_lookup[$file_name][$function_name])) {
            //$this->count_find_match ++;
            return $this->is_user_defined_function_lookup[$file_name][$function_name];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
//search for user defined functions in the multi-dimensional associative array $files_tokens
        if (!empty($this->files_functions)) {
            foreach ($this->files_functions as $key => $value) {
                if (( $value['file'] === $file_name) && ( $value['name'] === $function_name)) {
                    //table the value
                    $this->files->is_user_defined_function_lookup[$file_name][$function_name] = true;
                    return true;
                }
            }
        }
        //table the value
        $this->is_user_defined_function_lookup[$file_name][$function_name] = false;
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
    function is_variable($file_name, $file_index) {
        if ('variable' === $this->check_variable_function_property_method($file_name, $file_index)) {
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
    function is_property($file_name, $file_index) {
        if ('property' === $this->check_variable_function_property_method($file_name, $file_index)) {
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
    function is_function($file_name, $file_index) {
        if ('function' === $this->check_variable_function_property_method($file_name, $file_index)) {
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
    function is_method($file_name, $file_index) {
        if ('method' === $this->check_variable_function_property_method($file_name, $file_index)) {
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
    function check_variable_function_property_method($file_name, $file_index) {

        // Change PN
        if (isset($this->check_variable_function_property_method_lookup[$file_name][$file_index])) {
            //$this->count_find_match ++;
            return $this->check_variable_function_property_method_lookup[$file_name][$file_index];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
//    $t = microtime(true);
//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
        if ($file_index >= 0) {
            $token = $this->files->files_tokens[$file_name];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
            if (($file_index >= 2) && ((T_OBJECT_OPERATOR === $token[$file_index - 1][0] ) || (T_DOUBLE_COLON === $token[$file_index - 1][0] ))) {
                $file_index = $file_index - 2;
            }

            if (( T_VARIABLE === $token[$file_index][0] ) || ( T_STRING === $token[$file_index][0] ) || ( T_ECHO === $token[$file_index][0] ) || ( T_PRINT === $token[$file_index][0] ) || ( T_EXIT === $token[$file_index][0] ) || ( T_INT_CAST === $token[$file_index][0] ) || ( T_DOUBLE_CAST === $token[$file_index][0] ) || ( T_STRING_CAST === $token[$file_index][0] ) || ( T_ARRAY_CAST === $token[$file_index][0] ) || ( T_OBJECT_CAST === $token[$file_index][0] ) || ( T_BOOL_CAST === $token[$file_index][0] ) || ( T_UNSET_CAST === $token[$file_index][0] )
            ) {
                $name = $token[$file_index][1];

                while (( T_OBJECT_OPERATOR === $token[$file_index + 1][0] ) || (T_DOUBLE_COLON === $token[$file_index + 1][0] )) {

                    //for dynamically defined variable name, the name of the variable is the constant part only
                    //TODO improvement in this code
                    if ('{' === $token[$file_index + 2]) {
                        $file_index = $this->find_match($file_name, $file_index + 2, '{');
                        break;
                    }

                    $name = $name . $token[$file_index + 1][1] . $token[$file_index + 2][1];
                    $file_index+=2;
                }
                if ((T_OBJECT_OPERATOR === $token[$file_index - 1][0] ) || (T_DOUBLE_COLON === $token[$file_index - 1][0] )) {

                    //method
                    if ('(' === $token[$file_index + 1][0]) {
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'method';
                        return 'method';
//$this->time_execution_of += microtime(true) - $t;
                        //property
                    } else {
//$this->time_execution_of += microtime(true) - $t;     
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'property';
                        return 'property';
                    }
                } else {

                    //variable
                    if ((T_VARIABLE === $token[$file_index][0] ) && ( '(' != $token[$file_index + 1][0] )) {
//$this->time_execution_of += microtime(true) - $t;  
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'variable';
                        return 'variable';
                        //function
                    } elseif (( T_STRING === $token[$file_index][0] ) && ( '(' === $token[$file_index + 1][0] )) {
//$this->time_execution_of += microtime(true) - $t;
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'function';
                        return 'function';
                        //function
                    } elseif (( T_ECHO === $token[$file_index][0] ) || ( T_PRINT === $token[$file_index][0] ) || ( T_EXIT === $token[$file_index][0] ) || ( T_INT_CAST === $token[$file_index][0] ) || ( T_DOUBLE_CAST === $token[$file_index][0] ) || ( T_STRING_CAST === $token[$file_index][0] ) || ( T_ARRAY_CAST === $token[$file_index][0] ) || ( T_OBJECT_CAST === $token[$file_index][0] ) || ( T_BOOL_CAST === $token[$file_index][0] ) || ( T_UNSET_CAST === $token[$file_index][0] )
                    ) {
//$this->time_execution_of += microtime(true) - $t;   
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'function';
                        return 'function';
                    } else {
//$this->time_execution_of += microtime(true) - $t; 
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = null;
                        return null;
                    }
                }
//$this->time_execution_of += microtime(true) - $t;} else {
                $this->check_variable_function_property_method_lookup[$file_name][$file_index] = null;
                return null;
            }
        } else {
            $this->check_variable_function_property_method_lookup[$file_name][$file_index] = null;
//$this->time_execution_of += microtime(true) - $t;      
            return null;
        }
    }

    function get_variable_property_function_method_last_index($file_name, $file_index) {
        $count = count($this->files->files_tokens[$file_name]);
        if (($file_index < $count - 3) && ((T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index][0] ) || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index][0] ))) {
            $file_index = $file_index + 1;
        }
        while (( T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index + 1][0] ) || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index + 1][0] )) {
            $file_index+=2;
        }
        return $file_index;
    }

    /**
     * get the name of the php user defined function or an object method by parsing the multi-dimensional associative array $files_tokens
     *  
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     * 
     * @return string with the name of the php user defined function or the object method or 'variable' or 'property' or null
     */
    function get_function_method_name($file_name, $file_index) {

        // Change PN
        if (isset($this->get_function_method_name_lookup[$file_name][$file_index])) {
            //$this->count_find_match ++;
            return $this->get_function_method_name_lookup[$file_name][$file_index];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
        // 
        //$this->count_execution++;
        //$t = microtime(true);
        $name = null;

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
        if ($file_index >= 0) {
            $token = $this->files->files_tokens[$file_name];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
            if (($file_index >= 2) && ((T_OBJECT_OPERATOR === $token[$file_index - 1][0] ) || (T_DOUBLE_COLON === $token[$file_index - 1][0] ))) {
                $file_index = $file_index - 2;
            }

            if (( T_VARIABLE === $token[$file_index][0] ) || ( T_STRING === $token[$file_index][0] ) || ( T_ECHO === $token[$file_index][0] ) || ( T_PRINT === $token[$file_index][0] ) || ( T_EXIT === $token[$file_index][0] ) || ( T_INT_CAST === $token[$file_index][0] ) || ( T_DOUBLE_CAST === $token[$file_index][0] ) || ( T_STRING_CAST === $token[$file_index][0] ) || ( T_ARRAY_CAST === $token[$file_index][0] ) || ( T_OBJECT_CAST === $token[$file_index][0] ) || ( T_BOOL_CAST === $token[$file_index][0] ) || ( T_UNSET_CAST === $token[$file_index][0] )
            ) {

                $name = $token[$file_index][1];
                while (( T_OBJECT_OPERATOR === $token[$file_index + 1][0] ) || (T_DOUBLE_COLON === $token[$file_index + 1][0] )) {


                    //for dynamically defined variable name, the name of the variable is the constant part only
                    //TODO improvement in this code
                    if ('{' === $token[$file_index + 2]) {
                        $file_index = $this->find_match($file_name, $file_index + 2, '{');
//            $function_name = $this->get_function_method_name( $file_name, $file_index );
//            $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $file_index, $file_end_index, null, null );
                        break;
                    }

                    $name = $name . $token[$file_index + 1][1] . $token[$file_index + 2][1];
                    $file_index+=2;
                }
                if (( T_OBJECT_OPERATOR === $token[$file_index - 1][0] ) || (T_DOUBLE_COLON === $token[$file_index - 1][0] )) {

                    //method
                    if ('(' === $token[$file_index + 1][0]) {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;
                        //property
                    } else {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;
                    }
                } else {

                    //variable
                    if ((T_VARIABLE === $token[$file_index][0] ) && ( '(' != $token[$file_index + 1][0] )) {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;

                        //function
                    } elseif (( T_STRING === $token[$file_index][0] ) && ( '(' === $token[$file_index + 1][0] )) {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;

                        //function
                    } elseif (( T_ECHO === $token[$file_index][0] ) || ( T_PRINT === $token[$file_index][0] ) || ( T_EXIT === $token[$file_index][0] ) || ( T_INT_CAST === $token[$file_index][0] ) || ( T_DOUBLE_CAST === $token[$file_index][0] ) || ( T_STRING_CAST === $token[$file_index][0] ) || ( T_ARRAY_CAST === $token[$file_index][0] ) || ( T_OBJECT_CAST === $token[$file_index][0] ) || ( T_BOOL_CAST === $token[$file_index][0] ) || ( T_UNSET_CAST === $token[$file_index][0] )
                    ) {

                        //strip all whitespace from name, like replacing ( int ) with (int)
                        $name = preg_replace('/\s+/', '', $name);
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;
                    } else {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = null;
                        return null;
                    }
                }
            } else {
                $this->get_function_method_name_lookup[$file_name][$file_index] = null;
                return null;
            }
        } else {
            $this->get_function_method_name_lookup[$file_name][$file_index] = null;
            return null;
        }
    }

    /**
     * get the name of the php variable or an object property by parsing the multi-dimensional associative array $files_tokens
     *  
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     * 
     * @return string with the name of the php variable or the object property or 'function' or 'method' or null
     */
    function get_variable_property_name($file_name, $file_index) {
        //$this->count_execution++;
        //$t = microtime(true);
        // Change PN, update  $file_index
        if (isset($this->get_variable_property_name_lookup[$file_name][$file_index])) {
            //$this->count_find_match ++;
            //$file_index = $this->get_variable_property_complete_array_name_lookup_file_index[$file_name][$file_index]; 
            return $this->get_variable_property_name_lookup[$file_name][$file_index];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
        $file_index_ant = $file_index;

        $name = null;

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
        if ($file_index >= 0) {
            $token = $this->files->files_tokens[$file_name];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
            while (($file_index >= 2) && ((T_OBJECT_OPERATOR === $token[$file_index - 1][0] ) || (T_DOUBLE_COLON === $token[$file_index - 1][0] ) )) {
                $file_index = $file_index - 2;
            }


            if (( T_VARIABLE === $token[$file_index][0] ) || ( T_STRING === $token[$file_index][0] ) || ( T_ECHO === $token[$file_index][0] ) || ( T_PRINT === $token[$file_index][0] ) || ( T_EXIT === $token[$file_index][0] ) || ( T_INT_CAST === $token[$file_index][0] ) || ( T_DOUBLE_CAST === $token[$file_index][0] ) || ( T_STRING_CAST === $token[$file_index][0] ) || ( T_ARRAY_CAST === $token[$file_index][0] ) || ( T_OBJECT_CAST === $token[$file_index][0] ) || ( T_BOOL_CAST === $token[$file_index][0] ) || ( T_UNSET_CAST === $token[$file_index][0] )
            ) {

                $name = $token[$file_index][1];
                while (( T_OBJECT_OPERATOR === $token[$file_index + 1][0] ) || (T_DOUBLE_COLON === $token[$file_index + 1][0] )) {


                    //for dynamically defined variable name, the name of the variable is the constant part only
                    //TODO improvement in this code
                    if ('{' === $token[$file_index + 2]) {
                        $file_index = $this->find_match($file_name, $file_index + 2, '{');
//            $function_name = $this->get_function_method_name( $file_name, $file_index );
//            $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $file_index, $file_end_index, null, null );
                        break;
                    }

                    $name = $name . $token[$file_index + 1][1] . $token[$file_index + 2][1];
                    $file_index+=2;
                }
                if (( T_OBJECT_OPERATOR === $token[$file_index - 1][0] ) || (T_DOUBLE_COLON === $token[$file_index - 1][0] )) {

                    //method
                    if ('(' === $token[$file_index + 1][0]) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = 'function';
                        return 'function';
                        //property
                    } else {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = $name;
                        return $name;
                    }
                } else {

                    //variable
                    if ((T_VARIABLE === $token[$file_index][0] ) && ( '(' != $token[$file_index + 1][0] )) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = $name;
                        return $name;

                        //function
                    } elseif (( T_STRING === $token[$file_index][0] ) && ( '(' === $token[$file_index + 1][0] )) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = 'function';
                        return 'function';
                        //function
                    } elseif (( T_ECHO === $token[$file_index][0] ) || ( T_PRINT === $token[$file_index][0] ) || ( T_EXIT === $token[$file_index][0] ) || ( T_INT_CAST === $token[$file_index][0] ) || ( T_DOUBLE_CAST === $token[$file_index][0] ) || ( T_STRING_CAST === $token[$file_index][0] ) || ( T_ARRAY_CAST === $token[$file_index][0] ) || ( T_OBJECT_CAST === $token[$file_index][0] ) || ( T_BOOL_CAST === $token[$file_index][0] ) || ( T_UNSET_CAST === $token[$file_index][0] )
                    ) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = 'function';
                        return 'function';
                    } else {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = null;
                        return null;
                    }
                }
            } else {
                $this->get_variable_property_name_lookup[$file_name][$file_index] = null;
                return null;
            }
        } else {
            $this->get_variable_property_name_lookup[$file_name][$file_index] = null;
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
    /* PN
     * 
     * return array ($variable_name, $file_index)
     * 
     * 
     */
    function get_variable_property_complete_array_name($file_name, $file_index) {

        // Change PN, update  $file_index
        if (isset($this->get_variable_property_complete_array_name_lookup[$file_name][$file_index])) {
            //$this->count_find_match ++;
            //$file_index = $this->get_variable_property_complete_array_name_lookup_file_index[$file_name][$file_index]; 
            return $this->get_variable_property_complete_array_name_lookup[$file_name][$file_index];
        }
        // To.
        // The value isn't tabled, evaluate it and add to the table
        $file_index_ant = $file_index;

        //$this->count_execution++;
        //  $t = microtime(true);
        //get the variable name even if it is preceded by a '&'
        if ('&' === $this->files->files_tokens[$file_name][$file_index]) {
            $file_index++;
        }

        $variable_name = $this->get_variable_property_name($file_name, $file_index);

        $file_index = $this->get_variable_property_function_method_last_index($file_name, $file_index);

        if (($this->is_variable($file_name, $file_index)) || ($this->is_property($file_name, $file_index))) {

            if ((( T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index + 1][0] ) || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index + 1][0] ))) {
                $file_index = $file_index + 1;
                while (( T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index][0] ) || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index][0] )) {
                    $file_index = $file_index + 2;
                }
            } else {
                $file_index++;
            }

            for ($i = $file_index, $count = count($this->files->files_tokens[$file_name]); $i < $count - 1; $i++) {
                $add_index = 0;
                // test to see if it is an array variable
                if ('[' === $this->files->files_tokens[$file_name][$i]) {
                    $block_end_index = $this->find_match($file_name, $i, '[');
                    for ($j = $i; $j < $block_end_index; $j++) {
                        $add_index++;
                        if (is_array($this->files->files_tokens[$file_name][$j])) {
                            $variable_name = $variable_name . $this->files->files_tokens[$file_name][$j][1];
                        } else {
                            $variable_name = $variable_name . $this->files->files_tokens[$file_name][$j];
                        }
                    }
                    $variable_name = $variable_name . ']';
                } else {
                    break;
                }
                $i+=$add_index;
            }
            $file_index = $i - 1;
            //$this->time_execution_of += microtime(true) - $t;
            $this->get_variable_property_complete_array_name_lookup[$file_name][$file_index_ant] = array($variable_name, $file_index);
            return array($variable_name, $file_index);
        } else {
            $file_index = $file_index - 1;
            //$this->time_execution_of += microtime(true) - $t;
            $this->get_variable_property_complete_array_name_lookup[$file_name][$file_index_ant] = array($variable_name, $file_index);
            return array($variable_name, $file_index);
        }
    }

    function get_object_name($name) {
        $prefix = explode('->', $name, 2);
        $object_name = $prefix[0];
        if ($object_name === $name) {
            $object_name = null;
        }

        return $object_name;
    }

    function get_object_property_index($file_name, $function_name, $property_name) {
        $prefix = explode('->', $property_name, 2);
        $object_property_index = $this->get_variable_index($file_name, $prefix[0], $function_name);
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
    function get_variable_index_o($file_name, $variable_name, $function_name) {
        $count = count($this->parser_variables);
        for ($i = $count - 1; $i >= 0; $i--) {

//note: PHP functions are not case sensitive
            if (( $variable_name === $this->parser_variables[$i]['name'] ) && (0 === strcasecmp($this->parser_variables[$i]['file'], $file_name)) && (0 === strcasecmp($this->parser_variables[$i]['function'], $function_name) )) {
                return $i;
            }
        }
        return null;
    }

    function get_variable_index($file_name, $variable_name, $function_name) {
        $function_name = strtoupper($function_name);
        $key = "$file_name#$variable_name#$function_name";
        if (isset($this->parser_variables_lookup["$key"])) {
            $c = count($this->parser_variables_lookup["$key"]);
            return $this->parser_variables_lookup["$key"][$c - 1];
        } else {
            //$variable_index = null;
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
     * @return the multi-dimensional associative array $files_functions
     */
    function get_files_functions() {
        return $this->files_functions;
    }

    /**
     * get the multi-dimensional associative array with all the functions used in the code
     * 
     * @return the multi-dimensional associative array $used_Functions
     */
    function get_used_functions() {
        return $this->used_functions;
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
    function debug($message) {
        $this->parser_debug[] = $message;
    }

    /**
     * Show debug information html formated
     *
     * @param string $message with the debug message
     */
    function debug2($message, $parameters) {
        // header
        $m2 = str_replace('(', "<td>(</td><td>", $parameters);
        $m2 = str_replace(",", "</td><td>", $m2);
        $m2 = str_replace(")", "</td><td>)", $m2);

        $m2 = str_replace("main_parser", "<span style='color:blue'><b>main_parser [$this->main_parser_level]</b></span>", $m2);
        $m2 = str_replace("parse_variable_property_vulnerability", "<span style='color:green'><b>parse_variable_property_vulnerability</b></span>", $m2);
        $m2 = str_replace("parse_variable_property", "<span style='color:maroon'><b>parse_variable_property</b></span>", $m2);
        //$m2 = str_replace("", "<span style='color:maroon'><b></b></span>", $m2);
        $m2 = str_replace("_vulnerability", "<span style='color:red'><b>_vulnerability</b></span>", $m2);

        // Data
        //$m = str_replace('(', "<td>(</td><td>", $message);
        $m = ereg_replace('[-A-Za-z_ ]+\(', "<th></th><td>(</td><th>", $message);
        $m = str_replace(",", "</th><th>", $m);
        $m = str_replace(")", "</td><td>)", $m);
        $m = str_replace('C:\\Users\\pnunes\\Desktop\\Dropbox\\_PhD\\php_tests\\Core\phpsafe-oop_html\\test\\', " ", $m);

        //$parser_variables_lookup = $this->show_parser_variables_lookup_2(null);
        $parser_variables_lookup = "";
        $this->parser_debug2_counter++;
        $mm = "<tr><td>$this->parser_debug2_counter</td><td>$m2</td></tr><tr><td>$m</td><td>$parser_variables_lookup</td></tr>";
        $this->parser_debug2_text .= $mm;

        if ($this->parser_debug2_flag) {
            if ($this->parser_debug2_flag_file) {
                fprintf($this->parser_debug2_file_stream, "%s", $mm);
                fflush($this->parser_debug2_file_stream);
            }
        }
    }

}
// The ending PHP tag is omitted. This is actually safer than including it.