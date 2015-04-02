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
require_once 'class-php-safe.php';

//ini_set( 'max_execution_time', 2400 ); //2400 seconds = 40 minutes
ini_set('memory_limit', -1); //-1 unlimited
set_time_limit(0); //0 unlimited execution time
?>
<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta charset="utf-8" />
        <title><?php echo APP; ?></title>
        <style>
            /*      table tr:nth-child(odd) td{
                  }
                  table tr:nth-child(even) td{
                     background-color: red;
                  }*/

            #menu {
                background-color: #EDEDED;
                font-size: 14pt;
            }
            #menu a {
                padding: 5px;
                display: inline-block;
                /* visual do link */
                background-color: #EDEDED;
                color: #333;
                text-decoration: none;
                border-bottom: 3px solid #EDEDED;
                width: 10em;
                margin: 0px;
                text-align: center;
                vertical-align: middle;
            }

            #menu a:hover {
                background-color: #D6D6D6;
                color: #6D6D6D;
                border-bottom: 3px solid #EA0000;
            }

            nav {
                padding: 0px;
                margin: 0px;
                color: #333;
            }

            #topo {
                background: linear-gradient(#444, white);
                height: 20px;
            }

            #baixomenu {
                background: linear-gradient(#DDD, #444);
                height: 20px;
            }

            #page {
                /*  background: linear-gradient(#eee, #FFF); */
                min-height: 700px;
                /*        width: 1200px;*/
                margin: auto;
                padding: 0px;
            }

            #conteudo {
                padding: 1em;
                color: whitesmoke;
            }

            #OutraPagina {
                border: none;
                width: 100%;
            }
            /* END: Menu */

            hr {
                width: 70%;
                margin-top: 50px;
                margin-bottom: 50px;
                border: 0;
                border-top: 4px solid #ccc;
            }

            h1.TForm {
                color: maroon;
                font-size: 18pt;
                font-variant: small-caps;
                margin-top: 5px;
                padding-left: 5px;
            }

            h2.TForm {
                color: maroon;
                font-variant: small-caps;
                margin-top: 5px;
                font-size: 12pt;
                padding-left: 5px;
            }

            p {margin-left: 20px;

            }

            table.TForm, td.TForm, td.TForm {
                padding: 5px;
                background-color: #eee;
            }

            th.TForm {
                color: white;
                background-color: maroon;
                font-weight: bold;
                padding: 5px;
                border: none;
                border-collapse: collapse;
                font-size: 0.9em;
                font-family: Arial, Helvetica, sans-serif;
                height: 2em;
            }

            td.TForm {
                background-color: #fff;
                height: 2em;
                padding-left: 15px;
                vertical-align: top;
            }

            td.pr {
                text-align: right;
                padding-right: 1em;
            }
            text {
                font-weight: bold;
            }
            div.caixa {
                margin-top: 5px;
                width: 100%;
            }
        </style>

        <style>
            table, td, th {
                padding:4px;
                border: 1px solid gray;
                border-collapse: collapse;
            }

        </style>


        <style>

            .imgButton{
                padding-top: 54px;
                width: 10em;
                font-size: small;
                vertical-align: bottom;
                background-position: center 4px;
                background-repeat: no-repeat;
                margin: 4px 4px 0px 0px;
                box-shadow: 2px 2px 7px rgba(0, 0, 0, 0.2);
                background-color: #fffacd;
            }

            .imgParseFile {
                background-image: url(images/php_insect2.png);
            }

            input,
            textarea,
            select {
                border: 1px solid #a9a9a9;
                background: white;
                color: #333333;
                font-size: 0.8em;
                margin: 2px 0 2px 0;
                padding: 2px;
                box-sizing: border-box;
                -moz-box-sizing: border-box;
                -webkit-box-sizing: border-box;
                border-radius: 3px;
            }

            input:enabled:focus,
            textarea:enabled:focus,
            select:enabled:focus {
                border: 1px solid #800000;
            }

            input:enabled:hover,
            textarea:enabled:hover,
            select:enabled:hover {
                background-color: #fffacd;
                border: 1px solid #800000;
            }


            input[type="checkbox"] {
                display: inline;
            }

            input[type="checkbox"]:enabled + label:hover {
                background-color: #fffacd;
                border: 1px solid #800000;
            }

            input[type="checkbox"] + label {
                padding: 12px;
                border: 1px solid #a9a9a9;
                display: inline-block;
                position: relative;
                border-radius: 3px;
                box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05), inset 0px -15px 10px -12px rgba(0, 0, 0, 0.05);
                top: 2px;
            }

            input[type="checkbox"]:checked + label:after {
                content: '\2714';
                position: absolute;
                top: 0px;
                left: 3px;
                color: maroon;
                font-size: 22px;
            }

            input[type="checkbox"]:enabled + label {
                background-color: #FFFFFF;
            }

            input[type="checkbox"]:disabled + label {
                background-color: Gainsboro;
            }

            input[type="checkbox"]:hover:enabled + label:hover {
                font-weight: bold;
            }

            input[type="checkbox"] + label:active,
            input[type="checkbox"]:checked + label:active {
                box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05), inset 0px 1px 3px rgba(0, 0, 0, 0.1);
            }

            input[type="checkbox"]:checked + label {
                box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05), inset 0px -15px 10px -12px rgba(0, 0, 0, 0.05), inset 15px 10px -12px rgba(255, 255, 255, 0.1);
            }

        </style>

        <script>
            var path = decodeURIComponent("<?php
$s = getcwd();
echo rawurlencode($s . '/test/');
?>");
            function change_php_file(value) {
                var php_path = document.getElementById('s_list_of_paths');
                var php_file = document.getElementById('s_list_of_files');
                var file_to_parse = document.getElementById('php_file');
                php_path = decodeURIComponent(php_path.value);
                php_file = php_file.value;
                file_to_parse.value = php_path + php_file;
            }
        </script>


    </head>
    <body>

        <div id='page'>
            <h1 class="TForm"><?php echo APP; ?></h1>
            <div id="topo">
            </div>
            <nav id="menu">
                <a href="#Home">Home</a>
                <!--<a href="#SQLi">Results</a>-->
            </nav>
            <div id="baixomenu"></div>
            <div class='caixa' id='Home'>

                <?php

                function get_secure_checkbox_value($chk) {
                    $value = isset($_POST["$chk"]) ? $_POST["$chk"] : false;
                    return (is_bool($value) ? $value : false);
                }

                $list_of_files = array();
                if ($handle = opendir('./test')) {
                    while (false !== ($entry = readdir($handle))) {
                        if ($entry != "." && $entry != ".." && substr($entry, 0, 1) != '.') {
                            // echo "$entry <br />";
                            $list_of_files [] = $entry;
                        }
                    }
                    closedir($handle);
                }
                sort($list_of_files);

                $select_files = "<select id='s_list_of_files' onchange='change_php_file(this.value)' size='25'>";
                foreach ($list_of_files as $file) {
                    $select_files .= "<option>$file</option>";
                }
                $select_files.= "</select>";

                $select_paths = "<select id='s_list_of_paths' onchange='change_php_file(this.value)' size='15' style='width:50em'>";
                $path = getcwd() . '/test/';
                $select_paths .= "<option selected>$path</option>";
									//$select_paths .= "<option>adds more paths</option>";
                $select_paths .= "</select>";


                //echo "<br /><div class='main'><h2>" . APP . "</h2><br /><br />";
                if (extension_loaded('tokenizer') === false) {
                    echo 'The PHP tokenizer extension must be enabled';
                    exit;
                }

                if (isset($_POST['php_file'])) {
                    $_POST['php_file'] = trim($_POST['php_file']);
                }

                if (!isset($_POST['choose_new_php_file'])) {
                    if (isset($_POST['php_file'])) {
                        $current_directory = $_POST['php_file'];
                    } else {
                        $current_directory = getcwd() . '/test/test.php';
                    }
                    ?>

                    <form method='post' action='index.php'>
                        <table class='TForm' style="text-align: center; margin-left: auto; margin-right: auto;">
                            <tr><th class='TForm'>Files</th><th class='TForm'>Paths</th></tr>
                            <tr>
                                <td class='TForm'><?php echo $select_files; ?></td>
                                <td class='TForm'><?php echo $select_paths; ?></td>
                                
                            </tr>
                            <tr>
                                <th class='TForm'>Choose a PHP file to be analyzed by phpSAFE:</th>
                                <td class='TForm'>
                                    File<input type='text' maxlength='256' size='100' id='php_file' name='php_file' value='<?php echo $current_directory; ?>' />
                                    <input type='hidden' name='choose_new_php_file' value='true' />

                                </td>
                            </tr>
                            <tr>
                                <th></th>
                                <td><input class ='imgButton imgParseFile' type = 'submit' value = 'Analyze file' /></td>
                            </tr>
                        </table>
                    </form>


                    <!--<h1>find_match ERROR, tabling is deactivated!</h1>-->
                    <?php
                    echo "</div>";
                } else {
                    echo "<h1>Security analysis of the file </h1>";
                    $file_name = $_POST['php_file'];
                    $variable_name = "";
                    $line_mark = $line_end = 0;
                    echo "<h2><a href='show_php_file.php?file=$file_name&variable_name=$variable_name&line_mark=$line_mark&line_end=$line_end'>$file_name</a></h2>";

                    $time_start = microtime(true);
                    $vulnerability_check = new PHP_SAFE(htmlspecialchars($_POST['php_file']));

                    if (count($vulnerability_check->get_files_tokens()) > 0) {
                        $nv = count($vulnerability_check->get_vulnerable_variables());
                        $time_end = microtime(true);

                        $time = $time_end - $time_start;
                        $hours = $time / 60 / 60;
                        $minutes = ($time - floor($hours) * 60 * 60) / 60;
                        $seconds = ($time - floor($hours) * 60 * 60 - floor($minutes) * 60);


                        if ($time > 1) {
                            echo "<b>" . $nv . " vulnerabilities found in " . floor($hours) . ' hours, ' . floor($minutes) . ' minutes and ' . floor($seconds) . ' seconds. It was a total of ' . sprintf('%01.2f', $time) . " seconds!</b><br />";
                        } else {
                            echo "<b>" . $nv . " vulnerabilities found in " . sprintf('%01.2f', $time) . " seconds!</b><br />";
                        }
                        echo "<form method='post' action='index.php'><input type='hidden' name='php_file' value='" . $_POST['php_file'] . "' /><br /><input class ='imgButton imgParseFile' type='submit' value ='Choose another file' /></form>";
                        echo "<hr>";

                     
                        $vulnerability_check->show_vulnerable_variables(true);
                        $vulnerability_check->show_output_variables();

                        //$vulnerability_check->show_parser_variables_with_dependencies();
                        $vulnerability_check->show_parser_variables();
                        //$vulnerability_check->show_parser_variables_lookup();

                        $vulnerability_check->show_file_functions();
                        $vulnerability_check->show_used_functions();
                        //$vulnerability_check->show_file_classes();
                        $vulnerability_check->show_files_include_require();

                        echo "<hr><form method='post'><input type='button' value ='Show All' onclick='showAll()'/><input type='button' value ='Hide All' onclick='hideAll()'/><input type='button' value ='Default All' onclick='defaultAll()'/><br /></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxParserDebug' onclick='showParserDebug(this)'/>Show/Hide Parser Debug (<b>" . count($vulnerability_check->get_parser_debug()) . "</b>) <br /><pre><span id='parserDebug'></span></pre></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxVulnerableVariables' onclick='showVulnerableVariables(this)'/>Show/Hide Vulnerable Variables (<b>" . count($vulnerability_check->get_vulnerable_variables()) . "</b>) <br /><pre><span id='vulnerableVariables'></span></pre></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxOutputVariables' onclick='showOutputVariables(this)'/>Show/Hide Output Variables (<b>" . count($vulnerability_check->get_output_variables()) . "</b>) <br /><pre><span id='outputVariables'></span></pre></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxParserVariables' onclick='showParserVariables(this)'/>Show/Hide Parser Variables (<b>" . count($vulnerability_check->get_parser_variables()) . "</b>) <br /><pre><span id='parserVariables'></span></pre></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxFilesFunctions' onclick='showFilesFunctions(this)'/>Show/Hide Files Functions (<b>" . count($vulnerability_check->get_files_functions()) . "</b>) <br /><pre><span id='filesFunctions'></span></pre></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxUsedFunctions' onclick='showUsedFunctions(this)'/>Show/Hide Used Functions (<b>" . count($vulnerability_check->get_used_functions()) . "</b>) <br /><pre><span id='usedFunctions'></span></pre></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxFilesIncludeRequire' onclick='showFilesIncludeRequire(this)'/>Show/Hide Files Include Require (<b>" . count($vulnerability_check->get_files_include_require()) . "</b>) <br /><pre><span id='filesIncludeRequire'></span></pre></form>";
                        echo "<hr><form method='post'><input type='checkbox' id='checkboxFilesTokens' onclick='showFilesTokens(this)'/>Show/Hide Files Tokens (<b>" . count($vulnerability_check->get_files_tokens()) . "</b>) <br /><pre><span id='filesTokens'></span></pre></form>";

                        echo "<hr><form method='post'><input type='button' value ='Show All' onclick='showAll()'/><input type='button' value ='Hide All' onclick='hideAll()'/><input type='button' value ='Default All' onclick='defaultAll()'/><br /></form>";
                        echo "<hr>";
                        ?>
                        <!-- JavaScript -->
                        <script>
                            function showParserDebug(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_parser_debug()); ?>;
                                    document.getElementById('parserDebug').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('parserDebug').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            function showVulnerableVariables(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_vulnerable_variables()); ?>;
                                    document.getElementById('vulnerableVariables').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('vulnerableVariables').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            function showOutputVariables(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_output_variables()); ?>;
                                    document.getElementById('outputVariables').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('outputVariables').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            function showParserVariables(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_parser_variables()); ?>;
                                    document.getElementById('parserVariables').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('parserVariables').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            function showFilesFunctions(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_files_functions()); ?>;
                                    document.getElementById('filesFunctions').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('filesFunctions').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            function showUsedFunctions(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_used_functions()); ?>;
                                    document.getElementById('usedFunctions').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('usedFunctions').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            function showFilesIncludeRequire(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_files_include_require()); ?>;
                                    document.getElementById('filesIncludeRequire').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('filesIncludeRequire').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            function showFilesTokens(checkBox)
                            {
                                if (true == checkBox.checked)
                                {
                                    var php_var = <?php echo json_encode($vulnerability_check->get_files_tokens()); ?>;
                                    document.getElementById('filesTokens').innerHTML = dump(php_var) //Could also be info.innerHTML = ...
                                } else {
                                    document.getElementById('filesTokens').innerHTML = '' //Could also be info.innerHTML = ...

                                }
                                return;
                            }

                            /**
                             * Function : dump()
                             * Arguments: The data - array,hash(associative array),object
                             *    The level - OPTIONAL
                             * Returns  : The textual representation of the array.
                             * This function was inspired by the print_r function of PHP.
                             * This will accept some data as the argument and return a
                             * text that will be a more readable version of the
                             * array/hash/object that is given.
                             * Docs: http://www.openjs.com/scripts/others/dump_function_php_print_r.php
                             */
                            function dump(arr, level) {
                                var dumped_text = "";
                                if (!level)
                                    level = 0;
                                //The padding given at the beginning of the line.
                                var level_padding = "";
                                for (var j = 0; j < level + 1; j++)
                                    level_padding += "    ";
                                if (typeof (arr) == 'object') { //Array/Hashes/Objects 
                                    for (var item in arr) {
                                        var value = arr[item];
                                        if (typeof (value) == 'object') { //If it is an array,
                                            dumped_text += level_padding + "[" + item + "] ...\n";
                                            dumped_text += dump(value, level + 1);
                                        } else {
                                            dumped_text += level_padding + "[" + item + "] => " + value + "\n";
                                        }
                                    }
                                } else { //Stings/Chars/Numbers etc.
                                    dumped_text = "===>" + arr + "<===(" + typeof (arr) + ")";
                                }
                                return dumped_text;
                            }

                            function showAll() {
                                document.getElementById('checkboxParserDebug').checked = true;
                                showParserDebug(document.getElementById('checkboxParserDebug'));
                                document.getElementById('checkboxVulnerableVariables').checked = true;
                                showVulnerableVariables(document.getElementById('checkboxVulnerableVariables'));
                                document.getElementById('checkboxOutputVariables').checked = true;
                                showOutputVariables(document.getElementById('checkboxOutputVariables'));
                                document.getElementById('checkboxParserVariables').checked = true;
                                showParserVariables(document.getElementById('checkboxParserVariables'));
                                document.getElementById('checkboxFilesFunctions').checked = true;
                                showFilesFunctions(document.getElementById('checkboxFilesFunctions'));
                                document.getElementById('checkboxFilesIncludeRequire').checked = true;
                                showFilesIncludeRequire(document.getElementById('checkboxFilesIncludeRequire'));
                                document.getElementById('checkboxFilesTokens').checked = true;
                                showFilesTokens(document.getElementById('checkboxFilesTokens'));
                            }

                            function hideAll() {
                                document.getElementById('checkboxParserDebug').checked = false;
                                showParserDebug(document.getElementById('checkboxParserDebug'));
                                document.getElementById('checkboxVulnerableVariables').checked = false;
                                showVulnerableVariables(document.getElementById('checkboxVulnerableVariables'));
                                document.getElementById('checkboxOutputVariables').checked = false;
                                showOutputVariables(document.getElementById('checkboxOutputVariables'));
                                document.getElementById('checkboxParserVariables').checked = false;
                                showParserVariables(document.getElementById('checkboxParserVariables'));
                                document.getElementById('checkboxFilesFunctions').checked = false;
                                showFilesFunctions(document.getElementById('checkboxFilesFunctions'));
                                document.getElementById('checkboxFilesIncludeRequire').checked = false;
                                showFilesIncludeRequire(document.getElementById('checkboxFilesIncludeRequire'));
                                document.getElementById('checkboxFilesTokens').checked = false;
                                showFilesTokens(document.getElementById('checkboxFilesTokens'));
                            }

                            function defaultAll() {
                                document.getElementById('checkboxParserDebug').checked = false;
                                showParserDebug(document.getElementById('checkboxParserDebug'));
                                document.getElementById('checkboxVulnerableVariables').checked = false;
                                showVulnerableVariables(document.getElementById('checkboxVulnerableVariables'));
                                document.getElementById('checkboxOutputVariables').checked = false;
                                showOutputVariables(document.getElementById('checkboxOutputVariables'));
                                document.getElementById('checkboxParserVariables').checked = false;
                                showParserVariables(document.getElementById('checkboxParserVariables'));
                                document.getElementById('checkboxFilesFunctions').checked = false;
                                showFilesFunctions(document.getElementById('checkboxFilesFunctions'));
                                document.getElementById('checkboxUsedFunctions').checked = false;
                                showFilesFunctions(document.getElementById('checkboxUsedFunctions'));
                                document.getElementById('checkboxFilesIncludeRequire').checked = false;
                                showFilesIncludeRequire(document.getElementById('checkboxFilesIncludeRequire'));
                                document.getElementById('checkboxFilesTokens').checked = false;
                                showFilesTokens(document.getElementById('checkboxFilesTokens'));
                            }

                            window.onload = defaultAll();
                        </script>    
                        <?php
                    } else {
                        echo "File does not exist!";
                        echo "<form method='post' action='index.php'><input type='hidden' name='php_file' value='" . $_POST['php_file'] . "' /><br /><input class ='imgButton imgParseFile' type='submit' value ='Choose another file' /></form>";
                    }
                }
                ?>
            </div> <!--<div id='page'>-->
    </body>
</html>