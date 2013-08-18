<?php
require_once 'class-php-safe.php';

echo "<!DOCTYPE html><title>" . APP . "</title><html><head>";
echo "<br /><div class='main'><h2>" . APP . "</h2><br /><br />";
if (extension_loaded('tokenizer') === false) {
    echo 'The PHP tokenizer extension must be enabled';
    exit;
}

if (!isset($_POST['choose_new_php_file'])) {
    if (isset($_POST['php_file'])) {
        $current_directory = $_POST['php_file'];
    } else {
        $current_directory = getcwd() . '/test/test.php';
    }
    echo <<<_END
<div><form method='post' action='index.php'>
<span class='fieldname'>Choose a PHP file to be analyzed by phpSAFE:</span>
<input type='text' maxlength='256' size='100' name='php_file' value='$current_directory' /><br /><br />
<input type='hidden' name='choose_new_php_file' value='true' />
<input type='submit' value='Anaylze this file' />
</form>
</div>
_END;
} else {
    echo "Security analysis of the file <b>" . $_POST['php_file'] . "</b><br /><br />";
    if ($vulnerability_check = new PHP_SAFE(htmlspecialchars($_POST['php_file']))) {

        echo "<form method='post' action='index.php'><input type='hidden' name='php_file' value='" . $_POST['php_file'] . "' /><input type='submit' value ='Choose another file' /></form>";
        echo "<hr><b>" . count($vulnerability_check->get_vulnerable_variables()) . " vulnerabilities found!</b><br />";
        echo "<hr><form method='post'><input type='button' value ='Show All' onclick='showAll()'/><input type='button' value ='Hide All' onclick='hideAll()'/><input type='button' value ='Default All' onclick='defaultAll()'/><br /></form>";

        echo "<hr><form method='post'><input type='checkbox' id='checkboxParserDebug' onclick='showParserDebug(this)'/>Show/Hide Parser Debug (<b>" . count($vulnerability_check->get_parser_debug()) . "</b>) <br /><pre><span id='parserDebug'></span></pre></form>";
        echo "<hr><form method='post'><input type='checkbox' id='checkboxVulnerableVariables' onclick='showVulnerableVariables(this)'/>Show/Hide Vulnerable Variables (<b>" . count($vulnerability_check->get_vulnerable_variables()) . "</b>) <br /><pre><span id='vulnerableVariables'></span></pre></form>";
        echo "<hr><form method='post'><input type='checkbox' id='checkboxOutputVariables' onclick='showOutputVariables(this)'/>Show/Hide Output Variables (<b>" . count($vulnerability_check->get_output_variables()) . "</b>) <br /><pre><span id='outputVariables'></span></pre></form>";
        echo "<hr><form method='post'><input type='checkbox' id='checkboxParserVariables' onclick='showParserVariables(this)'/>Show/Hide Parser Variables (<b>" . count($vulnerability_check->get_parser_variables()) . "</b>) <br /><pre><span id='parserVariables'></span></pre></form>";
        echo "<hr><form method='post'><input type='checkbox' id='checkboxFilesFunctions' onclick='showFilesFunctions(this)'/>Show/Hide Files Functions (<b>" . count($vulnerability_check->get_files_functions()) . "</b>) <br /><pre><span id='filesFunctions'></span></pre></form>";
        echo "<hr><form method='post'><input type='checkbox' id='checkboxFilesIncludeRequire' onclick='showFilesIncludeRequire(this)'/>Show/Hide Files Include Require (<b>" . count($vulnerability_check->get_files_include_require()) . "</b>) <br /><pre><span id='filesIncludeRequire'></span></pre></form>";
        echo "<hr><form method='post'><input type='checkbox' id='checkboxFilesTokens' onclick='showFilesTokens(this)'/>Show/Hide Files Tokens (<b>" . count($vulnerability_check->get_files_tokens()) . "</b>) <br /><pre><span id='filesTokens'></span></pre></form>";

        echo "<hr><form method='post'><input type='button' value ='Show All' onclick='showAll()'/><input type='button' value ='Hide All' onclick='hideAll()'/><input type='button' value ='Default All' onclick='defaultAll()'/><br /></form>";
        echo "<hr>";
//        echo "<pre>";
//        echo "filesTokens<br />";
//        print_r($vulnerability_check->get_files_tokens());
//        echo "</pre>";
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
                return
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
                return
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
                return
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
                return
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
                return
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
                return
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
                return
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

                if (typeof(arr) == 'object') { //Array/Hashes/Objects 
                    for (var item in arr) {
                        var value = arr[item];

                        if (typeof(value) == 'object') { //If it is an array,
                            dumped_text += level_padding + "[" + item + "] ...\n";
                            dumped_text += dump(value, level + 1);
                        } else {
                            dumped_text += level_padding + "[" + item + "] => " + value + "\n";
                        }
                    }
                } else { //Stings/Chars/Numbers etc.
                    dumped_text = "===>" + arr + "<===(" + typeof(arr) + ")";
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

                document.getElementById('checkboxVulnerableVariables').checked = true;
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

            window.onload = defaultAll();
        </script>    
        <?php
    } else {
        echo "File does not exist!";
    }
}
echo '</div>';
?>
<br /><br /></body></html>