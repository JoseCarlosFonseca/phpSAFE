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

class Vulnerable_Filter {

//Input and output variables and functions adapted from RIPS 0.54 (http://rips-scanner.sourceforge.net/)
//
//RIPS is a static source code analyser for vulnerabilities in PHP scripts
//by Johannes Dahse (johannes.dahse@rub.de)
//
  static $VARIABLE_FILTERS = array(
    'phpGenericFunctions' => array(
      'abs',
      'base64_encode',
      'bin2hex',
      'bindec',
      'count',
      'crc32',
      'crypt',
      'date', //added by me
      'decbin',
      'doubleval',
      'filter_input',
      'floatval',
      'floor',
      'hash',
      'hexdec',
      'hexdec',
      'intval',
      'levenshtein',
      'max',
      'md5',
      'min',
      'ord',
      'rand',
      'rawurlencode',
      'round',
      'sha1',
      'sizeof',
      'strlen',
      'strpos',
      'strrpos',
      'strtotime', //added by me
      'urlencode',
    ),
    XSS => array(
      'htmlentities',
      'htmlspecialchars',
    ),
    SQL_INJECTION => array(
      'addslashes',
      'dbx_escape_string',
      'db2_escape_string',
      'ingres_escape_string',
      'maxdb_escape_string',
      'maxdb_real_escape_string',
      'mysql_escape_string',
      'mysql_real_escape_string',
      'mysqli_escape_string',
      'mysqli_real_escape_string',
      'pg_escape_string',
      'pg_escape_bytea',
      'sqlite_escape_string',
      'sqlite_udf_encode_binary',
    ),
    CODE_EXECUTION => array(
      'preg_quote',
    ),
    FILE_MANIPULATION => array(
      'basename',
      'pathinfo',
    ),
    COMMAND_EXECUTION => array(
      'escapeshellarg',
      'escapeshellcmd',
    ),
    XPATH_INJECTION => array(
      'addslashes',
    ),
    //'wp_specialchars', deprecated (ver mais em deprecated.php)
//apply_filters, --I think not
//see more at: http://codex.wordpress.org/Data_Validation
//see more at: http://fieldguide.automattic.com/avoiding-xss/
    WP_FUNCTIONS => array( //added by me
      'add_query_arg',
      'addslashes_gpc',
      'antispambot',
      'ent2ncr',
      'esc_attr',
      'esc_attr__',
      'esc_attr_x',
      'esc_html',
      'esc_html__',
      'esc_html_x',
      'esc_js',
      'esc_sql',
      'esc_textarea',
      'esc_url',
      'esc_url_raw',
      'format_to_post',
      'get_posts',
      'htmlentities2',
      'is_email',
      'like_escape',
      'remove_query_arg',
      'sanitize_email',
      'sanitize_file_name',
      'sanitize_html_class',
      'sanitize_key',
      'sanitize_mime_type',
      'sanitize_option',
      'sanitize_sql_orderby',
      'sanitize_text_field',
      'sanitize_title',
      'sanitize_title_for_query',
      'sanitize_trackback_urls',
      'sanitize_user',
      'tag_escape',
      'the_title',
      'the_title_attribute',
      'the_title_rss',
      '$wpdb->escape',
      '$wpdb->insert',
      '$wpdb->prepare',
      '$wpdb->update',
      'wp_htmledit_pre',
      'wp_html_excerpt',
      'wp_kses',
      'wp_kses_allowed_html',
      'wp_kses_data',
      'wp_kses_post',
      'wp_localize_script',
      'wp_parse_str',
      'wp_pre_kses_less_than_callback',
      'wp_richedit_pre',
      '_wp_specialchars',
      'wp_specialchars',
      'wp_strip_all_tags',
      'wptexturize',
      'wp_unique_filename',
      'zeroise',
    )
  );
  static $REVERT_VARIABLE_FILTERS = array(
    'phpFunctions' => array( //added by me
      'stripslashes',
    ),
    'wpFunctions' => array( //added by me
      'wp_specialchars_decode',
      'stripslashes_deep',
    )
  );

}


// The ending PHP tag is omitted. This is actually safer than including it.