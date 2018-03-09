<?php
/*
   Plugin Name: Firebase Authentication
   Plugin URI: http://wordpress.org/extend/plugins/firebase-authentication/
   Version: 0.1
   Author: https://github.com/icedman/wordpress-plugin-firebase-auth.git
   Description: Authenticate With Firebase
   Text Domain: firebase-authentication
   License: GPLv3
  */

/*
    "WordPress Plugin Template" Copyright (C) 2018 Michael Simpson  (email : michael.d.simpson@gmail.com)

    This following part of this file is part of WordPress Plugin Template for WordPress.

    WordPress Plugin Template is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    WordPress Plugin Template is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Contact Form to Database Extension.
    If not, see http://www.gnu.org/licenses/gpl-3.0.html
*/

$FirebaseAuthentication_minimalRequiredPhpVersion = '5.0';

/**
 * Check the PHP version and give a useful error message if the user's version is less than the required version
 * @return boolean true if version check passed. If false, triggers an error which WP will handle, by displaying
 * an error message on the Admin page
 */
function FirebaseAuthentication_noticePhpVersionWrong() {
    global $FirebaseAuthentication_minimalRequiredPhpVersion;
    echo '<div class="updated fade">' .
      __('Error: plugin "Firebase Authentication" requires a newer version of PHP to be running.',  'firebase-authentication').
            '<br/>' . __('Minimal version of PHP required: ', 'firebase-authentication') . '<strong>' . $FirebaseAuthentication_minimalRequiredPhpVersion . '</strong>' .
            '<br/>' . __('Your server\'s PHP version: ', 'firebase-authentication') . '<strong>' . phpversion() . '</strong>' .
         '</div>';
}


function FirebaseAuthentication_PhpVersionCheck() {
    global $FirebaseAuthentication_minimalRequiredPhpVersion;
    if (version_compare(phpversion(), $FirebaseAuthentication_minimalRequiredPhpVersion) < 0) {
        add_action('admin_notices', 'FirebaseAuthentication_noticePhpVersionWrong');
        return false;
    }
    return true;
}


/**
 * Initialize internationalization (i18n) for this plugin.
 * References:
 *      http://codex.wordpress.org/I18n_for_WordPress_Developers
 *      http://www.wdmac.com/how-to-create-a-po-language-translation#more-631
 * @return void
 */
function FirebaseAuthentication_i18n_init() {
    $pluginDir = dirname(plugin_basename(__FILE__));
    load_plugin_textdomain('firebase-authentication', false, $pluginDir . '/languages/');
}


//////////////////////////////////
// Run initialization
/////////////////////////////////

// Initialize i18n
add_action('plugins_loadedi','FirebaseAuthentication_i18n_init');

// Run the version check.
// If it is successful, continue with initialization for this plugin
if (FirebaseAuthentication_PhpVersionCheck()) {
    // Only load and run the init function if we know PHP version can parse it
    include_once('firebase-authentication_init.php');
    FirebaseAuthentication_init(__FILE__);
}
