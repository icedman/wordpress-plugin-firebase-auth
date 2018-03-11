<?php
require('vendor/autoload.php');
use \Firebase\JWT\JWT;

include_once('FirebaseAuthentication_LifeCycle.php');

function sanitize_sample_count_meta( $meta_value, $meta_key, $meta_type ) {
    echo 123;
    exit;
    return 'xxx';
}

class FirebaseAuthentication_Plugin extends FirebaseAuthentication_LifeCycle {

    /**
     * See: http://plugin.michael-simpson.com/?page_id=31
     * @return array of option meta data.
     */
    public function getOptionMetaData() {
        //  http://plugin.michael-simpson.com/?page_id=31
        return array(
            '_version' => array('Installed Version'), // Leave this one commented-out. Uncomment to test upgrades.
            'Firebase_Config' => array(__('Firebase Configuration', 'Firebase_Config'), 'textarea'),
        
        );
    }

//    protected function getOptionValueI18nString($optionValue) {
//        $i18nValue = parent::getOptionValueI18nString($optionValue);
//        return $i18nValue;
//    }

    protected function initOptions() {
        $options = $this->getOptionMetaData();
        if (!empty($options)) {
            foreach ($options as $key => $arr) {
                if (is_array($arr) && count($arr > 1)) {
                    $this->addOption($key, $arr[1]);
                }
            }
        }
    }

    public function getPluginDisplayName() {
        return 'Firebase Authentication';
    }

    protected function getMainPluginFileName() {
        return 'firebase-authentication.php';
    }

    /**
     * See: http://plugin.michael-simpson.com/?page_id=101
     * Called by install() to create any database tables if needed.
     * Best Practice:
     * (1) Prefix all table names with $wpdb->prefix
     * (2) make table names lower case only
     * @return void
     */
    protected function installDatabaseTables() {
        //        global $wpdb;
        //        $tableName = $this->prefixTableName('mytable');
        //        $wpdb->query("CREATE TABLE IF NOT EXISTS `$tableName` (
        //            `id` INTEGER NOT NULL");
    }

    /**
     * See: http://plugin.michael-simpson.com/?page_id=101
     * Drop plugin-created tables on uninstall.
     * @return void
     */
    protected function unInstallDatabaseTables() {
        //        global $wpdb;
        //        $tableName = $this->prefixTableName('mytable');
        //        $wpdb->query("DROP TABLE IF EXISTS `$tableName`");
    }


    /**
     * Perform actions when upgrading from version X to version Y
     * See: http://plugin.michael-simpson.com/?page_id=35
     * @return void
     */
    public function upgrade() {
    }

    public function addActionsAndFilters() {

        // Add options administration page
        // http://plugin.michael-simpson.com/?page_id=47
        add_action('admin_menu', array(&$this, 'addSettingsSubMenuPage'));

        // Example adding a script & style just for the options administration page
        // http://plugin.michael-simpson.com/?page_id=47
        //        if (strpos($_SERVER['REQUEST_URI'], $this->getSettingsSlug()) !== false) {
        //            wp_enqueue_script('my-script', plugins_url('/js/my-script.js', __FILE__));
        //            wp_enqueue_style('my-style', plugins_url('/css/my-style.css', __FILE__));
        //        }


        // Add Actions & Filters
        // http://plugin.michael-simpson.com/?page_id=37


        // Adding scripts & styles to all pages
        // Examples:
        //        wp_enqueue_script('jquery');
        //        wp_enqueue_style('my-style', plugins_url('/css/my-style.css', __FILE__));
        //        wp_enqueue_script('my-script', plugins_url('/js/my-script.js', __FILE__));


        // Register short codes
        // http://plugin.michael-simpson.com/?page_id=39


        // Register AJAX hooks
        // http://plugin.michael-simpson.com/?page_id=41

        // ------------------------
        //  rest API
        // ------------------------

        //add_filter( 'determine_current_user',  array($this, 'authenticate'), 30 );
        add_action( 'set_current_user', array($this, 'authenticate'), 50);
     
        add_action('rest_api_init', function() {

            $this->authenticate();

            // meta fields
            register_meta( 'user',
                'billing_phone',
                [ 'show_in_rest' => true ]
            );
            register_meta( 'user',
                'first_name',
                [ 'show_in_rest' => true ]
            );
            register_meta( 'user',
                'last_name',
                [ 'show_in_rest' => true ]
            );

            register_meta( 'post',
                '_price',
                [ 'show_in_rest' => true ]
            );

            register_meta( 'term',
                'vendor_data',
                [ 'show_in_rest' => true,
                    'sanitize_callback' => 'sanitize_sample_count_meta'
                ]
            );

            register_taxonomy( 'wcpv_product_vendors', array( 'product' ), [
                'public' => true,
                'label' => 'vendors',
                'show_in_rest' => true
            ] );

            // register_rest_route( 'firebase-auth/v1', '/verify', array(
            //     'methods' => 'GET',
            //     'callback' => array( $this, 'verify'),
            //     'args' => array(
            //         'token' => array(
            //             'type' => 'string',
            //             'description' => 'Firebase login token'
            //             ),
            //         ),
            //     )
            // );

            register_rest_route( 'firebase-auth/v1', '/verify', array(
                'methods' => 'POST',
                'callback' => array( $this, 'verifyAndUpdate'),
                'args' => array(
                    'token' => array(
                        'type' => 'string',
                        'description' => 'Firebase login token'
                        ),
                    ),
                )
            );

            register_rest_route( 'firebase-auth/v1', '/fetch_keys', array(
                'methods' => 'GET',
                'callback' => array( $this, 'fetch_keys')
                )
            );
        });

    }

    function fetch_keys( WP_REST_Request $request ) {
        $pkeys_raw = $this->getGoogleKeys();
        return $pkeys_raw;
    }

    function verify( WP_REST_Request $request, $thenUpdate = false ) {
        $token = $request->get_param('token');
        $result = $this->verifyToken($token);

        if ($result['status'] != 'ok') {
            return $result;
        }

        // create wp_user entry
        if ($thenUpdate) {
            $result['user'] = $this->createOrUpdateUser($result['decoded']);
        }

        return $result;

        // You can access parameters via direct array access on the object:
        // $param = $request['some_param'];

        // You can get the combined, merged set of parameters:
        // $parameters = $request->get_params();

        // The individual sets of parameters are also available, if needed:
        // $parameters = $request->get_url_params();
        // $parameters = $request->get_query_params();
        // $parameters = $request->get_body_params();
        // $parameters = $request->get_json_params();
        // $parameters = $request->get_default_params();

        // Uploads aren't merged in, but can be accessed separately:
        // $parameters = $request->get_file_params();
    }

    function verifyAndUpdate( WP_REST_Request $request ) {
        return $this->verify($request, true);
    }

    // ------------------------
    function verifyToken($token) {
        $pkeys_raw = file_get_contents(__DIR__ . '/keys.cache');
        $pkeys = json_decode($pkeys_raw, true);

        try {
            $decoded = JWT::decode($token, $pkeys, ["RS256"]);
        } catch(Exception $e) {
            return [ 'status'=>'error', 'message'=>'invalid token', $pkeys ];
        }

        $opts = json_decode(stripcslashes(get_option('FirebaseAuthentication_Plugin_Firebase_Config', '{}')));

        $aud = $decoded->aud;
        if (empty($aud)) {
            return [ 'status'=>'error','message'=>'not verified' ];
        }

        if ($aud != $opts->projectId) {
            return ['status'=>'error','message'=>'not verified' ];
        }

        return [ 'status'=>'ok','message'=>'verified', 'decoded'=>$decoded ];
    }

    function createOrUpdateUser($fbuser) {
        $username = explode('@',$fbuser->email)[0];
        $sanitized_user_login = sanitize_user($username);

        $default_user_name = $sanitized_user_login;
        $i = 1;
        while (username_exists($sanitized_user_login)) {
            $sanitized_user_login = $default_user_name . $i;
            $i++;
        }

        $user = get_user_by('email', $fbuser->email);
        if (empty($user)) {

            require_once(ABSPATH . WPINC . '/registration.php');
            $random_password = wp_generate_password($length = 12, $include_standard_special_chars = false);

            $ID = wp_create_user($sanitized_user_login, $random_password, $fbuser->email);
            if (is_wp_error($ID)) {
                // it won't error!
                return [];
            }
        } else {
            $ID = $user->ID;
        }

        $user = get_user_by( 'id', $ID ); 
        $user = get_userdata($ID);

        if (!empty($fbuser->name) && empty($user->data->first_name) && empty($user->data->last_name)) {
            $n = explode(' ', $fbuser->name);
            $first_name = $n[0];
            $last_name = '';
            if (count($n)>1) {
                $last_name = $n[1];
            }
            wp_update_user( array( 'ID' => $ID, 'first_name' => $first_name, 'last_name' => $last_name ) );
            $user->data->display_name = $fbuser->name;
        }

        if (!empty($fbuser->phone_number) && empty(get_usermeta($ID, 'billing_phone'))) {
            update_usermeta($ID, 'billing_phone', $fbuser->phone_number);
        }

        // update_usermeta( $user_id, 'school', $school );
        return $user;
    }

    function getGoogleKeys() {
        // settings
        $url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"; // json source
        $cache = __DIR__."/keys.cache"; // make this file in same dir
        $force_refresh = false; // dev
        $refresh = 60*60; // once an hour
        // cache json results so to not over-query (api restrictions)
        if ($force_refresh || ((time() - filectime($cache)) > ($refresh) || 0 == filesize($cache))) {
            // read json source
            $ch = curl_init($url) or die("curl issue");
            $curl_options = array(
                CURLOPT_RETURNTRANSFER  => true,
                CURLOPT_HEADER      => false,
                CURLOPT_FOLLOWLOCATION  => false,
                CURLOPT_ENCODING    => "",
                CURLOPT_AUTOREFERER     => true,
                CURLOPT_CONNECTTIMEOUT  => 7,
                CURLOPT_TIMEOUT     => 7,
                CURLOPT_MAXREDIRS   => 3,
                CURLOPT_SSL_VERIFYHOST  => false,
                CURLOPT_USERAGENT   => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.A.B.C Safari/525.13"
            );
            curl_setopt_array($ch, $curl_options);
            $curlcontent = curl_exec( $ch );
            curl_close( $ch );
            
            $handle = fopen($cache, 'wb') or die('no fopen');   
            $json_cache = $curlcontent;
            fwrite($handle, $json_cache);
            fclose($handle);
        } else {
            $json_cache = file_get_contents($cache); //locally
        }
        return $json_cache;
        
    }

    /** 
     * Get hearder Authorization
     * */
    function getAuthorizationHeader(){
        global $_SERVER;
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }
        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        return $headers;
    }

    /**
     * get access token from header
     * */
    function getBearerToken() {
        $headers = $this->getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }

    function authenticate() {
        global $current_user;
        if (!empty($current_user) && !empty($current_user->ID)) {
            return;
        }

        $token = trim($this->getBearerToken());
        if (empty($token)) {
            return;
        }

        $result = $this->verifyToken($token);
        // print_r($this->getBearerToken());

        $user = get_user_by('email', $result['decoded']->email);
        if (!empty($user)) {
            wp_set_current_user( $user->ID, $user->data->user_login );
            global $_current_user_id;
            $_current_user_id = $user->ID;
        }

        $current_user = new WP_User( $_current_user_id, $name );
        setup_userdata( $current_user->ID );
    }

    function userMetaGetCallback( $user, $field_name, $request) {
       return get_user_meta( $user[ 'id' ], $field_name, true );
    }
}
