<?php
require('vendor/autoload.php');
use \Firebase\JWT\JWT;

include_once('FirebaseAuthentication_LifeCycle.php');

class FirebaseAuthentication_Plugin extends FirebaseAuthentication_LifeCycle {

    /**
     * See: http://plugin.michael-simpson.com/?page_id=31
     * @return array of option meta data.
     */
    public function getOptionMetaData() {
        //  http://plugin.michael-simpson.com/?page_id=31
        return array(
            // '_version' => array('Installed Version'), // Leave this one commented-out. Uncomment to test upgrades.
            'Firebase_Config' => array(__('Firebase Configuration', 'Firebase_Config'), 'textarea'),
            'Firebase_Local_Auth_Secret' => array('Secret Key')
        
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

        add_action('firebase-auth-authenticate', array(&$this, 'authenticate'));

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

        //add_filter( 'determine_current_user',  array($this, 'authenticate'), 30 );
        add_action( 'set_current_user', array($this, 'authenticate'), 30);

        // ------------------------
        //  rest API
        // ------------------------
     
        add_action('rest_api_init', function() {

            $this->authenticate();

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

            register_rest_route( 'firebase-auth/v1', '/nonce', array(
                'methods' => 'GET',
                'callback' => array( $this, 'requestNonce'),
                'args' => array(
                    'actions' => array(
                        'type' => 'string',
                        'description' => 'comma delimited actions'
                        )
                    )
                )
            );

            register_rest_route( 'firebase-auth/v1', '/register', array(
                'methods' => 'POST',
                'callback' => array( $this, 'localRegister'),
                'args' => array(
                    'username' => array(
                        'type' => 'string',
                        'description' => 'Username'
                        ),
                    'password' => array(
                        'type' => 'string',
                        'description' => 'Password'
                        ),
                    'email' => array(
                        'type' => 'string',
                        'description' => 'Email'
                        ),
                    'first_name' => array(
                        'type' => 'string',
                        'description' => 'First name'
                        ),
                    'last_name' => array(
                        'type' => 'string',
                        'description' => 'Last name'
                        ),
                    'phone' => array(
                        'type' => 'string',
                        'description' => 'Phone'
                        )
                    )
                )
            );

            // local wordpress login
            register_rest_route( 'firebase-auth/v1', '/login', array(
                'methods' => 'POST',
                'callback' => array( $this, 'localLogin'),
                'args' => array(
                    'username' => array(
                        'type' => 'string',
                        'description' => 'Email'
                        ),
                    'password' => array(
                        'type' => 'string',
                        'description' => 'Password'
                        ),
                    )
                )
            );

            // verify token and create or update user
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

            // verify token and login
            register_rest_route( 'firebase-auth/v1', '/fb_login', array(
                'methods' => 'POST',
                'callback' => array( $this, 'verifyAndLogin'),
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

    function requestNonce(WP_REST_Request $request) {
        $actions = explode(',',$request->get_param('actions'));
        $res = [ 
            'nonce'=> $this->wp_create_nonce( 'wp_rest' )
         ];

         foreach($actions as $v) {
            // 'update-shipping-method'=> $this->wp_create_nonce('update-shipping-method')
            $res[$v] = $this->wp_create_nonce($v);
         }

         return $res;
    }

    function wp_create_nonce($action = -1) {
        global $current_user;
        $uid = (int)$current_user->ID;
        $token = wp_get_session_token();
        $i = wp_nonce_tick();
        return substr( wp_hash( $i . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), -12, 10 );
    }

    
    function localRegister(WP_REST_Request $request) {
        $user = (object)[
            'email' => $request->get_param('email'),
            'phone_number' => $request->get_param('phone')
        ];

        // file_put_contents('/tmp/log.txt', json_encode($request) . "\n\n" , FILE_APPEND);
        // file_put_contents('/tmp/log.txt', json_encode($user) . "\n\n" , FILE_APPEND);

        $user = $this->createOrUpdateUser($user, true);
        if ($user['error']) {
            return $user;
        }

        wp_update_user( array( 'ID' => $ID, 'password' => $request->get_param('password') ) );
        return $user;
    }

    function localLogin(WP_REST_Request $request) {
        $username = $request->get_param('username');
        $password = $request->get_param('password');
        $user = wp_signon( [
                  'user_login' => $username,
                  'user_password' => $password
                ], '');

        if ($user->errors != null) {
            return [ 'status'=>'error', 'message'=> $user->errors ];
        }

        if (!empty($user)) {
            wp_set_current_user( $user->ID, $user->data->user_login );
            global $_current_user_id;
            $_current_user_id = $user->ID;

            // login [ optional ]
            wp_set_auth_cookie( $user->ID );
            // do_action( 'wp_login', $user->data->user_login );
        }

        // generate a token
        $opts_raw = trim(get_option('FirebaseAuthentication_Plugin_Firebase_Config', '{}'));
        $opts_raw = stripcslashes($opts_raw);
        $opts = json_decode($opts_raw);

        $data = [
            'aud' => $opts->projectId,
            'email' => $user->user_email
        ];

        $secretKey = trim(get_option('FirebaseAuthentication_Plugin_Firebase_Local_Auth_Secret', 'stranger-things'));
        $secretKey = base64_decode($secretKey);

        $jwt = JWT::encode(
                $data,      //Data to be encoded in the JWT
                $secretKey, // The signing key
                'HS512'     // Algorithm used to sign the token, see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3
                );

        // return $this->verifyToken($jwt);
        return [ 'status' => 'ok', 'token' => $jwt ];
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

    function verifyAndLogin( WP_REST_Request $request ) {
        return $this->authenticate();
    }

    // ------------------------
    function verifyToken($token) {
        $pkeys_raw = file_get_contents(__DIR__ . '/keys.cache');
        $pkeys_raw = trim($pkeys_raw);
        $pkeys = json_decode($pkeys_raw, true);

        // local tokens
        try {
            $secretKey = trim(get_option('FirebaseAuthentication_Plugin_Firebase_Local_Auth_Secret', 'stranger-things'));
            $secretKey = base64_decode($secretKey);
            $decoded = JWT::decode($token, $secretKey, ["HS512"]);
        } catch(Exception $e) {
            $decoded = NULL;
            // return [ 'status'=>'error', 'message'=>'invalid token', $pkeys ];
        }

        // firebase tokens
        try {
            if (empty($decoded)) {
                $decoded = JWT::decode($token, $pkeys, ["RS256"]);
                // $decoded = JWT::decode($token, $pkeys, ["HS256"]);
            }
        } catch(Exception $e) {
            // $decoded = NULL;
            return [ 'status'=>'error', 
                    'message'=>'invalid token', 
                    'token'=>$token,
                    'keys'=>$pkeys
                ];
        }

        if (empty($decoded)) {
            return [ 'status'=>'error', 'message'=>'invalid token' ];
        }

        $opts_raw = trim(get_option('FirebaseAuthentication_Plugin_Firebase_Config', '{}'));
        $opts_raw = stripcslashes($opts_raw);
        $opts = json_decode($opts_raw);

        $aud = $decoded->aud;
        if (empty($aud)) {
            return [ 'status'=>'error','message'=>'not verified' ];
        }

        if ($aud != $opts->projectId) {
            return ['status'=>'error','message'=>'unverified project id' ];
        }

        return [ 'status'=>'ok','message'=>'verified', 'decoded'=>$decoded ];
    }

    function createOrUpdateUser($fbuser, $createOnly) {
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
                return ['error'=>'error registering user'];
            }
        } else {

            if ($createOnly) {
                return ['error'=>'email is already registered'];
            }

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
        // $force_refresh = false; // dev
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

        if (!$headers && isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        }

        // print_r($_SERVER);

        if (!$headers && function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
            // print_r($requestHeaders);
        }

        if (!$headers && function_exists('getallheaders')) {
            $requestHeaders = getallheaders();
            if (isset($h['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
            // print_r($requestHeaders);
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

        global $_REQUEST;
        if (!empty($_REQUEST['token'])) {
            return $_REQUEST['token'];
        }
        return null;
    }

    function authenticate() {
        error_reporting(E_ERROR);

        global $current_user;
        if (!empty($current_user) && !empty($current_user->ID)) {
            return [ 'status'=>'ok', 'user'=> $current_user ];
        }

        $token = trim($this->getBearerToken());
        if (empty($token)) {
            // my recurring pitfall.. always check nginx & apache
            // check that nginx/apache proxy passes this
            return ['error'=>'empty token'];
        }

        global $fbtoken;
        $fbtoken = $token;

        $result = $this->verifyToken($token);
        // todo: add error check for $result

        $user = get_user_by('email', $result['decoded']->email);
        if (!empty($user)) {
            wp_set_current_user( $user->ID, $user->data->user_login );
            global $_current_user_id;
            $_current_user_id = $user->ID;

            // login [ optional ]
            wp_set_auth_cookie( $user->ID );
            do_action( 'wp_login', $user->data->user_login );

            global $current_user;
            $current_user = new WP_User( $_current_user_id, $name );
            if (!empty($current_user)) {
                setup_userdata( $current_user->ID );
            }

            file_put_contents('/tmp/log.txt', $current_user->ID . "\n\n" , FILE_APPEND);
            file_put_contents('/tmp/log.txt', json_encode($current_user) . "\n\n" , FILE_APPEND);
        }

        $result['user'] = $user;
        return $result;
    }

    function userMetaGetCallback( $user, $field_name, $request) {
       return get_user_meta( $user[ 'id' ], $field_name, true );
    }
}
