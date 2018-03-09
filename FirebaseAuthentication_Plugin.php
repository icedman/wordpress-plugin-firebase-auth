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

        add_action('rest_api_init', function() {
            register_rest_route( 'firebase-auth/v1', '/verify', array(
                'methods' => 'POST',
                'callback' => array( $this, 'verify'),
                'args' => array(
                    'id' => array(
                        'validate_callback' => function($param, $request, $key) {
                            return is_numeric( $param );
                        }),
                    ),
                )
            );

            register_rest_route( 'firebase-auth/v1', '/fetch_keys', array(
                'methods' => 'GET',
                'callback' => array( $this, 'fetch_keys'),
                'args' => array(
                    'id' => array(
                        'validate_callback' => function($param, $request, $key) {
                            return is_numeric( $param );
                        }),
                    ),
                )
            );
        });

    }

    function fetch_keys( WP_REST_Request $request ) {
        $pkeys_raw = $this->getGoogleKeys();
        return $pkeys_raw;
    }

    function verify( WP_REST_Request $request ) {
        $token = $request->get_param('token');

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

        // create wp_user entry

        return [ 'status'=>'oxk','message'=>'verified', 'decoded'=>$decoded ];

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

        // return [ 'login' => $token, 'keys' => $keys, 'decoded' => $decoded, 'options' => $opts ];
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

}
