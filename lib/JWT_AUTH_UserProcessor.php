<?php

class JWT_AUTH_UserProcessor {

    public static function init() {

        add_filter( 'woocommerce_api_check_authentication', array(__CLASS__, 'determine_current_user_for_wc'), 10);
        add_filter( 'determine_current_user', array(__CLASS__, 'determine_current_user'), 10);
        add_filter( 'json_authentication_errors', array(__CLASS__, 'json_authentication_errors'));

    }

    public static function json_authentication_errors ( $error )
    {
    	// Passthrough other errors
    	if ( ! empty( $error ) ) {
    		return $error;
    	}

    	global $wp_json_basic_auth_error;

    	return $wp_json_basic_auth_error;
    }

    protected static function getAuthorizationHeader() {
        $authorization = false;

        if (function_exists('getallheaders'))
        {
            $headers = getallheaders();
            if (isset($headers['Authorization'])) {
                $authorization = $headers['Authorization'];
            }
            if ( ! $authorization && isset($headers['authorization'])) {
                $authorization = $headers['authorization'];
            }
        }
        elseif (isset($_SERVER["Authorization"])){
            $authorization = $_SERVER["Authorization"];
        }

        return $authorization;
    }

    protected static function findUser($jwt, $encodedJWT) {
        $overrideUserRepo = JWT_AUTH_Options::get('override_user_repo');

        $response = apply_filters( 'wp_jwt_auth_get_user', $jwt, $encodedJWT );

        return $response;
    }

    public static function determine_current_user_for_wc($user) {
        return self::determine_current_user_generic($user, true);
    }

    public static function determine_current_user ($user) {
        return self::determine_current_user_generic($user, false);
    }
    public static function determine_current_user_generic ($user, $returnUserObj)
    {
        global $wp_json_basic_auth_error;

	      $wp_json_basic_auth_error = null;
        $authorization = self::getAuthorizationHeader();

        $authorization = str_replace('Bearer ', '', $authorization);

        if ($authorization !== '') {

            try {
                $token = self::decodeJWT($authorization);
            }
            catch(Exception $e) {
                $wp_json_basic_auth_error = $e->getMessage();
                return null;
            }

            $objuser = self::findUser($token, $authorization);

            if (!$objuser) {
                $wp_json_basic_auth_error = 'Invalid user';
                return null;
            }

            if ($returnUserObj) {
                $user = $objuser;
            }
            else {
                $user = $objuser->ID;
            }
        }

        $wp_json_basic_auth_error = true;

        return $user;
    }

    public static function JWKfetch($domain) {

        global $wp_json_basic_auth_error;
        $wp_json_basic_auth_error = null;

        $cache_expiration = JWT_AUTH_Options::get('cache_expiration');

        $endpoint = "https://$domain/.well-known/jwks.json";

        if ( false === ($secret = get_transient('WP_Auth0_JWKS_cache') ) ) {

        $secret = [];

         $response = wp_remote_get( $endpoint, array() );

            if ( $response instanceof WP_Error ) {
                $wp_json_basic_auth_error = $response->get_error_message();
                error_log( $response->get_error_message() );
                return false;
            }

            if ( $response['response']['code'] != 200 ) {
                $wp_json_basic_auth_error = $response['body'];
                error_log( $response['body'] );
                return false;
            }

            if ( $response['response']['code'] >= 300 ) return false;           

            $jwks = json_decode($response['body'], true);
            
            foreach ($jwks['keys'] as $key) { 
                $secret[$key['kid']] = self::convertCertToPem($key['x5c'][0]);
            }
            if ($cache_expiration !== 0) {
                set_transient( 'WP_Auth0_JWKS_cache', $secret, $cache_expiration * MINUTE_IN_SECONDS );
            }
        }
        return $secret;
    }

    protected function convertCertToPem($cert) {
      return '-----BEGIN CERTIFICATE-----'.PHP_EOL
          .chunk_split($cert, 64, PHP_EOL)
          .'-----END CERTIFICATE-----'.PHP_EOL;
    }

    protected static function decodeJWT($encUser)
    {
        require_once JWT_AUTH_PLUGIN_DIR . 'lib/php-jwt/Exceptions/BeforeValidException.php';
        require_once JWT_AUTH_PLUGIN_DIR . 'lib/php-jwt/Exceptions/ExpiredException.php';
        require_once JWT_AUTH_PLUGIN_DIR . 'lib/php-jwt/Exceptions/SignatureInvalidException.php';
        require_once JWT_AUTH_PLUGIN_DIR . 'lib/php-jwt/Authentication/JWT.php';

        $aud = JWT_AUTH_Options::get( 'aud' );
        $secret = JWT_AUTH_Options::get( 'secret' );
        $domain = JWT_AUTH_Options::get( 'domain' );
        $secret_base64_encoded = JWT_AUTH_Options::get( 'secret_base64_encoded' );
        $secret_type = JWT_AUTH_Options::get( 'signing_algorithm' );

        if ( $secret_type === 'RS256' ){
            $secret = self::JWKfetch($domain);
        }
        if ($secret_base64_encoded) {
            $secret = base64_decode(strtr($secret, '-_', '+/'));
        }
        try {
            // Decode the user
            $decodedToken = \JWT::decode($encUser, $secret, array($secret_type));
            
            // validate that this JWT was made for us
            if ($decodedToken->aud != $aud) {
                throw new Exception("This token is not intended for us.");
            }
        } catch(\UnexpectedValueException $e) {
            throw new Exception($e->getMessage());
        }

        return $decodedToken;
    }

}
