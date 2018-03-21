<?php
/*
Plugin Name: OAuth
Plugin URI: https://servian.com.au
Description:  Allows autologin against OAuth service
Version: 1.1
Author: Servian Pty Ltd
Author URI: https://servian.com
License: GPLv2 Copyright (c) 2013 Servian Pty Ltd
*/

class OAuth {

	/**
	 * __construct
	 *
	 */
	public function __construct() {
		add_action( 'login_form', array( &$this, 'oauth_login_form' ) );
		add_action( 'wp_login', array( &$this, 'oauth_login' ), 1, 2 );
		add_action( 'wp_logout', array( &$this, 'oauth_logout' ), 1, 2 );
		if ( is_admin() ) {
			//AJAX stuff
			add_action( 'wp_ajax_oauth-callback', array( $this, 'oauth_callback' ) );
			add_action( 'wp_ajax_nopriv_oauth-callback', array( $this, 'oauth_callback' ) );

			add_action( 'admin_menu', array( $this, 'oauth_plugin_page' ) );
			add_action( 'admin_init', array( $this, 'oauth_init' ) );
		}
	} //end __construct

	/**
	 * check_option - used by launchkey_page_init
	 *
	 * @param $input
	 *
	 * @return array
	 */
	public function check_option( $input ) {
		if ( isset( $input['client_id'] ) ) {
			$client_id = trim( $input['client_id'] );
			if ( get_option( 'oauth_client_id' ) === FALSE ) {
				add_option( 'oauth_client_id', $client_id );
			}
			else {
				update_option( 'oauth_client_id', $client_id );
			}
		}
		else {
			$client_id = '';
		}

		if ( isset( $input['client_secret'] ) ) {
			$client_secret = trim( $input['client_secret'] );
			if ( get_option( 'oauth_client_secret' ) === FALSE ) {
				add_option( 'oauth_client_secret', $client_secret );
			}
			else {
				update_option( 'oauth_client_secret', $client_secret );
			}
		}
		else {
			$client_secret = '';
		}

		if ( isset( $input['allowed_domains'] ) ) {
			$allowed_domains = trim( $input['allowed_domains'] );
			if ( get_option( 'oauth_allowed_domains' ) === FALSE ) {
				add_option( 'oauth_allowed_domains', $allowed_domains );
			}
			else {
				update_option( 'oauth_allowed_domains', $allowed_domains );
			}
		}
		else {
			$allowed_domains = '';
		}

		if ( true ) {
			$autologin_active = isset( $input['autologin_active']);

			if ( get_option( 'oauth_autologin_active' ) === FALSE ) {
				add_option( 'oauth_autologin_active', $autologin_active );
			}
			else {
				update_option( 'oauth_autologin_active', $autologin_active );
			}
		}

		if ( isset( $input['url_base'] ) ) {
			$url_base = trim( $input['url_base'] );
			if ( get_option( 'oauth_url_base' ) === FALSE ) {
				add_option( 'oauth_url_base', $url_base );
			}
			else {
				update_option( 'oauth_url_base', $url_base );
			}
		}
		else {
			$url_base = '';
		}

		if ( isset( $input['img_field'] ) ) {
			$img_field = trim( $input['img_field'] );
			if ( get_option( 'oauth_img_field' ) === FALSE ) {
				add_option( 'oauth_img_field', $img_field );
			}
			else {
				update_option( 'oauth_img_field', $img_field );
			}
		}
		else {
			$img_field = '';
		}

		$options = array( $client_id, $client_secret, $allowed_domains, $autologin_active, $url_base,$img_field );
		return $options;
	} //end check_option

	/**
	 * create_admin_page - used by launchkey_plugin_page
	 */
	public function create_admin_page() {
		echo '<div class="wrap">';
		screen_icon();
		echo '    <h2>OAuth</h2>';
		echo '    <form method="post" action="options.php">';
		settings_fields( 'oauth_option_group' );
		do_settings_sections( 'oauth-setting-admin' );
		submit_button();
		echo '    </form>';
		echo '</div>';
	} //end create_admin_page

	/**
	 * create_app_key_field
	 */
	public function create_client_id_field() {
		echo '<input type="text" id="client_id" name="array_key[client_id]" value="' . get_option( 'oauth_client_id' ) . '">';
	}

	/**
	 * create_client_secret_field
	 */
	public function create_client_secret_field() {
		echo '<input type="text" id="client_secret" name="array_key[client_secret]" value="' . get_option( 'oauth_client_secret' ) . '">';
	}

	/**
	 * create_allowed_domains
	 */
	public function create_allowed_domains() {
		echo '<input type="text" id="allowed_domains" name="array_key[allowed_domains]" value="' . get_option( 'oauth_allowed_domains' ) . '">';
	}

	/**
	 * create_allowed_domains
	 */
	public function create_autologin_active_field() {
		echo '<input type="checkbox" id="autologin_active" name="array_key[autologin_active]" value="1" ' . (get_option( 'oauth_autologin_active' ) == '1' ? 'checked="checked"' : '' ) . '>';
	}

	/**
	*create_url_base_field
	*/
	public function create_url_base_field() {
		echo '<input type="text" id="url_base" name="array_key[url_base]" value="' . get_option( 'oauth_url_base' ) . '">';
	}

		/**
	*create__img_field_field
	*/
	public function create_img_field() {
		echo '<input type="text" id="img_field" name="array_key[img_field]" value="' . get_option( 'oauth_img_field' ) . '">';
	}


	/**
	 * create_allowed_domains
	 */
	public function create_redirect_url_field() {
		echo '<input type="text" id="redirect_url" name="array_key[redirect_url]" readonly="true" value="' . admin_url() .  'admin-ajax.php?action=oauth-callback">';
	}

	/**
	 * page init function - called from admin_init
	 *
	 * this function is called before anything else is done on the admin page.
	 *
	 * 1. Checks if OAuth ID token has expired
	 * 2. Uses refresh token from session to revalidate ID token
	 * 3. On failure, logs user out of Wordpress
	 */
	public function oauth_page_init() {
		$is_oauth_user = get_user_meta( wp_get_current_user()->ID, 'oauth-user', true);

		if ( is_user_logged_in() && $is_oauth_user != '' && ! isset( $_COOKIE['oauth_id_token'] ) ) {
			wp_logout();
			wp_redirect( wp_login_url());
			exit;
		}
	}

	/**
	 * handles the callback and authenticates against oauth API.
	 *
	 * performed by wp_ajax*_callback action
	 *
	 */
	public function oauth_callback() {
		if ( isset( $_GET['error'] ) ) {
			wp_redirect( wp_login_url() . "?oauth-error=1" );
		}

		$code = $_GET['code'];

		$client_id =  get_option( 'oauth_client_id' );
		$client_secret =  get_option( 'oauth_client_secret' );
		$url_base =  get_option( 'oauth_url_base' );
		$redirect_url = admin_url() . 'admin-ajax.php?action=oauth-callback';
		var_dump($code);
		if ( isset( $code ) ) {
			if ( true ) {
				//make oauth call
				$oauth_result = wp_remote_post( $url_base."/oauth/token/", array(
						'body' => array(
							'code' => $code,
							'client_id' => $client_id,
							'client_secret' => $client_secret,
							'redirect_uri' => $redirect_url,
							'grant_type' => 'authorization_code'
						)
				));

				if ( ! is_wp_error( $oauth_result ) ) {
					$oauth_response = json_decode( $oauth_result['body'], true );
				}
				else {
					wp_redirect( wp_login_url() . "?oauth-error=1" );
				}
				var_dump($oauth_response);
				die('');
				if ( isset( $oauth_response['access_token'] ) ) {
					$urlSessao = str_replace('https://login', 'https://api', $url_base);
					//vars
					$oauth_token_type        = $oauth_response['token_type'];
					$oauth_id_token          = $oauth_response['id_token'];
					$oauth_access_token      = $oauth_response['access_token'];
					$oauth_expiry            = $oauth_response['expires_in'] + current_time( 'timestamp', true );
					$idtoken_validation_result = wp_remote_get($urlSessao.'/perfil/dados/' . $oauth_id_token);

					if( ! is_wp_error($idtoken_validation_result)) {
						$idtoken_response = json_decode($idtoken_validation_result['body'], true);
						setcookie( 'oauth_id_token', $oauth_id_token, $oauth_expiry, COOKIEPATH, COOKIE_DOMAIN );
						setcookie( 'oauth_username', $oauth_username,  (time() + ( 86400 * 7)), COOKIEPATH, COOKIE_DOMAIN );
					} else {
						wp_redirect( wp_login_url() . "?oauth-token-error=1" );
					}
					$oauth_username = $idtoken_response['email'];
					$user = get_user_by('login', $oauth_username);


					if (! isset( $user->ID ) ) {
						$new_user_id = $this->try_create_domain_user($oauth_username);
						$user = get_user_by('id', $new_user_id);
					}

					// this is NOT an else condition related to the previous IF
					if(isset($user->ID)) {
						$is_oauth_meta_exists = (get_user_meta($user->ID, 'oauth-user', true) != '');
						if ( ! $is_oauth_meta_exists ) {
							add_user_meta( $user->ID, 'oauth-user', true, true);
						}

						wp_set_auth_cookie( $user->ID, false );
						wp_redirect( home_url() );
					} else {
						wp_redirect( wp_login_url() . "?domain-error=1&oauth-username=" . urlencode($oauth_username) );
					}

				}
				else {
					wp_redirect( wp_login_url() . "?oauth-error=1" );
				}
			}
			else {
				wp_redirect( wp_login_url() . "?oauth-error=1" );
			}
		}
		else {
			wp_redirect( wp_login_url() . "?oauth-error=1" );
		}
	}

	/**
	 *
	 */
	private function try_create_domain_user($username) {
		if ($this->is_domain_allowed($username)) {
			$user = get_userdatabylogin($username);
			$random_password = wp_generate_password( 12, false );
			$user_id = wp_create_user( $username, $random_password, $username);
			add_user_meta( $user_id, 'oauth-user', true, true);
			return $user_id;
		} else {
			return null;
		}
	}

	/**
	 * checks if user's domain is allowed for wordpress @author servian
	 * i.e. someone@apps-enabled-business.com is ok, whilst someone@foo.com is not allowed
	 *
	 * @param unknown $username
	 * @return boolean
	 */
	private function is_domain_allowed($username) {
		$parts = explode("@",$username);
		if (count($parts) != 2) {
			return false;
		} else {
			$user_domain = $parts[1];

			$domains_allowed_field = get_option('oauth_allowed_domains');

			if (isset($domains_allowed_field) && trim($domains_allowed_field) != '') {
				$domains_allowed = explode(",",ereg_replace(' ','',$domains_allowed_field));
			}
			if (is_array($domains_allowed)) {
				foreach ($domains_allowed as $domain) {
					if (strtolower($user_domain) == strtolower($domain)) {
						return true;
					}
				}
			}
			return false;
		}
	}


	/**
	 * wp-login.php with specifics
	 *
	 * @access public
	 * @return void,
	 *
	 */
	public function oauth_login_form() {
		$clientId =  get_option( 'oauth_client_id' );
		$autologinActive =  get_option( 'oauth_autologin_active' );
		$imgOauth =  get_option( 'oauth_img_field' );
		$redirectUrl = admin_url( 'admin-ajax.php?action=oauth-callback' );
		$linkOauth =  get_option( 'oauth_url_base' )."/oauth/authorize/?response_type=code".
  			"&client_id="     . $clientId .
  			"&redirect_uri="  . $redirectUrl;
  		if(!$oauthServerName){
  			$oauthServerName = "sabia";
  		}
		echo '<div style="padding:10px;border:1px solid #ced9ea;border-radius:3px;-webkit-border-radius:3px;-moz-border-radius:3px;"><a href="'. $linkOauth .'"><img height="20px" alt="image of oatu server" src="'.$imgOauth.'" /> <strong>Login Via '.$oauthServerName.'</strong></div>';
		if ( isset( $_GET['oauth-error'] ) ) {
			echo '<div style="padding:10px;background-color:#FFDFDD;border:1px solid #ced9ea;border-radius:3px;-webkit-border-radius:3px;-moz-border-radius:3px;"><p style="line-height:1.6em;"><strong>Error!</strong> Error connecting. </p></div><br>';
		}
		else if ( isset( $_GET['domain-error'] ) ) {
			$username = $_GET['oauth-username'];
			echo '<div style="padding:10px;background-color:#FFDFDD;border:1px solid #ced9ea;border-radius:3px;-webkit-border-radius:3px;-moz-border-radius:3px;"><p style="line-height:1.6em;"><strong>Error!</strong> User ' . $username . ' is not authorised to login. </p></div><br>';
		}
		else if ( $autologinActive && !isset( $_GET['loggedout']) ){
			//straight through to autologin - no form rendered
			//$urlSessao = str_replace('https://login', 'https://api', $this->authHost);
			//$loginUrl = 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=' . $clientId . '&redirect_uri=' . $redirectUrl . '&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email&login_hint=@servian.com.au&access_type=offline';
			//wp_redirect($loginUrl);
			exit;
		}
	}

	/**
	 * logout method - called from wp_logout action
	 *
	 * @access public
	 * @return void
	 */
	public function launchkey_logout() {
		setcookie( 'oauth_id_token', '1', 0, COOKIEPATH, COOKIE_DOMAIN );
		setcookie( 'oauth_username', '1',  0, COOKIEPATH, COOKIE_DOMAIN );
	}

	/**
	 * oauth_init
	 *
	 * Invoked by admin_init action
	 *
	 */
	public function oauth_init() {
		$this->oauth_page_init();

		register_setting( 'oauth_option_group', 'array_key', array( $this, 'check_option' ) );

		add_settings_section( 'setting_section_id', 'API Settings', array(
				$this,
				'oauth_section_info'
			), 'oauth-setting-admin');

		add_settings_field( 'autologin_active', 'Activate auto-login',	array(
				$this,
				'create_autologin_active_field'
			),
			'oauth-setting-admin', 'setting_section_id');

		add_settings_field( 'url_base', 'URL do serviço',	array(
				$this,
				'create_url_base_field'
			),
			'oauth-setting-admin', 'setting_section_id');
		add_settings_field('img_field','Imagem do serviço oauth',array(
				$this,
				'create_img_field'
			),
			'oauth-setting-admin', 'setting_section_id');
		add_settings_field( 'client_id', 'Client ID',	array(
				$this,
				'create_client_id_field'
			),
			'oauth-setting-admin', 'setting_section_id');

		add_settings_field( 'client_secret', 'Secret Key', array(
				$this,
				'create_client_secret_field'
			),
			'oauth-setting-admin', 'setting_section_id');

		add_settings_field( 'redirect_url', 'Redirect URL', array(
				$this,
				'create_redirect_url_field'
			),
			'oauth-setting-admin', 'setting_section_id');

		add_settings_section( 'app_setting_section_id', 'Authentication Settings', array(
				$this,
				'oauth_app_settings_section_info'
			), 'oauth-setting-admin');

		add_settings_field( 'allowed_domains', 'Allowed domain', array(
				$this,
				'create_allowed_domains'
			),
			'oauth-setting-admin', 'app_setting_section_id');
	}

	/**
	 * oauth_plugin_page
	 *
	 * this function is invoked by admin_menu action
	 */
	public function oauth_plugin_page() {
		// Plugin Settings page and menu item
		add_options_page( 'OAuth', 'OAuth', 'manage_options', 'oauth-setting-admin',
		array( $this, 'create_admin_page' ) );
	}

	/**
	 *
	 */
	public function oauth_section_info() {
		echo '<p>Please use the site reference to setup OAuth 2.0 authentication.</p>' .
				'<p>Redirect URL field is automatically generated and is read-only. You must register it with OAuth to enable authentication.';
	}

	/**
	 *
	 */
	public function oauth_app_settings_section_info() {
		echo 'Limit domain names to allow authentication';
	}

}

$OAuth = new OAuth();

?>
