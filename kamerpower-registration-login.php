<?php
/*
Plugin Name: Kamerpower WP Custom Login & Registration Form
Plugin URI: https://kamerpower.com/
Description: A shortcode based Lightweight WordPress plugin that creates custom login and registration forms that can be implemented using a shortcode.
Version: 1.0
Author: Alondi Commanda
Author URI: https://kamerpower.com/
*/




/* ------------------------------------------------------------------------- */
// user registration login form
/* ------------------------------------------------------------------------- */
function kamerpower_registration_form() {
 
	// only show the registration form to non-logged-in members
	if(!is_user_logged_in()) {
 
		global $kamerpower_load_css;
 
		// set this to true so the CSS is loaded
		$kamerpower_load_css = true;
 
		// check to make sure user registration is enabled
		$registration_enabled = get_option('users_can_register');
 
		// only show the registration form if allowed
		if($registration_enabled) {
			$output = kamerpower_registration_form_fields();
		} else {
			$output = __('User registration is not enabled');
		}
		return $output;
	}
}
add_shortcode('register_form', 'kamerpower_registration_form');

/* ------------------------------------------------------------------------- */
// user login form
/* ------------------------------------------------------------------------- */
function kamerpower_login_form() {
 
	if(!is_user_logged_in()) {
 
		global $kamerpower_load_css;
 
		// set this to true so the CSS is loaded
		$kamerpower_load_css = true;
 
		$output = kamerpower_login_form_fields();
	} else {
		// could show some logged in user info here
		// $output = 'user info here';
		echo 'Already Logged-In <a id="kamerpower_logout" href="'. wp_logout_url( get_permalink() ) .'" title="Logout">Logout</a>';
		
	}
	return $output;
}
add_shortcode('login_form', 'kamerpower_login_form');

/* ------------------------------------------------------------------------- */
// registration form fields
/* ------------------------------------------------------------------------- */
function kamerpower_registration_form_fields() {
 
	ob_start(); ?>	
		<h3 class="kamerpower_header"><?php _e('Register New Account'); ?></h3>
 
		<?php 
		// show any error messages after form submission
		kamerpower_show_error_messages(); ?>
 
		<form id="kamerpower_registration_form" class="kamerpower_form" action="" method="POST">
			<fieldset>
				<p>
					<label for="kamerpower_user_Login"><?php _e('Username'); ?></label>
					<input name="kamerpower_user_login" id="kamerpower_user_login" class="required" type="text"/>
				</p>
				<p>
					<label for="kamerpower_user_email"><?php _e('Email'); ?></label>
					<input name="kamerpower_user_email" id="kamerpower_user_email" class="required" type="email"/>
				</p>
				<p>
					<label for="kamerpower_user_first"><?php _e('First Name'); ?></label>
					<input name="kamerpower_user_first" id="kamerpower_user_first" class="required" type="text"/>
				</p>
				<p>
					<label for="kamerpower_user_last"><?php _e('Last Name'); ?></label>
					<input name="kamerpower_user_last" id="kamerpower_user_last" class="required" type="text"/>
				</p>
				<p>
					<label for="password"><?php _e('Password'); ?></label>
					<input name="kamerpower_user_pass" id="password" class="required" type="password"/>
				</p>
				<p>
					<label for="password_again"><?php _e('Password Again'); ?></label>
					<input name="kamerpower_user_pass_confirm" id="password_again" class="required" type="password"/>
				</p>
				<p>
					<input type="hidden" name="kamerpower_register_nonce" value="<?php echo wp_create_nonce('kamerpower-register-nonce'); ?>"/>
					<input type="submit" value="<?php _e('Register Your Account'); ?>"/>
				</p>
			</fieldset>
		</form>
	<?php
	return ob_get_clean();
}

/* ------------------------------------------------------------------------- */
// login form fields
/* ------------------------------------------------------------------------- */
function kamerpower_login_form_fields() {
 
	ob_start(); ?>
		<h3 class="kamerpower_header"><?php _e('Login'); ?></h3>
 
		<?php
		// show any error messages after form submission
		kamerpower_show_error_messages(); ?>
 
		<form id="kamerpower_login_form"  class="kamerpower_form" action="" method="post">
			<fieldset>
				<p>
					<label for="kamerpower_user_Login">Username</label>
					<input name="kamerpower_user_login" id="kamerpower_user_login" class="required" type="text"/>
				</p>
				<p>
					<label for="kamerpower_user_pass">Password</label>
					<input name="kamerpower_user_pass" id="kamerpower_user_pass" class="required" type="password"/>
				</p>
				<p>
					<input type="hidden" name="kamerpower_login_nonce" value="<?php echo wp_create_nonce('kamerpower-login-nonce'); ?>"/>
					<input id="kamerpower_login_submit" type="submit" value="Login"/>
				</p>
			</fieldset>
		</form>
	<?php
	return ob_get_clean();
}

/* ------------------------------------------------------------------------- */
// Logs a member in after submitting a form
/* ------------------------------------------------------------------------- */
function kamerpower_login_member() {
 
	if(isset($_POST['kamerpower_user_login']) && wp_verify_nonce($_POST['kamerpower_login_nonce'], 'kamerpower-login-nonce')) {
 
		// this returns the user ID and other info from the user name
		$user = get_userdatabylogin($_POST['kamerpower_user_login']);
 
		if(!$user) {
			// if the user name doesn't exist
			kamerpower_errors()->add('empty_username', __('Invalid inputs'));
		}
 
		if(!isset($_POST['kamerpower_user_pass']) || $_POST['kamerpower_user_pass'] == '') {
			// if no password was entered
			kamerpower_errors()->add('empty_password', __('Please enter a password'));
		}
 
		// check the user's login with their password
		if(!wp_check_password($_POST['kamerpower_user_pass'], $user->user_pass, $user->ID)) {
			// if the password is incorrect for the specified user
			kamerpower_errors()->add('empty_password', __('Incorrect inputs'));
		}
 
		// retrieve all error messages
		$errors = kamerpower_errors()->get_error_messages();
 
		// only log the user in if there are no errors
		if(empty($errors)) {
 
			wp_setcookie($_POST['kamerpower_user_login'], $_POST['kamerpower_user_pass'], true);
			wp_set_current_user($user->ID, $_POST['kamerpower_user_login']);	
			do_action('wp_login', $_POST['kamerpower_user_login']);
 
			wp_redirect(home_url("/")); exit;
		}
	}
}
add_action('init', 'kamerpower_login_member');

/* ------------------------------------------------------------------------- */
// Register a new user
/* ------------------------------------------------------------------------- */
function kamerpower_add_new_member() {
  	if (isset( $_POST["kamerpower_user_login"] ) && wp_verify_nonce($_POST['kamerpower_register_nonce'], 'kamerpower-register-nonce')) {
		$user_login		= $_POST["kamerpower_user_login"];	
		$user_email		= $_POST["kamerpower_user_email"];
		$user_first 	= $_POST["kamerpower_user_first"];
		$user_last	 	= $_POST["kamerpower_user_last"];
		$user_pass		= $_POST["kamerpower_user_pass"];
		$pass_confirm 	= $_POST["kamerpower_user_pass_confirm"];
 
		// this is required for username checks
		require_once(ABSPATH . WPINC . '/registration.php');
 
		if(username_exists($user_login)) {
			// Username already registered
			kamerpower_errors()->add('username_unavailable', __('Username already taken'));
		}
		if(!validate_username($user_login)) {
			// invalid username
			kamerpower_errors()->add('username_invalid', __('Invalid username'));
		}
		if($user_login == '') {
			// empty username
			kamerpower_errors()->add('username_empty', __('Please enter a username'));
		}

		
		
		if(!is_email($user_email)) {
			//invalid email
			kamerpower_errors()->add('email_invalid', __('Invalid email'));
		}
		if(email_exists($user_email)) {
			//Email address already registered
			kamerpower_errors()->add('email_used', __('Email already registered'));
		}
		if($user_pass == '') {
			// passwords do not match
			kamerpower_errors()->add('password_empty', __('Please enter a password'));
		}
		if($user_pass != $pass_confirm) {
			// passwords do not match
			kamerpower_errors()->add('password_mismatch', __('Passwords do not match'));
		}
 
		$errors = kamerpower_errors()->get_error_messages();
 
		// only create the user in if there are no errors
		if(empty($errors)) {
 
			$new_user_id = wp_insert_user(array(
					'user_login'		=> $user_login,
					'user_pass'	 		=> $user_pass,
					'user_email'		=> $user_email,
					'first_name'		=> $user_first,
					'last_name'			=> $user_last,
					'user_registered'	=> date('Y-m-d H:i:s'),
					'role'				=> 'subscriber'
				)
			);
			if($new_user_id) {
				// send an email to the admin alerting them of the registration
				wp_new_user_notification($new_user_id);
 
				// log the new user in
				wp_setcookie($user_login, $user_pass, true);
				wp_set_current_user($new_user_id, $user_login);	
				do_action('wp_login', $user_login);
 
				// send the newly created user to the home page after logging them in
				wp_redirect(home_url("/")); exit;
			}
 
		}
 
	}
}
add_action('init', 'kamerpower_add_new_member');

/* ------------------------------------------------------------------------- */
// used for tracking error messages
/* ------------------------------------------------------------------------- */
function kamerpower_errors(){
    static $wp_error; // Will hold global variable safely
    return isset($wp_error) ? $wp_error : ($wp_error = new WP_Error(null, null, null));
}

/* ------------------------------------------------------------------------- */
// Displays error messages from form submissions
/* ------------------------------------------------------------------------- */
function kamerpower_show_error_messages() {
	if($codes = kamerpower_errors()->get_error_codes()) {
		echo '<div class="kamerpower_errors">';
		    // Loop error codes and display errors
		   foreach($codes as $code){
		        $message = kamerpower_errors()->get_error_message($code);
		        echo '<span class="error"><strong>' . __('Error') . '</strong>: ' . $message . '</span><br/>';
		    }
		echo '</div>';
	}	
}

/* ------------------------------------------------------------------------- */
// register our form css
/* ------------------------------------------------------------------------- */
function kamerpower_register_css() {
	wp_register_style('kamerpower-form-css', plugin_dir_url( __FILE__ ) . '/css/forms.css');
}
add_action('init', 'kamerpower_register_css');

/* ------------------------------------------------------------------------- */
// load our form css
/* ------------------------------------------------------------------------- */
function kamerpower_print_css() {
	global $pippin_load_css;
 
	// this variable is set to TRUE if the short code is used on a page/post
	if ( ! $kamerpower_load_css )
		return; // this means that neither short code is present, so we get out of here
 
	wp_print_styles('kamerpower-form-css');
}
add_action('wp_footer', 'kamerpower_print_css');

/* ------------------------------------------------------------------------- */
// Redirect to custom registration and login form
/* ------------------------------------------------------------------------- */
// Hook the appropriate WordPress action
add_action('init', 'prevent_wp_login');

function prevent_wp_login() {
    // WP tracks the current page - global the variable to access it
    global $pagenow;
    // Check if a $_GET['action'] is set, and if so, load it into $action variable
    $action = (isset($_GET['action'])) ? $_GET['action'] : '';
    // Check if we're on the login page, and ensure the action is not 'logout'
    if( $pagenow == 'wp-login.php' && ( ! $action || ( $action && ! in_array($action, array('logout', 'lostpassword', 'rp'))))) {
        // Load the home page url
        $page = site_url("/login/");
        // Redirect to the home page
        wp_redirect($page);
        // Stop execution to prevent the page loading for any reason
        exit();
    }
}

/* ------------------------------------------------------------------------- */
// Disable Admin Bar for All Users Except for Administrators
/* ------------------------------------------------------------------------- */
add_action('after_setup_theme', 'remove_admin_bar');
function remove_admin_bar() {
if (!current_user_can('administrator') && !is_admin()) {
  show_admin_bar(false);
}
}


