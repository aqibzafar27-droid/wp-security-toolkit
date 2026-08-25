<?php
/*
Plugin Name: WP Security Toolkit
Description: A lightweight WordPress brute-force protection plugin.
Version: 1.1.0
Author: Aqib Zafar
*/


/*
 * Get the visitor's IP address.
 *
 * If the site is behind a proxy (like Cloudflare), REMOTE_ADDR
 * would return the proxy's IP instead of the visitor's real IP.
 * In that case, we check the X-Forwarded-For header instead —
 * but only if the admin has confirmed the site uses a proxy,
 * since this header can otherwise be faked by an attacker.
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

function wps_get_ip_address() {

    $behind_proxy = get_option( 'wps_behind_proxy', false );

    if ( $behind_proxy && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {

        // Header can contain multiple IPs like "client, proxy1, proxy2".
        // The first one is the original visitor's IP.
        $forwarded_ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );

        $candidate_ip = trim( $forwarded_ips[0] );

        // Only trust it if it's actually a valid IP address.
        if ( filter_var( $candidate_ip, FILTER_VALIDATE_IP ) ) {

            return $candidate_ip;
        }
    }

    return $_SERVER['REMOTE_ADDR'];
}


/*
 * Create a unique key for each IP address.
 */
function wps_get_attempt_key() {

    $ip_address = wps_get_ip_address();

    return 'wps_failed_' . md5( $ip_address );
}


/*
 * Get the configured maximum login attempts (default 5).
 */
function wps_get_max_attempts() {

    return (int) get_option( 'wps_max_attempts', 5 );
}


/*
 * Get the configured lockout duration in minutes (default 15).
 */
function wps_get_lockout_minutes() {

    return (int) get_option( 'wps_lockout_minutes', 15 );
}


/*
 * Record a failed login attempt.
 */
function wps_login_failed( $username ) {

    $attempt_key = wps_get_attempt_key();

    $attempts = get_transient( $attempt_key );

    if ( false === $attempts ) {

        $attempts = 0;
    }

    $attempts++;

    $lockout_minutes = wps_get_lockout_minutes();

    set_transient( $attempt_key, $attempts, $lockout_minutes * MINUTE_IN_SECONDS );
}


/*
 * Check whether the IP address is locked.
 */
function wps_check_login_lockout( $user, $username, $password ) {

    $attempt_key = wps_get_attempt_key();

    $attempts = get_transient( $attempt_key );

    $max_attempts = wps_get_max_attempts();

    if ( false !== $attempts && $attempts >= $max_attempts ) {

        $lockout_minutes = wps_get_lockout_minutes();

        return new WP_Error(
            'wps_login_locked',
            sprintf(
                'Too many failed login attempts. Please try again in %d minutes.',
                $lockout_minutes
            )
        );
    }

    return $user;
}


/*
 * Reset failed attempts after successful login.
 */
function wps_reset_login_attempts( $user_login, $user ) {

    $attempt_key = wps_get_attempt_key();

    delete_transient( $attempt_key );
}


/*
 * WordPress hooks.
 */
add_action( 'wp_login_failed', 'wps_login_failed' );

add_filter( 'authenticate', 'wps_check_login_lockout', 30, 3 );

add_action( 'wp_login', 'wps_reset_login_attempts', 10, 2 );

add_action ('admin_menu' , 'wps_admin_menu' );

function wps_admin_menu (){
    add_menu_page (
        'wp_security_toolkit',
        'security-toolkit',
        'manage_options',
        'wp-security-toolkit',
        'wps_security_dashboard',
        'dashicons-shield',
        80
        );

    add_submenu_page(
        'wp-security-toolkit',
        'securiy_settings',
        'settings',
        'manage_options',
        'wps_security_settings',
        'wps_settings_page'
    );
}
function wps_settings_page() {

    echo '<div class="wrap">';
    echo '<h1>Security Settings</h1>';

    echo '<form method="post" action="options.php">';

    settings_fields('wps_settings');

    echo '<table class="form-table">';

    echo '<tr>';
    echo '<th>Maximum Login Attempts</th>';
    echo '<td>';

    echo '<input type="number" name="wps_max_attempts" value="' . esc_attr(get_option('wps_max_attempts', 5)) . '" min="1">';

    echo '</td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th>Lockout Duration (minutes)</th>';
    echo '<td>';

    echo '<input type="number" name="wps_lockout_minutes" value="' . esc_attr(get_option('wps_lockout_minutes', 15)) . '" min="1">';

    echo '</td>';
    echo '</tr>';

    echo '<tr>';
    echo '<th>Site is behind a proxy (e.g. Cloudflare)</th>';
    echo '<td>';

    echo '<label><input type="checkbox" name="wps_behind_proxy" value="1" ' . checked( 1, get_option( 'wps_behind_proxy', 0 ), false ) . '> Enable if your site uses Cloudflare or a similar proxy/CDN</label>';
    echo '<p class="description">Only enable this if you are sure — enabling it on a site without a proxy lets attackers fake their IP and bypass lockouts.</p>';

    echo '</td>';
    echo '</tr>';

    echo '</table>';

    submit_button();

    echo '</form>';

    echo '</div>';
}

function wps_security_dashboard (){
    echo '<div class= "wrap">';
    echo '<h1> security Toolkit </h1>';
    echo '<p> protect your website from brute force attack </p>';
    echo '<h2> protection status</h2>';
    $failed_attempts = wps_get_failed_attempts();
    $max_attempts = wps_get_max_attempts();
    $lockout_minutes = wps_get_lockout_minutes();
    echo '<div class="security-stats">';

echo '<div class="stat-card">';
echo '<h3>Failed Login Attempts</h3>';
echo '<strong>' . $failed_attempts . '</strong>';
echo '</div>';

echo '<div class="stat-card">';
echo '<h3>Maximum Login Attempts</h3>';
echo '<strong>' . $max_attempts . '</strong>';
echo '</div>';

echo '<div class="stat-card">';
echo '<h3>Lockout Duration</h3>';
echo '<strong>' . $lockout_minutes . ' Minutes</strong>';
echo '</div>';

echo '</div>';
   echo '<div class="security-card">';
echo '<span class="status-dot"></span>';
echo '<strong>Protection is Active</strong>';
echo '</div>';
    echo '</div>';

}
function wps_admin_styles() {
    wp_enqueue_style(
         'wps-admin-style'
         , plugin_dir_url( __FILE__).'admin.css'
         );
}
add_action( 'admin_enqueue_scripts', 'wps_admin_styles' );


function wps_get_failed_attempts(){
    $attempt_key=wps_get_attempt_key();
    $attempts = get_transient($attempt_key);

    return false ===$attempts ? 0:$attempts;
    }
function wps_register_setting(){
 register_setting(
    'wps_settings',
    'wps_max_attempts',
    array(
        'type'              => 'integer',
        'sanitize_callback' => 'absint',
        'default'           => 5,
    )
 );

 register_setting(
    'wps_settings',
    'wps_lockout_minutes',
    array(
        'type'              => 'integer',
        'sanitize_callback' => 'absint',
        'default'           => 15,
    )
 );

 register_setting(
    'wps_settings',
    'wps_behind_proxy',
    array(
        'type'              => 'boolean',
        'sanitize_callback' => 'rest_sanitize_boolean',
        'default'           => false,
    )
 );
}
add_action ('admin_init', 'wps_register_setting');