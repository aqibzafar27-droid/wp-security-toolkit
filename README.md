# WP Security Toolkit

A lightweight WordPress plugin that protects your login page from brute-force attacks by locking out an IP address after too many failed login attempts.

## Features

- **Brute-force protection** — tracks failed login attempts per IP address and locks out an IP after a configurable number of failures.
- **Configurable lockout settings** — set the maximum allowed login attempts and lockout duration (in minutes) from the WordPress admin panel.
- **Proxy / CDN aware IP detection** — correctly identifies the visitor's real IP address even when the site is behind a proxy or CDN like Cloudflare (only enabled when explicitly confirmed by the admin, to prevent IP spoofing).
- **Admin dashboard** — a simple dashboard showing current protection status, failed login attempts, and active settings.
- **Automatic reset** — failed attempt counters reset automatically after a successful login.

## How It Works

The plugin uses WordPress [transients](https://developer.wordpress.org/apis/transients/) to store failed login attempts per IP address, keyed by an MD5 hash of the IP. When a user exceeds the configured maximum number of failed attempts, further login attempts from that IP are blocked until the lockout period expires.

## Installation

1. Download or clone this repository.
2. Upload the `wp-security-toolkit` folder to your `/wp-content/plugins/` directory.
3. Activate the plugin through the **Plugins** menu in WordPress.
4. Go to **Security Toolkit → Settings** in the admin sidebar to configure:
   - Maximum login attempts
   - Lockout duration (in minutes)
   - Whether your site is behind a proxy/CDN

## Settings

| Setting | Description | Default |
|---|---|---|
| Maximum Login Attempts | Number of failed attempts before lockout | 5 |
| Lockout Duration | How long (in minutes) an IP stays locked out | 15 |
| Behind a Proxy | Enable only if your site uses Cloudflare or a similar proxy/CDN | Off |

## Security Notes

- The plugin only trusts the `X-Forwarded-For` header for IP detection when the "Behind a Proxy" setting is explicitly enabled by the admin — this prevents attackers from spoofing their IP to bypass lockouts on sites that aren't actually behind a proxy.
- All user-facing output is escaped using WordPress core functions (`esc_attr`, `esc_html`) to prevent XSS.
- Settings are registered and sanitized using the WordPress Settings API (`register_setting`) with proper sanitize callbacks.

## Author

Built by [Aqib Zafar](https://github.com/aqibzafar27-droid)
