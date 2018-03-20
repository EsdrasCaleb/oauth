=== Plugin Name ===
Contributors: EsdrasCaleb
Tags: security, login, oauth2, oauth,authentication, autologin
Requires at least: 3.0.1
Tested up to: 4.9
Stable tag: 1.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Provides automatic authentication against Google OAuth2 API.

Made with Google oauth of egor.kolesnikov.at.servian

https://br.wordpress.org/plugins/google-oauth/

== Description ==

This plugin allows to authenticate users against Google Apps OAuth2 API. Once installed
and properly configured, it will start redirecting to Google consent page. After consent
has been obtained, user is automatically created in WordPress database.


== Installation ==

- Upload `google-oauth.php` to the `/wp-content/plugins/` directory

- Activate the plugin through the 'Plugins' menu in WordPress

- Log in to Google App Cloud Console with administrative privileges and setup the app for
OAuth2 authentication (https://developers.google.com/accounts/docs/OAuth2Login).

It will require you to provide redirect URLs - http URL is available at the plugin settings page,
and you’ll need another one for HTTPS (same URL, just starting with https://).

After all that is done, Google will provide Client ID and Client Secret values you’ll
need to copy-paste into respective fields on the plugin settings page and set the Allowed Domain.


== Frequently Asked Questions ==

Nothing has been asked yet.


== Changelog ==

= 1.0 =
First version

