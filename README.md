rLdapAdmin
==========

Minimalistic PHP-based LDAP administration & user panel

Configuration
-------------

Create file .config.php with next content:
```
<?php
// Set parameters
$ldap_server   = 'ldap://127.0.0.1/';
$ldap_domain   = 'dc=example,dc=net';
$ldap_userbase = 'ou=Users,'.$ldap_domain;
```
