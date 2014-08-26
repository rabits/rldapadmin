<?php
/**
 * rLdapAdmin LDAP manager
 *
 * @copyright (C) 2014 Rabit <home@rabits.org>
 * @license http://www.gnu.org/copyleft/gpl.html GNU/GPL
 * @link http://www.rabits.org
 */

include('.config.php');

/**
 * function ldap_escape
 * @author Chris Wright
 * @version 2.0
 * @param string $subject The subject string
 * @param bool $dn Treat subject as a DN if TRUE
 * @param string|array $ignore Set of characters to leave untouched
 * @return string The escaped string
 */
function ldap_escape( $subject, $dn = false, $ignore = NULL ) {

    // The base array of characters to escape
    // Flip to keys for easy use of unset()
    $search = array_flip($dn ? array('\\', ',', '=', '+', '<', '>', ';', '"', '#') : array('\\', '*', '(', ')', "\x00"));

    // Process characters to ignore
    if (is_array($ignore)) {
        $ignore = array_values($ignore);
    }
    for ($char = 0; isset($ignore[$char]); $char++) {
        unset($search[$ignore[$char]]);
    }

    // Flip $search back to values and build $replace array
    $search = array_keys($search); 
    $replace = array();
    foreach ($search as $char) {
        $replace[] = sprintf('\\%02x', ord($char));
    }

    // Do the main replacement
    $result = str_replace($search, $replace, $subject);

    // Encode leading/trailing spaces in DN values
    if ($dn) {
        if ($result[0] == ' ') {
            $result = '\\20'.substr($result, 1);
        }
        if ($result[strlen($result) - 1] == ' ') {
            $result = substr($result, 0, -1).'\\20';
        }
    }

    return $result;
}

function ldap_exist($ldapconn, $base, $filter) {
    return ldap_count_entries($ldapconn, ldap_search($ldapconn, $base, $filter)) > 0;
}

function forbidden() {
    error_log("forbidden: " . $_SERVER['REMOTE_ADDR'] . ', user: ' . ldap_escape($_SERVER['PHP_AUTH_USER'], true));
    sleep(rand(0, 3));
    session_destroy();
    Header("HTTP/1.0 403 Forbidden");
    die('Unauthorized.');
}

// Request LDAP reader/writer user
if( isset($_GET['logout']) || empty($_SERVER['PHP_AUTH_USER']) ) {
    Header('WWW-Authenticate: Basic realm="LDAP Credentials"');
    Header('HTTP/1.0 401 Unauthorized');
    die();
}

// Set parameters
// Placed in .config.php
//$ldap_server   = 'ldap://127.0.0.1/';
//$ldap_domain   = 'dc=example,dc=net';
//$ldap_userbase = 'ou=Users,'.$ldap_domain;
$ldap_user     = $_SERVER['PHP_AUTH_USER'] === 'admin'
    ? 'cn=admin,' . $ldap_domain
    : 'cn='.ldap_escape($_SERVER['PHP_AUTH_USER'], true).','.$ldap_userbase;
$ldap_pass     = $_SERVER['PHP_AUTH_PW'];

// Connect to ldap server
$ldapconn = ldap_connect($ldap_server) or die("Could not connect to LDAP server");
ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3) ;

$ldapbind = @ldap_bind($ldapconn, $ldap_user, $ldap_pass) || forbidden();

// Check that userbase exists
if( ! ldap_exist($ldapconn, $ldap_domain, "ou=Users") ) {
    // Creating organisation unit
    ldap_add($ldapconn, $ldap_userbase, array(
        'ou' => 'Users',
        'objectClass' => 'organizationalUnit',
    ));
    print('<p>Creation Users unit: '.htmlspecialchars(ldap_error($ldapconn))."</p>\n");
}
?>
<!DOCTYPE html>
<html>
    <head>
        <title>LDAP Manager</title>
        <meta http-equiv="Content-type" content="text/html;charset=UTF-8"/>
        <link rel="shortcut icon" type="image/png" href="/favicon.ico" />
        <link rel="icon" type="image/png" href="/favicon.png" />
    </head>
    <body>
        <div id="container">
            <h1>Add/Modify LDAP User</h1>
<?php
// Add/modify/delete user
if( isset($_POST['login']) ) {
    $data['cn'] = $_POST['login'];
    $data['userPassword'] = $_POST['password'];
    $data['givenName'] = $_POST['givenname'];
    $data['sn'] = $_POST['surname'];
    $data['objectClass'] = 'inetOrgPerson';

    if( !empty($data['userPassword'].$data['givenName'].$data['sn']) ) {
        if( ! ldap_exist($ldapconn, $ldap_userbase, "cn=".ldap_escape($data['cn'], true)) ) {
            // Add user
            ldap_add($ldapconn, 'cn='.ldap_escape($data['cn'], true).','.$ldap_userbase, $data);
            print('<p>Adding user ');
        } else {
            // Modify user
            ldap_modify($ldapconn, 'cn='.ldap_escape($data['cn'], true).','.$ldap_userbase, $data);
            print('<p>Modifed user ');
        }
    } else {
        // Remove user
        ldap_delete($ldapconn, 'cn='.ldap_escape($data['cn'], true).','.$ldap_userbase);
        print('<p>Removing user ');
    }
    print(htmlspecialchars($data['cn']).': '.htmlspecialchars(ldap_error($ldapconn))."</p>\n");
}
?>
            <form action="/" method="post">
                <table>
                    <tr><td>Login:</td><td><input type="text" name="login"></td></tr>
                    <tr><td>Password:</td><td><input type="password" name="password"></td></tr>
                    <tr><td>Given Name:</td><td><input type="text" name="givenname"></td></tr>
                    <tr><td>Surname:</td><td><input type="text" name="surname"></td></tr>
                </table>
                <input type="submit" value="Send"> <input type="reset" value="Reset">
            </form>
            <h1>LDAP Users List</h1>
            <table border="1">
                    <tr><td><b>Login</b></td><td><b>Name</b></td></tr>
<?php
// Print table of found users
$list = ldap_get_entries($ldapconn, ldap_search($ldapconn, $ldap_userbase, "cn=*", array("cn", "givenname", "sn")));
for( $i = 0; $i < $list['count']; $i++ ) {
    // Print users
    print('<tr><td>'.htmlspecialchars($list[$i]['cn'][0]).'</td><td>'.htmlspecialchars($list[$i]['givenname'][0]).' '.htmlspecialchars($list[$i]['sn'][0])."</td></tr>\n");
}
print("</table><p>Request operation: ".htmlspecialchars(ldap_error($ldapconn))."</p>\n");

// Close ldap connection
ldap_close($ldapconn);
?>
        </div>
    </body>
</html>
