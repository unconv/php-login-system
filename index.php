<?php
require_once( "Auth.php" );

// Start the PHP session
session_start();

// Connect to the database
$db = new PDO(
    dsn: "mysql:host=localhost;dbname=cardi",
    username: "cardi",
    password: "cardi",
);

// Set database error mode
$db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

// Initialize the Auth class
$auth = new Auth( $db );

// Handle login submit
if( isset( $_POST['username'] ) && isset( $_POST['password'] ) ) {
    $userid = $auth->authenticate( $_POST['username'], $_POST['password'] );

    if( $userid ) {
        // If username and password were correct,
        // log user in and redirect to front page
        $auth->log_user_in( $userid );
        header( "Location: /" );
        exit;
    } else {
        // If username and password were incorrect,
        // add flash error and redirect to front page
        $_SESSION["error"] = "Wrong username or password!";
        header( "Location: /" );
        exit;
    }
}

// Handle logout submit
if( isset( $_POST['logout'] ) ) {
    $auth->log_user_out();
    header( "Location: /" );
    exit;
}

// Check logged in user
$userid = $auth->logged_in_user();

// Show the login form if no user is logged in
if( ! $userid ) {
    require_once( "login.php" );
    exit;
}

// EVERYTHING BELOW THIS LINE WILL BE VISIBLE
// TO LOGGED IN USERS ONLY

if( $auth->get_user_role( $userid ) === 1 ) {
    // This is visible for user with role 1
    echo "You are an administrator!\n";
} else {
    // This is visible to other users
    echo "You are a regular user\n";
}

// Logout button form
?><form method="post" action="">
    <input type="hidden" name="logout" value="true" />
    <button>Logout</button>
</form>
