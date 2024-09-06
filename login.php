<h2>Please log in</h2>
<?php
if( isset( $_SESSION['error'] ) ) {
    echo '<b style="color: red">'.htmlspecialchars( $_SESSION['error'] ).'</b>';
    $_SESSION['error'] = null;
}
?>
<form method="post" action="">
    Username: <input name="username" type="text" /><br />
    Password: <input name="password" type="password" /><br />
    <button>Login</button>
</form>
