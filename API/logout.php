<?php
session_start();

// セッション変数をクリア
$_SESSION = array();

// セッションを破棄
session_destroy();

// クッキーも破棄
if (isset($_COOKIE['user_token'])) {
    setcookie('user_token', '', time() - 3600, '/');
}
header('Location: /login/');
exit();
?>
