<?php
// セッション設定
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 3600);
ini_set('session.use_strict_mode', 1);
ini_set('session.sid_length', 48);
ini_set('session.sid_bits_per_character', 6);

// セキュリティ定数
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 1800);
define('CSRF_TOKEN_EXPIRE', 3600);
define('SESSION_LIFETIME', 3600);

// ヘッダー
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-only");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// セッション開始
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// データベースに接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_errno) {
  die("データベースの接続に失敗しました: " . $mysqli->connect_error);
}

if (isset($_GET['token'])) {
    $token = htmlspecialchars($_GET['token'], ENT_QUOTES, 'UTF-8');

    $stmt = $mysqli->prepare("SELECT user_id, type, email, expires_at FROM users_verification WHERE token = ? AND is_verified = FALSE");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $stmt->bind_result($user_id, $type, $email, $expires_at);
    $stmt->fetch();
    $stmt->close();

    if ($user_id && new DateTime() < new DateTime($expires_at)) {
        $stmt = $mysqli->prepare("UPDATE users_verification SET is_verified = TRUE WHERE token = ?");
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $stmt->close();

        $stmt = $mysqli->prepare("UPDATE users SET email = ? WHERE id = ?");
        $stmt->bind_param("si", $email, $user_id);
        $stmt->execute();
        $stmt->close();

        header("Location: success/");
        exit();
    } else {
        header("Location: failed/");
        exit();
    }
} else {
    header("Location: failed/");
    exit();
}

$mysqli->close();
