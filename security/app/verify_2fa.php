<?php
// セッション設定
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 1);
session_start();

// Google Authenticator クラスの読み込み
require 'libs/GoogleAuthenticator.php';

// データベースに接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_errno) {
  echo "データベースの接続に失敗しました: " . $mysqli->connect_error;
  exit();
}

// セッションのセキュリティチェック
function validateSession()
{
  if (!isset($_SESSION['created_at'])) {
    $_SESSION['created_at'] = time();
  } else if (time() - $_SESSION['created_at'] > SESSION_LIFETIME) {
    session_destroy();
    return false;
  }

  if (!isset($_SESSION['user_ip'])) {
    $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
  } else if ($_SESSION['user_ip'] !== $_SERVER['REMOTE_ADDR']) {
    session_destroy();
    return false;
  }

  if (!isset($_SESSION['user_agent'])) {
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
  } else if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    session_destroy();
    return false;
  }

  // セッションIDの再生成（セッションハイジャック対策）
  if (!isset($_SESSION['last_regeneration'])) {
    $_SESSION['last_regeneration'] = time();
  } else if (time() - $_SESSION['last_regeneration'] > 300) {
    session_regenerate_id(true);
    $_SESSION['last_regeneration'] = time();
  }

  return true;
}

// ログイン状態の確認
if (!isset($_SESSION["user_id"])) {
  header("Location: /login/");
  exit();
}

// セッション状態の確認
$user_id = $_SESSION["user_id"];
$session_id = session_id();
$stmt = $mysqli->prepare("SELECT last_login_at FROM users_session WHERE session_id = ? AND username = (SELECT username FROM users WHERE id = ?)");
if ($stmt === false) {
  die('Prepare statement failed: ' . $mysqli->error);
}
$stmt->bind_param("si", $session_id, $user_id);
$stmt->execute();
$stmt->bind_result($last_login_at);
$stmt->fetch();
$stmt->close();
if ($last_login_at) {
  $current_time = new DateTime();
  $last_login_time = new DateTime($last_login_at);
  $interval = $current_time->diff($last_login_time);
  if ($interval->days >= 3) {
    session_unset();
    session_destroy();
    header("Location: /login/");
    exit();
  } else {
    $stmt = $mysqli->prepare("UPDATE users_session SET last_login_at = NOW() WHERE session_id = ?");
    if ($stmt === false) {
      die('Prepare statement failed: ' . $mysqli->error);
    }
    $stmt->bind_param("s", $session_id);
    $stmt->execute();
    $stmt->close();
  }
} else {
  session_unset();
  session_destroy();
  header("Location: /login/");
  exit();
}

// Recovery codeを生成する関数
function generateRecoveryCodes($count = 10)
{
  $recovery_codes = [];
  for ($i = 0; $i < $count; $i++) {
    $recovery_code = strtoupper(bin2hex(random_bytes(5)));
    $recovery_code = substr($recovery_code, 0, 5) . '-' . substr($recovery_code, 5, 5);
    $recovery_codes[] = $recovery_code;
  }
  return $recovery_codes;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $code = implode('', array_map('trim', $_POST));

  // ユーザー情報を取得
  $stmt = $mysqli->prepare("SELECT username FROM users WHERE id = ?");
  if ($stmt === false) {
    die('Prepare statement failed: ' . $mysqli->error);
  }
  $stmt->bind_param("i", $user_id);
  $stmt->execute();
  $stmt->bind_result($username);
  $stmt->fetch();
  $stmt->close();

  // Secretを取得
  $stmt = $mysqli->prepare("SELECT two_factor_secret FROM users_factor WHERE username = ?");
  if ($stmt === false) {
    die('Prepare statement failed: ' . $mysqli->error);
  }
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $stmt->bind_result($secret);
  $stmt->fetch();
  $stmt->close();

  if (empty($secret)) {
    header("Location: ../");
    exit();
  }

  // 2FAコードの検証
  $g = new PHPGangsta_GoogleAuthenticator();
  if ($g->verifyCode($secret, $code)) {
    // リカバリーコードを生成
    $recovery_codes = generateRecoveryCodes();

    // Recoveryコードを保存
    $stmt = $mysqli->prepare("UPDATE users_factor SET recovery_codes = ? WHERE username = ?");
    if ($stmt === false) {
      header("Location: ./?error=2FAの有効化に失敗しました。");
      exit();
    }
    $recovery_codes_json = json_encode($recovery_codes);
    $stmt->bind_param("ss", $recovery_codes_json, $username);
    if (!$stmt->execute()) {
      header("Location: ./?error=2FAの有効化に失敗しました。");
      exit();
    }
    $stmt->close();

    // 2FAを有効化
    $stmt = $mysqli->prepare("UPDATE users_factor SET two_factor_enabled = 1 WHERE username = ?");
    if ($stmt === false) {
      header("Location: ./?error=2FAの有効化に失敗しました。");
      exit();
    }
    $stmt->bind_param("s", $username);
    if (!$stmt->execute()) {
      header("Location: ./?error=2FAの有効化に失敗しました。");
      exit();
    }
    $stmt->close();

    header("Location: ../?success=1");
    exit();
  } else {
    header("Location: ./?error=無効なセキュリティコードです。");
    exit();
  }
}

$mysqli->close();
