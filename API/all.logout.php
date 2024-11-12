<?php
session_start();

// データベース接続
$mysqli = new mysqli("", "", "", "");

// データベース接続のエラーハンドリング
if ($mysqli->connect_error) {
  die('データベースの接続に失敗しました: ' . $mysqli->connect_error);
  exit();
}

// セッション固定化攻撃を防止するため、セッションIDを再生成
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

// ユーザーがログインしていない場合はログインページにリダイレクト
if (!isset($_SESSION["user_id"])) {
    header("Location: /login.php");
    exit();
}

// ユーザーIDの取得
$userId = $_SESSION["user_id"];

// ユーザー名を取得
$query = "SELECT username, notifications FROM users WHERE id = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("i", $userId);
$stmt->execute();
$stmt->bind_result($username, $notifications);
$stmt->fetch();
$stmt->close();


// ユーザーの全セッションを削除
$stmt = $mysqli->prepare("DELETE FROM users_session WHERE username = ?");
if ($stmt) {
    $stmt->bind_param("i", $username);
    $stmt->execute();
    $stmt->close();
} else {
    die('Prepare statement failed: ' . $mysqli->error);
}

// 現在のセッションを終了
session_unset();
session_destroy();

// ログインページにリダイレクト
header("Location: /login/");
exit();
?>
