<?php
session_start();

// データベースに接続
$mysqli = new mysqli("", "", "", "");

if ($mysqli->connect_errno) {
  echo "データベースの接続に失敗しました: " . $mysqli->connect_error;
  exit();
}

// ユーザー情報を取得
$user_id = $_SESSION["user_id"];

// ログイン状態の確認
if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
  $ip_address = $_SERVER['HTTP_CLIENT_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
  $x_forwarded_for = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
  $ip_address = trim($x_forwarded_for[0]);
} else {
  $ip_address = $_SERVER['REMOTE_ADDR'];
}
if (isset($_SESSION["user_id"])) {
  $user_id = $_SESSION["user_id"];
  $session_id = session_id();

  $stmt = $mysqli->prepare("SELECT last_login_at, ip_address FROM users_session WHERE session_id = ? AND username = (SELECT username FROM users WHERE id = ?)");
  if ($stmt === false) {
    die('Prepare statement failed: ' . $mysqli->error);
  }
  $stmt->bind_param("si", $session_id, $user_id);
  $stmt->execute();
  $stmt->bind_result($last_login_at, $session_ip_address);
  $stmt->fetch();
  $stmt->close();

  if ($last_login_at && $session_ip_address === $ip_address) {
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
} else {
  header("Location: /login/");
  exit();
}

// ユーザー名を取得
$user_id = $_SESSION["user_id"];
$query = "SELECT username, two_factor_enabled FROM users WHERE id = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $two_factor_enabled);
$stmt->fetch();
$stmt->close();

// デバイス情報を取得
$query = "SELECT ip_address, last_login_at, created_at FROM users_session WHERE username = ? ORDER BY created_at DESC";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->bind_result($ip_address, $last_login_at, $created_at);
$devices = [];
while ($stmt->fetch()) {
  $devices[] = [
    'ip_address' => $ip_address,
    'last_login_at' => $last_login_at,
    'created_at' => $created_at
  ];
}
$stmt->close();


$mysqli->close();
?>

<!--

 _______                           ______ _       _
|__   __|                         |___  /(_)     | |
   | |     ___   __ _  _ __ ___      / /  _  ___ | |_  _   _
   | |    / _ \ / _` || '_ ` _ \    / /  | |/ __|| __|| | | |
   | |   |  __/| (_| || | | | | |  / /__ | |\__ \| |_ | |_| |
   |_|    \___| \__,_||_| |_| |_| /_____||_||___/ \__| \__, |
                                                        __/ |
                                                       |___/

 We are TeamZisty!
 If you are watching this, why don't you join our team?
 https://discord.gg/6BPfVm6cST

-->

<!DOCTYPE html>
<html lang="ja">

<head>
  <meta charset="UTF-8">
  <title>Security｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description" content="Zistyはなんとなくで結成されたプログラミングチームです。そしてここは大事な規約が眠っています。">
  <meta name="copyright" content="Copyright &copy; 2023 Zisty. All rights reserved." />
  <meta property="og:title" content="Terms - Zisty" />
  <meta property="og:image" content="https://zisty.net/images/screenshot.785.jpg">
  <meta property="og:image:alt" content="バナー画像">
  <meta property="og:locale" content="ja_JP" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Terms - Zisty" />
  <meta name="twitter:description" content="Zistyはなんとなくで結成されたプログラミングチームです。そしてここは大事な規約が眠っています。">
  <meta name="twitter:image:src" content />
  <meta name="twitter:site" content="https://zisty.net/" />
  <meta name="twitter:creator" content="https://zisty.net/" />
  <meta name="twitter:title" content="Zisty" />
  <meta name="twitter:description" content="https://zisty.net/" />
  <meta name="twitter:image:src" content />
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
  <script>
    const timeStamp = new Date().getTime();
    document.write('<link rel="stylesheet" href="https://zisty.net/icon.css?time=' + timeStamp + '">');
    document.write('<link rel="stylesheet" href="https://zisty.net/css/main.css?time=' + timeStamp + '">');
    document.write('<link rel="stylesheet" href="/css/main.css?time=' + timeStamp + '">');
  </script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">
  <style>
    .settings-btn {
      font-size: 14px;
      width: 100px;
      margin-right: 8px;
      margin-left: 15px;
      border: none;
      background-color: #007bff;
      color: white;
      border-radius: 3px;
      cursor: pointer;
      margin-top: 0;
    }

    .settings-btn:hover {
      background-color: #0056b3;
    }

    .release-btn {
      font-size: 14px;
      width: 100px;
      margin-right: 8px;
      margin-left: 15px;
      border: none;
      background-color: #FF3333;
      color: white;
      border-radius: 3px;
      cursor: pointer;
      margin-top: 0;
    }

    .release-btn:hover {
      background-color: #c92626;
    }
  </style>
</head>

<body>
  <noscript>
    <div class="noscript-overlay">
      <div class="message-box">
        <div class="emoji">⚠️</div>
        <h1>JavaScriptを有効にしてください</h1>
        <p>
          ダッシュボードを使用するにはJavaScriptを有効にしていただく必要があります。<br>
          JavaScriptを有効にして再読み込みをするか、JavaScriptに対応しているブラウザを使用していただく必要があります。
        </p>
      </div>
    </div>
  </noscript>

  <div id="dialog" class="dialog"></div>
  <script>
    window.onload = function() {
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('success') === '1') {
        showDialog("✅ 正常に設定されました！");
        const iconElement = document.getElementById('user-icon');
        if (iconElement) {
          const iconUrl = iconElement.src;
          iconElement.src = '';
          iconElement.src = iconUrl + '?v=' + new Date().getTime();
        }
      } else if (urlParams.get('error')) {
        showDialog("❌ " + decodeURIComponent(urlParams.get('error')));
      }
    };

    function showDialog(message) {
      alert(message);
    }
  </script>

  <div class="header">
    <div class="left-links">
      <a class="header-a" href="https://zisty.net/"><i class="fa-solid fa-house"></i></a>
      <a class="header-a" href="https://zisty.net/blog/">Blog</a>
      <a class="header-a" href="https://accounts.zisty.net/">Accounts</a>
    </div>
    <div class="right-links">
      <a class="header-b" href="https://discord.gg/6BPfVm6cST" target="_blank"><i class="fa-brands fa-discord"></i></a>
      <a class="header-b" href="https://x.com/teamzisty" target="_blank"><i class="fa-brands fa-x-twitter"></i></a>
      <a class="header-b" href="https://github.com/teamzisty" target="_blank"><i class="fa-brands fa-github"></i></a>
    </div>
  </div>
  <main>
    <div class="hello">
      <a href="/" class="return">
        <div class="icon-background">
          <i class="fa-solid fa-left-long"></i>
        </div>
      </a>

      <h2>セキュリティ</h2>
      <p>現在ログインしているデバイスの確認などを行うことができます。</p>

      <h3>2段階認証(2FA)</h3>
      <p>2段階認証(2FA)を利用することで、アカウントを不正アクセスから守ることができます。 サインインやプロフィールの編集、連携の解除のたびにセキュリティコードの入力が必要となります。</p>
      <div class="twoFAbox">
        <i class="fa-solid fa-mobile"></i>
        <div class="content">
          <h2 class="title">2段階認証アプリ</h2>
          <p class="details">2段階認証(2FA)として認証アプリを使用します。 サインインの際に、認証アプリにより提供されるセキュリティコードが必要になります。</p>
        </div>
        <?php if ($two_factor_enabled == 0): ?>
          <button onclick="window.location.href='app/'" class="settings-btn">設定</button>
        <?php else: ?>
          <button onclick="window.location.href='app/'" class="release-btn">解除</button>
        <?php endif; ?>
      </div>

      <h3>デバイス</h3>
      <p>現在このアカウントにログインしているアカウントの一覧です。覚えのないエントリーがある場合はすぐにパスワードを変更し、自分を守ることができます。</p>
      <?php if (!empty($devices)) : ?>
        <?php foreach ($devices as $device) : ?>
          <div class="twoFAbox">
            <i class="fa-solid fa-check"></i>
            <div class="content">
              <h2 class="title"><?php echo htmlspecialchars($device['ip_address']); ?></h2>
              <p class="details">作成日：<?php echo htmlspecialchars($device['created_at']); ?>・ラストログイン：<?php echo htmlspecialchars($device['last_login_at']); ?></p>
            </div>
          </div>
        <?php endforeach; ?>
      <?php else : ?>
        <p>現在、ログインしているデバイスはありません。</p>
      <?php endif; ?>
  </main>

  <script src="js/Warning.js"></script>
  <script src="js/showDialog.js"></script>
</body>

</html>