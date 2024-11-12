<?php
session_start();
$userId = $_SESSION['user_id'];

// データベース接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_error) {
  die('データベースの接続に失敗しました: ' . $mysqli->connect_error);
}

$currentUrl = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
$client_id = isset($_GET['client_id']) ? $_GET['client_id'] : '';
$service_data = [];

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
      header("Location: /login/?auth=" . urlencode($client_id));
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
    header("Location: /login/?auth=" . urlencode($client_id));
    exit();
  }
} else {
  header("Location: /login/?auth=" . urlencode($client_id));
  exit();
}

// ユーザー情報を取得
$query = "SELECT username, email, two_factor_secret FROM users WHERE id = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $email, $two_factor_secret);
$stmt->fetch();
$stmt->close();

if (empty($email)) {
  header("Location: /profile/email/");
  exit();
}

// client_idからサービスの取得
if (!empty($client_id)) {
  $stmt = $mysqli->prepare("SELECT icon_url, name, description, Authentication_URL, Terms_URL, Privacy_URL, Service_URL FROM link_services WHERE service_id = ?");
  if ($stmt) {
    $stmt->bind_param("s", $client_id);
    $stmt->execute();
    $stmt->bind_result($icon_url, $name, $description, $auth_url, $terms_url, $privacy_url, $service_url);

    if ($stmt->fetch()) {
      $service_data = [
        'icon_url' => $icon_url,
        'name' => $name,
        'description' => $description,
        'auth_url' => $auth_url,
        'terms_url' => $terms_url,
        'privacy_url' => $privacy_url,
        'service_url' => $service_url,
      ];
    }

    $stmt->close();
  }
}

//public_id
$stmt = $mysqli->prepare("SELECT public_id FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$stmt->bind_result($public_id);
$stmt->fetch();
$stmt->close();

// サービスが既にリンクされているか確認
$check_stmt = $mysqli->prepare("SELECT COUNT(*) FROM link_accounts WHERE user_id = ? AND service_id = ?");
$check_stmt->bind_param("ss", $userId, $client_id);
$check_stmt->execute();
$check_stmt->bind_result($count);
$check_stmt->fetch();
$check_stmt->close();

// サービスが既にリンクされている場合
if ($count > 0) {
  $password = bin2hex(random_bytes(32));
  $encryption_key = bin2hex(random_bytes(16));
  $iv = random_bytes(16);
  $encrypted_token = openssl_encrypt($password, 'aes-256-cbc', hex2bin($encryption_key), 0, $iv);
  $encrypted_token = base64_encode($iv . $encrypted_token);
  $update_stmt = $mysqli->prepare("UPDATE link_accounts SET one_time_password = ? WHERE user_id = ? AND service_id = ?");
  if ($update_stmt) {
    $update_stmt->bind_param("sss", $password, $userId, $client_id);
    $update_stmt->execute();
    if ($update_stmt->affected_rows > 0) {
      $update_stmt->close();
      $redirect_url = $service_data['auth_url'] . "?token=" . urlencode($encrypted_token) . urlencode($encryption_key);
      header("Location: $redirect_url");
      exit();
    } else {
      echo 'ワンタイムパスワードの更新に失敗しました。';
    }
  } else {
    die('Prepare failed: ' . $mysqli->error);
  }
} else {
}

// POST リクエストが送信された場合はサービスを追加
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // 既にサービスがリンクされていないか確認
  $check_stmt = $mysqli->prepare("SELECT COUNT(*), link_id, one_time_password FROM link_accounts WHERE user_id = ? AND service_id = ?");
  $check_stmt->bind_param("ss", $public_id, $client_id);
  $check_stmt->execute();
  $check_stmt->bind_result($count, $existing_link_id, $existing_password);
  $check_stmt->fetch();
  $check_stmt->close();

  if ($count === 0) {
    // 新規のサービス追加
    $link_id = str_pad(mt_rand(0, 999999999999999999), 18, '0', STR_PAD_LEFT);
    $password = bin2hex(random_bytes(32));
    $encryption_key = bin2hex(random_bytes(16));
    $iv = random_bytes(16);
    $encrypted_token = openssl_encrypt($password, 'aes-256-cbc', hex2bin($encryption_key), 0, $iv);
    $encrypted_token = base64_encode($iv . $encrypted_token);

    $insert_stmt = $mysqli->prepare("INSERT INTO link_accounts (user_id, service_id, link_id, one_time_password) VALUES (?, ?, ?, ?)");
    if ($insert_stmt) {
      $insert_stmt->bind_param("ssss", $public_id, $client_id, $link_id, $encrypted_token);
      $insert_stmt->execute();
      $insert_stmt->close();

      // リダイレクトURLの生成と送信
      $redirect_url = $service_data['auth_url'] . "?token=" . urlencode($encrypted_token) . urlencode($encryption_key);
      header("Location: $redirect_url");
      exit();
    } else {
      die('Prepare failed: ' . $mysqli->error);
    }
  } else {
    // ワンタイムパスワードを再発行して更新
    $new_password = bin2hex(random_bytes(32));
    $new_encryption_key = bin2hex(random_bytes(16));
    $iv = random_bytes(16);
    $new_encrypted_token = openssl_encrypt($new_password, 'aes-256-cbc', hex2bin($new_encryption_key), 0, $iv);
    $new_encrypted_token = base64_encode($iv . $new_encrypted_token);

    $update_stmt = $mysqli->prepare("UPDATE link_accounts SET one_time_password = ? WHERE user_id = ? AND service_id = ?");
    if ($update_stmt) {
      $update_stmt->bind_param("sss", $new_password, $public_id, $client_id);
      $update_stmt->execute();
      $update_stmt->close();

      // リダイレクトURLの生成と送信
      $redirect_url = $service_data['auth_url'] . "?token=" . urlencode($new_encrypted_token) . urlencode($new_encryption_key);
      header("Location: $redirect_url");
      exit();
    } else {
      die('Prepare failed: ' . $mysqli->error);
    }
  }
}

$previous_page = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : $service_url;

$mysqli->close();
?>

<!DOCTYPE html>
<html lang="ja">

<head>
  <meta charset="utf-8" />
  <title>Authorize｜Zisty</title>
  <meta name="description" content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <meta property="og:title" content="Zisty Account - Authorize" />
  <meta property="og:site_name" content="accounts.zisty.net">
  <meta property="og:image" content="https://accounts.zisty.net/images/header.jpg">
  <meta property="og:image:alt" content="バナー画像">
  <meta property="og:locale" content="ja_JP" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Zisty Account - Authorize" />
  <meta name="twitter:description" content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="twitter:image:src" content />
  <meta name="twitter:site" content="accounts.zisty.net" />
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
  <script>
    const timeStamp = new Date().getTime();
    document.write('<link rel="stylesheet" href="https://zisty.net/icon.css?time=' + timeStamp + '">');
    document.write('<link rel="stylesheet" href="https://zisty.net/css/main.css?time=' + timeStamp + '">');
  </script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">
  <style>
    body {
      font-family: 'Noto Sans JP', sans-serif;
      margin: 0;
      padding: 0;
      background-color: #181a1b;
      color: #c8c3bc;
      min-height: 100vh;
      overflow-x: hidden;
    }


    h1 {
      font-size: 70px;
      margin: 0;
      margin-top: 40px;
    }

    a {
      text-decoration: none;
      color: #0066ff;
    }

    form {
      background-color: #181a1b;
      padding: 30px;
      border-radius: 8px;
      width: 400px;
      text-align: center;
    }

    form a {
      color: rgb(82, 165, 246);
    }

    main {
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      padding: 10px;
      margin: 20px;
      height: 10em;
      position: relative;
    }

    label {
      display: block;
      margin: 10px 12px 5px;
      color: #9e9e9e;
      text-align: left;
    }

    input {
      width: calc(100% - 10px);
      padding: 8px;
      margin-bottom: 10px;
      border: 1px solid #494949;
      background-color: #121212;
      color: #a7a7a7;
      border-radius: 4px;
      box-sizing: border-box;
    }

    input[type="submit"] {
      background-color: #4caf50;
      color: #fff;
      cursor: pointer;
      transition: all 0.3s ease;
      width: calc(100% - 20px);
    }

    input[type="submit"]:hover {
      background-color: #45a049;
    }

    hr {
      margin: 50px 20px 50px 20px;
    }

    header {
      background-color: #333;
      color: #fff;
      padding: 10px;
      text-align: center;
    }

    nav {
      display: flex;
      justify-content: center;
      background-color: #555;
      padding: 10px;
    }

    nav a {
      color: #fff;
      text-decoration: none;
      margin: 0 15px;
      font-weight: bold;
    }

    .Tsu {
      position: relative;
      flex: 1;
      padding: 20px;
      text-align: center;
      background-color: #fff;
      margin-top: 10px;
      max-width: 300px;
      margin: 10px;
      display: flex;
      flex-direction: column;
      /* コンテンツを縦に配置 */
      transition: all 0.3s ease;
    }

    .Tsu:hover {
      transform: scale(1.1);
    }

    .btn-container {
      margin-top: auto;
      /* ボタンを一番下に配置 */
    }


    .header {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background-color: #181a1b;
      color: #fff;
      padding: 10px;
      display: flex;
      justify-content: space-between;
      width: 100%;
      z-index: 1000;
      position: relative;
    }

    #languageBox {
      background-color: #333;
      color: #fff;
      padding: 10px;
      text-align: center;
      cursor: pointer;
      border-radius: 10px 10px 10px 10px;
    }

    #languageDropdown {
      display: none;
      position: absolute;
      background-color: rgb(36, 36, 36);
      box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
      padding: 10px;
      z-index: 1;
      border-radius: 10px;
      color: #dadada;
    }

    #languageDropdown a {
      display: block;
      color: #dadada;
      padding: 8px;
      text-decoration: none;
      cursor: pointer;
    }

    #languageDropdown a:hover {
      color: #686868;
    }

    /* 左側のリンクのスタイル */
    .left-links {
      order: 1;
      /* 左側の要素を左側に配置 */
    }

    /* 右側のリンクのスタイル */
    .right-links {
      order: 2;
      /* 右側の要素を右側に配置 */
      margin-right: 19px;
    }


    .header-a {
      text-decoration: none;
      /* リンクの下線を削除 */
      color: #fff;
      /* リンクのテキスト色を設定 */
      margin: 0 10px;
      /* リンク間の間隔を設定 */
    }

    /* ホバーエフェクトを追加する場合のスタイル */
    .header-a:hover {
      text-decoration: underline;
      /* マウスオーバー時にリンクを下線表示 */
    }

    .header-b {
      text-decoration: none;
      /* リンクの下線を削除 */
      color: #fff;
      /* リンクのテキスト色を設定 */
      margin-right: 10px;
    }

    /* ホバーエフェクトを追加する場合のスタイル */
    .header-b:hover {
      text-decoration: underline;
      /* マウスオーバー時にリンクを下線表示 */
    }

    .header-bar {
      text-decoration: none;
      /* リンクの下線を削除 */
      color: #fff;
      /* リンクのテキスト色を設定 */
      margin: 0;
      margin-right: 8px;
      margin-left: -4px;
    }

    .fa-link {
      font-size: 40px;
    }

    .fa-circle-exclamation {
      font-size: 40px;
    }

    .fa-brands {
      font-size: 18px;
      transition: 0.5s;
    }

    .fa-brands:hover {
      color: rgb(194, 194, 194);
    }

    .fa-paper-plane {
      font-size: 16px;
      transition: 0.5s;
    }

    .fa-paper-plane:hover {
      color: rgb(194, 194, 194);
    }

    .fa-earth-americas {
      font-size: 15px;
      transition: 0.5s;
    }

    .fa-earth-americas:hover {
      color: rgb(194, 194, 194);
    }

    .fa-earth-americas {
      font-size: 15px;
      transition: 0.5s;
    }

    .fa-earth-americas:hover {
      color: rgb(194, 194, 194);
    }

    .fa-boxes-stacked {
      font-size: 15px;
      transition: 0.5s;
    }

    .fa-boxes-stacked:hover {
      color: rgb(194, 194, 194);
    }

    .hello {
      margin-top: 50px;
      font-size: 30px;
      width: 700px;
    }

    .what {
      color: #333333b4;
      font-size: 26px;
    }

    .mizi {
      color: #333333e1;
      font-size: 30px;
    }

    .fancy-link {
      font-family: 'Noto Sans JP', sans-serif;
      display: inline-block;
      padding: 12px 24px;
      font-size: 1.125rem;
      text-align: center;
      text-decoration: none;
      cursor: pointer;
      border: none;
      border-radius: 20px;
      transition: background-color 0.5s, box-shadow 0.5s;
      /* トランジション時間を追加 */
      color: #fdfefc;
      box-shadow: 0 10px 25px 0 rgba(34, 34, 34, 0.5);
      margin-top: 10px;
    }

    .fancy-link.default {
      background: linear-gradient(to right, rgb(0, 255, 42), rgb(0, 189, 41));
      transition: background-color 0.5s, box-shadow 0.5s;
      /* トランジション時間を追加 */
    }

    .fancy-link.default:hover {
      background: linear-gradient(to right, rgb(0, 206, 34), rgb(0, 224, 49));
      box-shadow: 0 15px 30px 0 rgba(34, 34, 34, 0.7);
      /* box-shadow の変更に対するアニメーション */
    }

    .fancy-link.default1 {
      background: linear-gradient(to right, rgb(0, 247, 255), rgb(0, 129, 189));
      transition: background-color 0.5s, box-shadow 0.5s;
      /* トランジション時間を追加 */
    }

    .fancy-link.default1:hover {
      background: linear-gradient(to right, rgb(0, 206, 206), rgb(0, 160, 224));
      box-shadow: 0 15px 30px 0 rgba(34, 34, 34, 0.7);
      /* box-shadow の変更に対するアニメーション */
    }

    .fancy-link.default2 {
      background: linear-gradient(to right, rgb(55, 0, 255), rgb(167, 0, 189));
      transition: background-color 0.5s, box-shadow 0.5s;
      /* トランジション時間を追加 */
    }

    .fancy-link.default2:hover {
      background: linear-gradient(to right, rgb(124, 0, 206), rgb(34, 0, 224));
      box-shadow: 0 15px 30px 0 rgba(34, 34, 34, 0.7);
      /* box-shadow の変更に対するアニメーション */
    }

    .fancy-link.default3 {
      background: linear-gradient(to right, rgb(29, 160, 241), rgb(137, 199, 238));
      transition: background-color 0.5s, box-shadow 0.5s;
      /* トランジション時間を追加 */
    }

    .fancy-link.default3:hover {
      background: linear-gradient(to right, rgb(137, 199, 238), rgb(29, 160, 241));
      box-shadow: 0 15px 30px 0 rgba(34, 34, 34, 0.7);
      /* box-shadow の変更に対するアニメーション */
    }

    .fancy-link.default5 {
      background: linear-gradient(to right, rgb(241, 29, 29), rgb(255, 166, 0));
      transition: background-color 0.5s, box-shadow 0.5s;
      /* トランジション時間を追加 */
    }

    .fancy-link.default5:hover {
      background: linear-gradient(to right, rgb(255, 166, 0), rgb(241, 29, 29));
      box-shadow: 0 15px 30px 0 rgba(34, 34, 34, 0.7);
      /* box-shadow の変更に対するアニメーション */
    }


    .fa-play {
      margin-right: 5px;
    }

    .fa-circle-info {
      margin-right: 5px;
    }

    .fa-up-right-from-square {
      margin-right: 5px;
    }

    .twitter {
      margin-right: 5px;
    }

    .github {
      margin-right: 5px;
    }

    .box {
      margin-right: 5px;
    }



    .boxbox {
      width: 200px;
      height: 200px;
      margin: 10px;
      padding: 20px;
      background-color: #d1d1d17e;
      color: #5c5c5c;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      border-radius: 10px 10px 10px 10px;
    }

    .icon {
      font-size: 36px;
    }

    .bold-text {
      font-weight: bold;
      font-size: 20px;
    }

    .normal-text {
      font-size: 16px;
    }

    .center {
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      /* ブラウザウィンドウの高さいっぱいに表示 */
    }

    .tp {
      font-size: 14px;
      margin-top: 50px;
    }

    .TextBox {
      margin: 5px;
      /*外の余白を設定*/
      position: relative;
      /*通常位置を基準に相対位置を指定*/
    }

    .TextBox label {
      /*入力欄に入力する前のラベルのスタイルの設定*/
      color: gray;
      /*文字色の指定*/
      position: absolute;
      /*親要素を基準に絶対位置を指定*/
      inset: -0.2rem auto auto 1rem;
      /*上 右 下 左の配置を設定*/
      font-size: .8rem;
      /*フォントのサイズを指定*/
    }

    .TextBox input:focus+label,
    /*入力中の状態の設定*/
    .TextBox input:not(:placeholder-shown)+label {
      /*入力が終わりかつ、入力欄に文字が入力されている状態の設定*/
      color: gray;
      /*文字色の指定*/
      background-color: #181a1b;
      /*ラベルの背景色を設定*/
      font-size: .8rem;
      /*フォントのサイズを指定*/
      inset: -1.5em auto auto 1rem;
      /*上下左右の配置を設定*/
      padding: 0 .5em;
      /*内の余白を指定*/
      transition: all 0.2s 0s ease;
      /*未入力状態から入力状態になるときのラベル移動のアニメーションの時間指定*/
    }

    .error-message {
      color: rgb(255, 88, 88);
      font-size: 15px;
    }

    #loading-screen {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: #181a1b;
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 9999;
    }

    @keyframes fadeOut {
      0% {
        opacity: 1;
      }

      100% {
        opacity: 0;
        display: none;
      }
    }

    .button-container {
      display: flex;
      justify-content: center;
    }

    .styled-button {
      padding: 6px 30px;
      font-size: 16px;
      color: white;
      background-color: #007BFF;
      border: none;
      border-radius: 25px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      cursor: pointer;
      transition: background-color 0.3s, box-shadow 0.3s;
      margin-right: 3px;
      margin-left: 3px;
    }

    .styled-button:not(:last-child) {
      border-top-right-radius: 0;
      border-bottom-right-radius: 0;
    }

    .styled-button:not(:first-child) {
      border-top-left-radius: 0;
      border-bottom-left-radius: 0;
    }

    .styled-button:hover {
      background-color: #0056b3;
      box-shadow: 0 6px 8px rgba(0, 0, 0, 0.1);
    }

    .styled-button:active {
      background-color: #004494;
      box-shadow: 0 3px 4px rgba(0, 0, 0, 0.1);
    }

    .rules {
      color: #c8c3bc;
      text-decoration: underline solid #c8c3bc;
    }
  </style>
  <script>
    function account_error(message) {
      alert(message);
    }
  </script>
</head>

<body>
  <div id="loading-screen">
    <noscript>
      <p>
        <span style="font-size: 50px;">⚠</span><br>
        JavaScriptを有効にしてください。<br>
        Please enable JavaScript.
      </p>
      <style>
        .load {
          width: 0;
        }
      </style>
    </noscript>
    <img src="https://accounts.zisty.net/images/load.gif">
  </div>

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

  <div class="center">
    <?php if (!empty($service_data)): ?>
      <form method="post" action="" onsubmit="return validateForm()">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <img src="<?php echo htmlspecialchars($service_data['icon_url']); ?>" width="50px">
        <h2>認証しますか？</h2>
        <p><?php echo htmlspecialchars($service_data['name']); ?>がアカウントへのアクセスを要求しています。<br>続行すると名前、メールアドレス、言語設定、PublicIDが共有されます。<br><br>
          <?php echo htmlspecialchars($service_data['name']); ?>の<a class="rules" target="_blank" href="<?php echo htmlspecialchars($service_data['privacy_url']); ?>">プライバシーポリシー</a>と<a class="rules" target="_blank" href="<?php echo htmlspecialchars($service_data['terms_url']); ?>">利用規約</a>をご覧ください。</br></p>

        <?php
        if (isset($_GET['error'])) {
          echo '<p class="error-message">Error：' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8') . '</p>';
        }
        ?>

        <div class="button-container">
          <a href="<?php echo $previous_page ?>" class="styled-button" style="background-color: #333;">キャンセル</a>
          <button class="styled-button">認証</button>
        </div>

        <p class="tp"><a href="https://zisty.net/terms/" target="_blank">Tos</a>｜<a
            href="https://zisty.net/privacy/" target="_blank">Privacy</a></p>
      </form>
    <?php else: ?>
      <form>
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <img src="None.jpg" width="70px">
        <h2>道に迷いんでしまったようです</h2>
        <p>あなたがリクエストしたサービスは存在しないまたは停止されている可能性があります。</p>

        <p class="tp"><a href="https://zisty.net/terms/" target="_blank">Tos</a>｜<a
            href="https://zisty.net/privacy/" target="_blank">Privacy</a></p>
      </form>
    <?php endif; ?>
  </div>

  <script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script>
  <script src="../Warning.js"></script>
  <script src="/showDialog.js"></script>
  <script>
    window.addEventListener('load', function() {
      setTimeout(function() {
        var loadingScreen = document.getElementById('loading-screen');
        loadingScreen.style.animation = 'fadeOut 1s ease forwards';
      }, 1000);
    });
  </script>
</body>

</html>