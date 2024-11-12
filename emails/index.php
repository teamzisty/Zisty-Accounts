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

// ユーザー情報を取得
$user_id = $_SESSION["user_id"] ?? null;
if (!$user_id) {
  header("Location: /login/");
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

// ユーザー情報を取得
$stmt = $mysqli->prepare("SELECT username, email FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $email);
$stmt->fetch();
$stmt->close();

$email_sent = false;

// フォームが送信された場合の処理
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  // CSRFトークン検証
  if (
    !isset($_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token_time']) ||
    time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_EXPIRE
  ) {
    header("Location: /emails?error=" . urlencode('無効なリクエストです。'));
    exit();
  }

  $new_email = $_POST["new_email"];
  $current_password = $_POST["current_password"];

  // 新しいメールアドレスが既に存在するか確認
  $stmt = $mysqli->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
  $stmt->bind_param("s", $new_email);
  $stmt->execute();
  $stmt->bind_result($count);
  $stmt->fetch();
  $stmt->close();

  if ($count > 0) {
    $error_message = "このメールアドレスは既に使用されています。";
  }

  $stmt = $mysqli->prepare("SELECT password FROM users WHERE id = ?");
  $stmt->bind_param("i", $user_id);
  $stmt->execute();
  $stmt->bind_result($hashed_password);
  $stmt->fetch();
  $stmt->close();

  if (password_verify($current_password, $hashed_password)) {
    $token = bin2hex(random_bytes(32));
    $expires_at = (new DateTime())->add(new DateInterval('P1D'))->format('Y-m-d H:i:s');
    $stmt = $mysqli->prepare("INSERT INTO users_verification (user_id, type, token, email, expires_at) VALUES (?, 'email_verification', ?, ?, ?)");
    $stmt->bind_param("isss", $user_id, $token, $new_email, $expires_at);
    $stmt->execute();
    $stmt->close();

    // 認証リンクの作成
    $verify_link = "https://accounts.zisty.net/auth/email/?token={$token}";

    // メール送信
    $to = $new_email;
    $subject = "メールアドレスの認証";
    $message = "
          <html>
          <head>
            <title>メールアドレスの認証｜Zisty</title>
          </head>
          <body>
            <p>{$username} 様</p>
            <p>メールアドレスを確認するには、次のリンクをクリックしてください。</p>
            <a href='{$verify_link}'>{$verify_link}</a>
            <p>このアドレスの確認を依頼していない場合は、このメールを無視してください。</p>
            <p>よろしくお願い致します。</p>
            <p>TeamZisty / Zisty Accounts</p>
          </body>
          </html>
      ";

    $headers = "MIME-Version: 1.0\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8\r\n";
    $headers .= "From: Zisty Accounts <no-reply@zisty.net>\r\n";

    if (mail($to, $subject, $message, $headers)) {
      $email_sent = true;
    } else {
      $error_message = "メールの送信に失敗しました。";
    }
  } else {
    $error_message = "パスワードが間違っています。";
  }
}

// CSRFトークンの生成
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$_SESSION['csrf_token_time'] = time();

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
  <title>Emails｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="Emails" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://accounts.zisty.net/" />
  <meta property="og:image" content="https://accounts.zisty.net/images/header.jpg" />
  <meta property="og:description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?" />
  <meta property="og:site_name" content="Zisty Accounts" />
  <meta property="og:locale" content="ja_JP" />
  <!-- Twitter Card Meta Tags (if needed) -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:site" content="@teamzisty">
  <meta name="twitter:creator" content="@teamzisty" />
  <meta name="twitter:title" content="Emails / Zisty Accounts">
  <meta name="twitter:description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="twitter:image" content="https://accounts.zisty.net/images/header.jpg">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">
  <script src="https://www.google.com/recaptcha/api.js?render=6LdKgkgqAAAAADJkj3xBqXPpJBy0US_zj8siyx1w"></script>
  <script>
    const timeStamp = new Date().getTime();
    document.write('<link rel="stylesheet" href="https://accounts.zisty.net/css/style.css?time=' + timeStamp + '">');
  </script>
  <style>
    .settings-btn {
      font-size: 14px;
      padding: 10px 25px;
      margin-right: 10px;
      border: none;
      background-color: #1b1b1b;
      color: #cfcfcf;
      border: 1px solid #414141;
      border-radius: 3px;
      cursor: pointer;
      margin-top: 0;
      min-width: 80px;
    }

    .settings-btn:hover {
      border: 1px solid #636363;
      background-color: #1b1b1b;
    }

    .switch {
      font-size: 17px;
      position: relative;
      display: inline-block;
      min-width: 3.1em;
      height: 30px;
      margin-right: 15px;
      margin-bottom: 10px;
    }

    .switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }

    .slider {
      position: absolute;
      cursor: pointer;
      inset: 0;
      border: 1px solid #414141;
      border-radius: 50px;
      transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }

    .slider:before {
      position: absolute;
      content: "";
      height: 1.2em;
      width: 1.2em;
      left: 0.2em;
      bottom: 0.2em;
      background-color: rgb(182, 182, 182);
      border-radius: inherit;
      transition: all 1s cubic-bezier(0.23, 1, 0.320, 1);
    }
  </style>
  <script>
    window.onload = function() {
      const urlParams = new URLSearchParams(window.location.search);

      if (urlParams.get('success') === '1') {
        showDialog("正常に保存されました！");
        const iconElement = document.getElementById('user-icon');
        if (iconElement) {
          const iconUrl = iconElement.src;
          iconElement.src = '';
          iconElement.src = iconUrl + '?v=' + new Date().getTime();
        }
        const url = new URL(window.location);
        url.searchParams.delete('success');
        history.replaceState(null, '', url);

      } else if (urlParams.get('error')) {
        showDialog("" + decodeURIComponent(urlParams.get('error')));
        const url = new URL(window.location);
        url.searchParams.delete('error');
        history.replaceState(null, '', url);
      }
    };

    function showDialog(message) {
      alert(message);
    }
  </script>
</head>

<body>
  <noscript>
    <meta http-equiv="refresh" content="0;url=/error/NOSCRIPT/" />
  </noscript>

  <div class="notification" id="notification">
    <div class="notification-icon">
      <i class="bi bi-info-circle"></i>
    </div>
    <div class="notification-content">
      <div class="notification-title">Notification</div>
      <div class="notification-message" id="notification-message"></div>
    </div>
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

  <main>
    <nav class="nav-container">
      <h2 class="category-title">Personal</h2>
      <ul class="nav-list" role="menu">
        <a href="/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-person"></i>
            <span>Profile</span>
          </li>
        </a>
        <a href="/admin/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-gear"></i>
            <span>Account</span>
          </li>
        </a>
        <a href="/language/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-globe"></i>
            <span>Language</span>
          </li>
        </a>
        <a href="/notifications/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-bell"></i>
            <span>Notifications</span>
          </li>
        </a>
      </ul>

      <h2 class="category-title">Access</h2>
      <ul class="nav-list" role="menu">
        <a href="/sessions/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-broadcast-pin"></i>
            <span>Sessions</span>
          </li>
        </a>
        <a href="/security/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-shield-lock"></i>
            <span>Security</span>
          </li>
        </a>
        <a href="/emails/" class="nav-link">
          <li class="nav-item koko" role="menuitem">
            <i class="bi bi-envelope-paper-fill"></i>
            <span>Emails</span>
          </li>
        </a>
      </ul>

      <h2 class="category-title">Integrations</h2>
      <ul class="nav-list" role="menu">
        <a href="/applications/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-grid"></i>
            <span>Applications</span>
          </li>
        </a>
        <a href="/developer/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-code-slash"></i>
            <span>Developer</span>
          </li>
        </a>
      </ul>

      <ul class="nav-list bottom-links" role="menu">
        <a href="https://zisty.net/docs/" target="_blank" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-book"></i>
            <span>Document</span>
          </li>
        </a>
        <a href="/API/logout.php" class="nav-link" style="color: #c98884;">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-door-open"></i>
            <span>Log Out</span>
          </li>
        </a>
      </ul>
    </nav>

    <div class="content">
      <?php if ($email): ?>
        <section>
          <h3><?php echo htmlspecialchars($email); ?></h3>
          <p>登録されているメールアドレスへZisty Accountsへの通知やアカウント削除の確認、パスワードリセットの確認などのメールが送信されます。</p>
        </section>
      <?php endif; ?>


      <section>
        <h2>アドレスの変更
        </h2>
        <p>メールアドレスを変更することができます。変更、または追加することによって二段階認証の設定や制限されているサービスとの連携が可能になります。</p>

        <?php if (!$email_sent): ?>
          <form method="post" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <label for="current_password">パスワード<br></label>
            <input type="password" id="confirm_password" name="current_password" required>

            <label for="new_email">新しいメールアドレス<br></label>
            <input type="email" id="new_email" name="new_email" required>

            <button type="submit"><i class="fa-regular fa-paper-plane"></i> アドレスに認証URLを送信</button>
          </form>
        <?php else: ?>
          <section style="padding: 0px 20px; margin: 0;">
            <p>追加予定のメールアドレスへ確認URLを送信しました。</p>
          </section>
        <?php endif; ?>
      </section>

      <section>
        <h2>アドレスの非公開（開発者版）</h2>
        <p>
          サービスとの連携時、設定されたアドレスは使用せずに<?php echo htmlspecialchars($username); ?>@users.noreply.zisty.netを使用することができます。しかし、これを使用すると非公開を公開に切り替えたとき、そのサービスへそのままログインすることができなくなる可能性があります。よく考えてご使用ください。
        </p>
        <p>※現在設定不可能になっています。今後にご期待ください。</p>
        <div class="link">
          <div class="content">
            <h2 class="title">Private Link</h2>
          </div>
          <label class="switch">
            <input type="checkbox" name="status">
            <span class="slider"></span>
          </label>
        </div>
      </section>
    </div>
  </main>

  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
</body>

</html>