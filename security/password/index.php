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

// データベース接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_error) {
  die('データベースの接続に失敗しました: ' . $mysqli->connect_error);
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

// 連携チェックをする関数
$sso_query = "SELECT sso FROM users WHERE id = ?";
$stmt = $mysqli->prepare($sso_query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($sso);
$stmt->fetch();
$stmt->close();
$form_disabled = ($sso === 'Google' || $sso === 'GitHub');

$error_message = "";
$success_message = "";

// POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // CSRFトークン検証
  if (
    !isset($_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token_time']) ||
    time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_EXPIRE
  ) {
    header("Location: /login?error=" . urlencode('無効なリクエストです。'));
    exit();
  }

  $currentPassword = $_POST['current_password'];
  $newPassword = $_POST['new_password'];

  if (!preg_match('/^[A-Z0-9!@#$%^&*()_+-=]{6,}$/i', $newPassword)) {
    $error_message = "パスワードは6文字以上、かつ1～9、A～Z、記号のみ使用できます。";
  }

  if (empty($currentPassword) || empty($newPassword)) {
    $error_message = "すべてのフィールドに入力してください。";
  } else {
    // データベースからユーザー情報を取得
    $stmt = $mysqli->prepare('SELECT password FROM users WHERE id = ?');
    if ($stmt) {
      $stmt->bind_param('i', $userId);
      $stmt->execute();
      $stmt->bind_result($hashedPassword);
      $stmt->fetch();
      $stmt->close();

      if ($hashedPassword && password_verify($currentPassword, $hashedPassword)) {
        // パスワードをハッシュ化
        $hashedNewPassword = password_hash($newPassword, PASSWORD_BCRYPT);

        // パスワードを更新
        $stmt = $mysqli->prepare('UPDATE users SET password = ? WHERE id = ?');
        if ($stmt) {
          $stmt->bind_param('si', $hashedNewPassword, $userId);
          $stmt->execute();
          $stmt->close();

          header("Location: /all_logout.php");
        } else {
          $error_message = "パスワードの更新に失敗しました。";
        }
      } else {
        $error_message = "現在のパスワードが正しくありません。";
      }
    } else {
      $error_message = "ユーザー情報の取得に失敗しました。";
    }
  }
  // 結果に応じてリダイレクト
  if (isset($success) && $success) {
    header("Location: ?success=1");
  } else {
    header("Location: ?error=" . urlencode($error_message));
  }
  exit();
}

// CSRFトークンの生成
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$_SESSION['csrf_token_time'] = time();

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
  <title>Password｜Security｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="Password" />
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
  <meta name="twitter:title" content="Password / Zisty Accounts">
  <meta name="twitter:description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="twitter:image" content="https://accounts.zisty.net/images/header.jpg">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">
  <script>
    const timeStamp = new Date().getTime();
    document.write('<link rel="stylesheet" href="https://accounts.zisty.net/css/style.css?time=' + timeStamp + '">');
  </script>
  <style>
    input,
    textarea {
      margin-top: 5px;
      padding: 10px;
      border: 1px solid #81818167;
      background-color: #161211;
      border-radius: 4px;
      margin-bottom: 15px;
      color: #979797;
      transition: all 0.3s;
    }

    input:hover,
    textarea:hover {
      border: 1px solid #dcdcdc9a;
      background-color: #161211;
    }

    input:focus,
    textarea:focus {
      border: 1px solid #dcdcdc9a;
      background-color: #161211;
    }


    input:-webkit-autofill,
    input:-webkit-autofill:hover,
    input:-webkit-autofill:focus {
      -webkit-text-fill-color: #979797 !important;
      -webkit-box-shadow: 0 0 0 30px #161211 inset !important;
      transition: background-color 5000s ease-in-out 0s;
    }

    textarea:-webkit-autofill,
    textarea:-webkit-autofill:hover,
    textarea:-webkit-autofill:focus {
      -webkit-text-fill-color: #979797 !important;
      -webkit-box-shadow: 0 0 0 30px #161211 inset !important;
      transition: background-color 5000s ease-in-out 0s;
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
          <li class="nav-item koko" role="menuitem">
            <i class="bi bi-shield-lock-fill"></i>
            <span>Security</span>
          </li>
        </a>
        <a href="/emails/" class="nav-link">
          <li class="nav-item" role="menuitem">
            <i class="bi bi-envelope-paper"></i>
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
      <section style="background-color: #ff2f0005;">
        <h2 style="color: #fc8a84;">パスワードを変更する</h2>
        <p>ここではパスワードを変更することができます。パスワードを変更すると全デバイスとの連携は解除され、再度ログインする必要があります。</p>

        <?php if (!$form_disabled): ?>
          <form method="post" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

            <label for="current_password">今のパスワード<br></label>
            <input type="password" id="current_password" name="current_password" required>

            <label for="new_password">新しいパスワード<br></label>
            <input type="password" id="new_password" name="new_password" required>

            <button style="margin-top: 30px;" class="button-warning" type="submit">パスワードを変更する</button>
          </form>
        <?php else: ?>
          <section style="background-color: #271511; border: 1px solid #352521; padding: 0px 20px; margin: 0;">
            <p>サードパーティーの認証によってログインされているアカウントはパスワードを変更することはできません。</p>
          </section>
        <?php endif; ?>
      </section>
    </div>
  </main>

  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
</body>

</html>