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

// 言語を取得する関数
$stmt = $mysqli->prepare("SELECT language FROM users WHERE id = ?");
if ($stmt === false) {
  die('Prepare statement failed: ' . $mysqli->error);
}
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($language);
$stmt->fetch();
$stmt->close();
$display_language = ($language === 'Japanese') ? '日本語' : 'English';

// セッション設定
function generateCsrfToken() {
  if (isset($_SESSION['csrf_token']) && isset($_SESSION['csrf_token_expire']) && 
      $_SESSION['csrf_token_expire'] >= time()) {
      return $_SESSION['csrf_token'];
  }
  $token = bin2hex(random_bytes(32));
  $_SESSION['csrf_token'] = $token;
  $_SESSION['csrf_token_expire'] = time() + CSRF_TOKEN_EXPIRE;
  return $token;
}
function validateCsrfToken($token) {
  if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_expire'])) {
      return false;
  }
  if ($_SESSION['csrf_token_expire'] < time()) {
      unset($_SESSION['csrf_token']);
      unset($_SESSION['csrf_token_expire']);
      return false;
  }
  return hash_equals($_SESSION['csrf_token'], $token);
}

// AJAXリクエストによる言語の更新処理
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['language'])) {
  $submitted_token = $_POST['csrf_token'] ?? '';
  if (!validateCsrfToken($submitted_token)) {
    $error_message = "認証に失敗しました";
  }

  if (isset($_SESSION["user_id"])) {
    $user_id = $_SESSION["user_id"];
    $new_language = $_POST['language'];
    $stmt = $mysqli->prepare("UPDATE users SET language = ? WHERE id = ?");
    if ($stmt === false) {
      die('Prepare statement failed: ' . $mysqli->error);
    }
    $stmt->bind_param("si", $new_language, $user_id);
    $stmt->execute();
    $stmt->close();
    header("Location: ?success=1");
    exit();
  } else {
    $error_message = "言語の更新に失敗しました";
    exit();
  }

  // 結果に応じてリダイレクト
  if (isset($success) && $success) {
    header("Location: ?success=1");
  } else {
    header("Location: ?error=" . urlencode($error_message));
  }
  exit();
}

$csrf_token = generateCsrfToken();

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
  <title>Language｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="Language" />
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
  <meta name="twitter:title" content="Language / Zisty Accounts">
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
    .content .title {
      font-size: 20px;
    }

    .content .description {
      color: #cfcfcf;
    }

    .button-style {
      display: inline-block;
      padding: 8px 20px;
      background-color: #1b1b1b;
      color: #cfcfcf;
      border: 1px solid #414141;
      text-align: center;
      text-decoration: none;
      border-radius: 10px;
      font-size: 12px;
      transition: all 0.3s ease;
    }

    .button-style:hover {
      background-color: #1b1b1b;
      border: 1px solid #2e2e2e;
    }


    .link {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0px 5px;
      border: 1px solid #2b2b2b;
      border-radius: 5px;
      margin-top: 15px;
    }

    .link i {
      padding: 10px;
      border-radius: 5px;
      margin-left: 10px;
      font-size: 25px;
    }

    .link .title {
      margin: 0;
      font-size: 18px;
    }

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
    }

    .settings-btn:hover {
      border: 1px solid #636363;
      background-color: #1b1b1b;
    }
  </style>
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
          <li class="nav-item koko" role="menuitem">
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
      <section>
        <h2>言語（ベータ版）</h2>
        <p>言語を設定することによって、連携時に共有され、そのサービスの言語を簡単に設定することができます。</p>
        <form method="POST">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
          <select id="options" name="language">
            <option value="Japanese" <?php if ($language === 'Japanese') echo 'selected'; ?>>日本語</option>
            <option value="English" <?php if ($language === 'English') echo 'selected'; ?>>English</option>
          </select>
        </form>
      </section>
    </div>
  </main>

  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
  <script>
    document.getElementById('options').addEventListener('change', function() {
      const selectedLanguage = this.value;
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "", true);
      xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      const csrfToken = document.querySelector('input[name="csrf_token"]').value;
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
          showDialog("正常に保存されました！");
        }
      };
      xhr.send("language=" + encodeURIComponent(selectedLanguage) + "&csrf_token=" + encodeURIComponent(csrfToken));
    });
  </script>
</body>

</html>