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
  echo "データベースの接続に失敗しました: " . $mysqli->connect_error;
  exit();
}

// URLのクエリパラメータから値を取得
$error = isset($_GET['error']) ? htmlspecialchars($_GET['error']) : '';

// ユーザー情報を取得
$user_id = isset($_SESSION["user_id"]) ? $_SESSION["user_id"] : null;

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
$result = $stmt->get_result();
$user_data = $result->fetch_assoc();
$username = $user_data['username'];
$email = $user_data['email'];
$stmt->close();

if (empty($email)) {
  header("Location: ../");
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

// アクセストークン確認
if (isset($_COOKIE['recovery_codes_verification'])) {
  $token = $_COOKIE['recovery_codes_verification'];
  $stmt = $mysqli->prepare("SELECT user_id, is_verified FROM users_verification WHERE token = ? AND type = 'recovery_codes_verification' AND expires_at > NOW()");
  $stmt->bind_param("s", $token);
  $stmt->execute();
  $result = $stmt->get_result();
  $verified = $result->fetch_assoc();
  $stmt->close();

  if ($verified) {
    // Recovery codesを取得
    $stmt = $mysqli->prepare("SELECT recovery_codes FROM users_factor WHERE username = ?");
    if ($stmt === false) {
      die('Prepare statement failed: ' . $mysqli->error);
    }
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $recovery_data = $result->fetch_assoc();
    $recovery_codes_json = $recovery_data['recovery_codes'];
    $stmt->close();

    if (empty($recovery_codes_json)) {
      header("Location: ../?error=二段階認証が設定されていません。");
      exit();
    }

    $recovery_codes = json_decode($recovery_codes_json, true);
    if (!$recovery_codes || !is_array($recovery_codes)) {
      header("Location: ../?error=二段階認証が設定されていません。");
      exit();
    }
  } else {
    header("Location: /auth/recovery-codes/");
    exit();
  }
} else {
  header("Location: /auth/recovery-codes/");
  exit();
}

// POSTリクエストの処理
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // CSRFトークン検証
  if (
    !isset($_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token_time']) ||
    time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_EXPIRE
  ) {
    header("Location: /security/recovery-codes?error=" . urlencode('無効なリクエストです。'));
    exit();
  }

  // 新しいRecovery codesを生成
  $new_recovery_codes = generateRecoveryCodes();
  $new_recovery_codes_json = json_encode($new_recovery_codes);

  // データベースに新しいリカバリーコードを保存
  $stmt = $mysqli->prepare("UPDATE users_factor SET recovery_codes = ? WHERE username = ?");
  if ($stmt === false) {
    die('Prepare statement failed: ' . $mysqli->error);
  }
  $stmt->bind_param("ss", $new_recovery_codes_json, $username);
  $stmt->execute();
  $stmt->close();

  header("Location: ./?success=1");
  exit();
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
  <title>Recovery Codes｜Security｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="Recovery Codes" />
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
  <meta name="twitter:title" content="Recovery Codes / Zisty Accounts">
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
    .lists {
      border-radius: 15px;
      padding: 20px;
      max-width: 400px;
      display: flex;
      justify-content: space-between;
      margin: 0 auto;
    }

    .list ul {
      padding: 10px 0px 0px 20px;
    }

    .list li {
      margin-bottom: 15px;
      position: relative;
      line-height: 1.6;
      color: #bebebe;
      font-size: 20px;
    }
  </style>
  <script>
    window.onload = function() {
      const urlParams = new URLSearchParams(window.location.search);

      if (urlParams.get('success') === '1') {
        showDialog("正常に発行されました！");

        const successSection = document.querySelector('.success');
        if (successSection) {
          successSection.style.display = 'block';
        }

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
      <section class="success" style="background-color: #b3ff0005; border: 1px solid #d0ff001f; padding: 0px 20px; display: none;">
        <p>新しいRecovery codeが正常に発行されました。これらのRecovery codeは安全な場所に保管し、以前のコードは破棄してください。</p>
      </section>

      <section>
        <h2>Recovery codes</h2>
        <p>デバイスへログインできなくなり、二段階認証コードを確認できない場合にRecovery codeを使用してアカウントにアクセスすることができます。</p>
        <p>Recovery codeは安全な場所に保管してください。これらのコードがわからない場合、アカウントにアクセスできなくなります。</p>
        <div class="lists">
          <div class="list">
            <ul>
              <?php
              $total_codes = count($recovery_codes);
              $half = ceil($total_codes / 2);
              for ($i = 0; $i < $half; $i++) {
                if (isset($recovery_codes[$i])) {
                  echo '<li>' . htmlspecialchars($recovery_codes[$i]) . '</li>';
                }
              }
              ?>
            </ul>
          </div>
          <div class="list">
            <ul>
              <?php
              for ($i = $half; $i < $total_codes; $i++) {
                if (isset($recovery_codes[$i])) {
                  echo '<li>' . htmlspecialchars($recovery_codes[$i]) . '</li>';
                }
              }
              ?>
            </ul>
          </div>
        </div>
      </section>

      <form method="POST" action="" id="recovery-codes-form">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <section>
          <h2>新たに生成する</h2>
          <p>新しいRecovery codeを生成します。新たに生成してしまうと古いコードは使用できなくなってしまいます。</p>
          <button type="submit" class="settings-btn">新たに生成する</button>
        </section>
      </form>

    </div>
  </main>

  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
</body>

</html>