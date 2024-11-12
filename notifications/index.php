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

// Ajax リクエストの処理
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $response = ['success' => false, 'message' => ''];

  if (isset($_POST['action'])) {
    switch ($_POST['action']) {
      case 'update_notifications':
        $notifications_array = [
          'security' => isset($_POST['security']) && $_POST['security'] === 'true',
          'announcements' => isset($_POST['announcements']) && $_POST['announcements'] === 'true',
          'status' => isset($_POST['status']) && $_POST['status'] === 'true'
        ];
        break;

      case 'unsubscribe_all':
        $notifications_array = [
          'security' => false,
          'announcements' => false,
          'status' => false
        ];
        break;

      default:
        $response['message'] = '不正なアクションです';
        header('Content-Type: application/json');
        echo json_encode($response);
        exit();
    }

    $notifications_json = json_encode($notifications_array);

    $stmt = $mysqli->prepare("UPDATE users SET notifications = ? WHERE id = ?");
    if ($stmt === false) {
      $response['message'] = 'Prepare statement failed: ' . $mysqli->error;
    } else {
      $stmt->bind_param("si", $notifications_json, $user_id);
      if ($stmt->execute()) {
        $response['success'] = true;
        $response['message'] = '設定を保存しました';
        $response['notifications'] = $notifications_array;
      } else {
        $response['message'] = '保存に失敗しました: ' . $stmt->error;
      }
      $stmt->close();
    }
  }

  header('Content-Type: application/json');
  echo json_encode($response);
  exit();
}

// 通知設定の取得
$stmt = $mysqli->prepare("SELECT notifications FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($notifications);
$stmt->fetch();
$stmt->close();

// 現在の設定を取得
$notifications = json_decode($notifications, true);
if ($notifications === null) {
  $notifications = [
    'security' => true,
    'announcements' => false,
    'status' => false
  ];
}

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
  <title>Notifications｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="Notifications" />
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
  <meta name="twitter:title" content="Notifications / Zisty Accounts">
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

    .link p {
      font-size: 12px;
      margin-bottom: 0;
      margin-top: 10px;
    }

    .link .title {
      margin: 0;
      font-size: 15px;
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

    .switch input:checked+.slider {
      border: 1px solid #414141;
    }

    .switch input:checked+.slider:before {
      transform: translateX(1.4em);
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
          <li class="nav-item" role="menuitem">
            <i class="bi bi-globe"></i>
            <span>Language</span>
          </li>
        </a>
        <a href="/notifications/" class="nav-link">
          <li class="nav-item koko" role="menuitem">
            <i class="bi bi-bell-fill"></i>
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
        <h2>通知</h2>
        <p>通知は設定されているメールアドレスを使用して送信されます。</p>

        <div class="link">
          <div class="content">
            <h2 class="title">セキュリティメール</h2>
            <p>アカウントにログインされた場合やパスワードが変更された場合にメールでお知らせします。</p>
          </div>
          <label class="switch">
            <input type="checkbox" name="security" <?php echo $notifications['security'] ? 'checked' : ''; ?> onchange="updateNotification(this)">
            <span class="slider"></span>
          </label>
        </div>

        <div class="link">
          <div class="content">
            <h2 class="title">アナウンス＆アップデート</h2>
            <p>Zisty Accountsの最新の機能や改善、バグの修正などをメールでお知らせします。</p>
          </div>
          <label class="switch">
            <input type="checkbox" name="announcements" <?php echo $notifications['announcements'] ? 'checked' : ''; ?> onchange="updateNotification(this)">
            <span class="slider"></span>
          </label>
        </div>

        <div class="link">
          <div class="content">
            <h2 class="title">ステータスメール</h2>
            <p>Zisty Accountsがログインできなくなる問題が発生したり、サービスの連携が行えなくなる問題などが発生した場合にメールでお知らせします。</p>
          </div>
          <label class="switch">
            <input type="checkbox" name="status" <?php echo $notifications['status'] ? 'checked' : ''; ?> onchange="updateNotification(this)">
            <span class="slider"></span>
          </label>
        </div>
      </section>

      <section style="background-color: #ff2f0005;">
        <h2 style="color: #fc8a84;">全てのメールの配信登録を解除する</h2>
        <p>これにはセキュリティに関するメール、アナウンスやアップデートに関するメール、ステータスに関するメールなどを含みます。</p>
        <button onclick="unsubscribeAll()" class="button-warning">解除する</button>
      </section>
  </main>


  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
  <script>
    let saveTimeout;
    const notification = document.getElementById('notification');

    function showNotification(message, success = true) {
      notification.textContent = message;
      notification.style.backgroundColor = success ? '#4CAF50' : '#f44336';
      notification.classList.add('show');

      setTimeout(() => {
        notification.classList.remove('show');
      }, 3000);
    }

    function updateNotification(checkbox) {
      if (saveTimeout) {
        clearTimeout(saveTimeout);
      }
      saveTimeout = setTimeout(() => {
        const formData = new FormData();
        formData.append('action', 'update_notifications');
        document.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          formData.append(cb.name, cb.checked);
        });

        fetch(window.location.href, {
            method: 'POST',
            body: formData
          })
          .then(response => response.json())
          .then(data => {
            if (data.success) {

            } else {
  
            }
          })
          .catch(error => {
            showDialog('エラーが発生しました');
          });
      }, 10);
    }

    function unsubscribeAll() {
      const formData = new FormData();
      formData.append('action', 'unsubscribe_all');

      fetch(window.location.href, {
          method: 'POST',
          body: formData
        })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
              checkbox.checked = false;
            });
            showDialog("全ての通知を解除しました");
          } else {
            showDialog("全ての通知を解除しました");
          }
        })
        .catch(error => {
          showDialog('Error:', error);
          showNotification('エラーが発生しました', false);
        });
    }
  </script>
</body>

</html>