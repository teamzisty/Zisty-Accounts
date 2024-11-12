<?php
// セッション設定の強化
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

// データベース接続設定
$host = '';
$dbname = '';
$username = '';
$password = '';
try {
  $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
  die("データベース接続エラー: " . $e->getMessage());
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

// public_idを取得
$user_id = $_SESSION["user_id"];
$query = "SELECT public_id FROM users WHERE id = ?";
$stmt = $pdo->prepare($query);
$stmt->execute([$user_id]);
$public_id = $stmt->fetchColumn();

// データベースから連携サービス情報を取得する関数
function getLinkedServices($pdo, $publicId)
{
  $query = "SELECT ls.service_id, ls.icon_url, ls.name, ls.description 
              FROM link_accounts la 
              JOIN link_services ls ON la.service_id = ls.service_id 
              WHERE la.user_id = :public_id";

  $stmt = $pdo->prepare($query);
  $stmt->execute([':public_id' => $publicId]);

  return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// 連携サービス情報を取得
$services = getLinkedServices($pdo, $public_id);

// 取得したサービス数をカウント
$serviceCount = count($services);

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  // CSRFトークン検証
  if (
    !isset($_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']) ||
    !isset($_SESSION['csrf_token_time']) ||
    time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_EXPIRE
  ) {
    header("Location: /applications?error=" . urlencode('無効なリクエストです。'));
    exit();
  }
  try {
    // トランザクション開始
    $pdo->beginTransaction();

    // 全ての連携を解除
    $delete_query = "DELETE FROM link_accounts WHERE user_id = ?";
    $delete_stmt = $pdo->prepare($delete_query);
    $delete_stmt->execute([$public_id]);

    // トランザクションをコミット
    $pdo->commit();

    // リダイレクト
    header("Location: ./?success=1");
    exit();
  } catch (PDOException $e) {
    $pdo->rollBack();
    $error_message = "連携解除中にエラーが発生しました。";
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
  <title>Applications｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="Applications" />
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
  <meta name="twitter:title" content="Applications / Zisty Accounts">
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
    a {
      text-decoration: none;
    }

    .item {
      display: flex;
      align-items: center;
      border-bottom: 1px solid #303030;
      padding: 3px 15px;
    }

    .item .icon {
      font-size: 24px;
      margin-right: 15px;
    }

    .item .icon img {
      width: 30px;
      border-radius: 5px;
    }

    .item .content {
      flex-grow: 1;
    }

    .item .name {
      font-weight: bold;
      color: #cfcfcf;
    }

    .item .description {
      color: #666;
      font-size: 0.9em;
      margin-top: 10px;
    }

    .item .arrow {
      font-size: 20px;
      color: #999;
      transition: transform 0.3s, color 0.3s;
    }

    .item:hover .arrow {
      transform: translateX(5px);
      color: #e4e4e4;
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
      min-width: 80px;
    }

    .settings-btn:hover {
      border: 1px solid #636363;
      background-color: #1b1b1b;
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
          <li class="nav-item" role="menuitem">
            <i class="bi bi-envelope-paper"></i>
            <span>Emails</span>
          </li>
        </a>
      </ul>

      <h2 class="category-title">Integrations</h2>
      <ul class="nav-list" role="menu">
        <a href="/applications/" class="nav-link">
          <li class="nav-item koko" role="menuitem">
            <i class="bi bi-grid-fill"></i>
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
        <h2>Applications</h2>
        <p><?php echo htmlspecialchars($serviceCount); ?>個のアプリケーションにアカウントのアクセスを許可しました。</p>

        <?php
        if (isset($message)) {
          echo "<p style='color: #ff675d;'><i style='margin-right: 5px;' class='fa-solid fa-ban'></i> <b>" . htmlspecialchars($message) . "</b></p>";
        }
        function displayServices($services)
        {
          if (empty($services)) {
          } else {
            foreach ($services as $service) {
              echo '<a href="overview?client_id=' . htmlspecialchars($service['service_id']) . '">';
              echo '<div class="item">';
              echo '<div class="icon">';
              echo '<img src="' . htmlspecialchars($service['icon_url']) . '"alt="' . htmlspecialchars($service['name']) . '">';
              echo '</div>';
              echo '<div class="content">';
              echo '<p class="name">' . htmlspecialchars($service['name']) . '</p>';
              echo '<p class="description">' . htmlspecialchars($service['description']) . '</p>';
              echo '</div>';
              echo '<div class="arrow">';
              echo '<i class="bi bi-chevron-right"></i>';
              echo '</div>';
              echo '</div>';
              echo '</a>';
            }
          }
        }
        displayServices($services);
        ?>
      </section>

      <section style="background-color: #ff2f0005;">
        <h2 style="color: #fc8a84;">全ての連携を解除する</h2>
        <p>このアカウントと連携しているサービスとの連携を全て解除します。全て解除してしまうと二度と同じアカウントでログインすることができなくなる可能性があります。</p>
        <button class="button-warning" id="unlinkButton">連携を解除する</button>
      </section>
    </div>
  </main>

  <div id="modalOverlay" class="modal-overlay" style="display: none;">
    <div class="modal-content">
      <i class="bi bi-exclamation-square"></i>
      <p>続行すると<?php echo htmlspecialchars($serviceCount); ?>個のアプリケーションとの連携を全て解除します。解除するとアプリケーションは共有した情報やデータへアクセスできなくなりますが、既に共有された情報やデータは削除されません。</p>
      <form method="POST">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="hidden" name="unlink" value="1">
        <button type="submit">連携を解除する</button>
      </form>
    </div>
  </div>

  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const modal = document.getElementById('modalOverlay');
      const unlinkButton = document.getElementById('unlinkButton');

      unlinkButton.addEventListener('click', function() {
        modal.style.display = 'flex';
      });

      modal.addEventListener('click', function(e) {
        if (e.target === modal) {
          modal.style.display = 'none';
        }
      });
    });
  </script>
</body>

</html>