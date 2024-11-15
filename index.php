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

// ユーザー情報を取得
$user_id = $_SESSION["user_id"];

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

// データベースからユーザー情報を取得
$query = "SELECT username, email, name, created_at, private_id, icon_path FROM users WHERE id = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $email, $encrypted_name, $created_at, $private_id, $icon_path);
$stmt->fetch();
$stmt->close();

// 名前を複合化
$name = decryptUsername($encrypted_name, $private_id);

// 暗号化関数
function encryptUsername($username, $private_id)
{
  $cipher = "aes-256-cbc";
  $key = substr(hash('sha256', $private_id, true), 0, 32);
  $iv_length = openssl_cipher_iv_length($cipher);
  $iv = openssl_random_pseudo_bytes($iv_length);
  $encrypted = openssl_encrypt($username, $cipher, $key, 0, $iv);
  return base64_encode($encrypted . '::' . $iv);
}

// 複合化処理
function decryptUsername($encrypted_name, $private_id)
{
  $cipher = "aes-256-cbc";
  $key = substr(hash('sha256', $private_id, true), 0, 32);
  list($encrypted_data, $iv) = explode('::', base64_decode($encrypted_name), 2);
  $decrypted = openssl_decrypt($encrypted_data, $cipher, $key, 0, $iv);
  return $decrypted;
}


// 連携チェックをする関数
$sso_query = "SELECT SSO FROM users WHERE id = ?";
$stmt = $mysqli->prepare($sso_query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($SSO);
$stmt->fetch();
$stmt->close();
$form_disabled = ($SSO === 'Google' || $SSO === 'GitHub');

// アイコンが設定されていない場合の代わりのアイコンのURLを設定
$default_icon = '/@/default.webp';
$icon_path = !empty($icon_path) && file_exists($_SERVER['DOCUMENT_ROOT'] . $icon_path) ? $icon_path : $default_icon;

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
    header("Location: /login?error=" . urlencode('無効なリクエストです。'));
    exit();
  }
  $new_name = $_POST['name'];

  // ユーザー名の検証
  if (empty($new_name)) {
    $error_message = "ユーザー名が入力されていません。";
  } elseif (strlen($new_name) > 50 || strlen($new_name) < 3) {
    $error_message = "ユーザー名は3文字以上50文字未満で入力してください。";
  } else {
    if (isset($_FILES['icon']) && $_FILES['icon']['error'] === UPLOAD_ERR_OK) {
      $file_tmp = $_FILES['icon']['tmp_name'];
      $file_name = $username . '.webp';
      $destination = $_SERVER['DOCUMENT_ROOT'] . '/@/icons/' . $file_name;

      if ($_FILES['icon']['size'] > 5 * 1024 * 1024) {
        $error_message = "ファイルサイズは5MBを超えてはいけません";
      } else {
        if (file_exists($destination)) {
          unlink($destination);
        }
        $image = imagecreatefromstring(file_get_contents($file_tmp));
        if ($image !== false) {
          if (imagewebp($image, $destination)) {
            imagedestroy($image);

            $icon_path = '/@/icons/' . $file_name;

            $update_icon_query = "UPDATE users SET icon_path = ? WHERE id = ?";
            $update_icon_stmt = $mysqli->prepare($update_icon_query);
            $update_icon_stmt->bind_param("si", $icon_path, $user_id);
            if ($update_icon_stmt->execute()) {
              $message = "アイコンが更新されました";
              $success = true;
            } else {
              $error_message = "データベース更新に失敗しました: " . $update_icon_stmt->error;
            }
            $update_icon_stmt->close();
          } else {
            $error_message = "画像の保存に失敗しました";
          }
        } else {
          $error_message = "画像のアップロードに失敗しました";
        }
      }
    }

    // 名前を暗号化して保存
    $encrypted_name = encryptUsername($new_name, $private_id);
    $update_query = "UPDATE users SET name = ? WHERE id = ?";
    $update_stmt = $mysqli->prepare($update_query);
    $update_stmt->bind_param("si", $encrypted_name, $user_id);
    $update_stmt->execute();
    $update_stmt->close();

    // 更新された情報を取得し直す
    $query = "SELECT username, name, notifications, created_at, private_id FROM users WHERE id = ?";
    $stmt = $mysqli->prepare($query);
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $stmt->bind_result($username, $encrypted_name, $notifications, $created_at, $private_id);
    $stmt->fetch();
    $stmt->close();

    // 名前を複合化
    $name = decryptUsername($encrypted_name, $private_id);

    if (!isset($error_message)) {
      $message = "情報が更新されました。";
      $success = true;
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
  <title>Profile｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="Profile" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://accounts.zisty.net/" />
  <meta property="og:image" content="https://accounts.zisty.net/images/header.jpg" />
  <meta property="og:description" content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?" />
  <meta property="og:site_name" content="Zisty Accounts" />
  <meta property="og:locale" content="ja_JP" />
  <!-- Twitter Card Meta Tags (if needed) -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:site" content="@teamzisty">
  <meta name="twitter:creator" content="@teamzisty" />
  <meta name="twitter:title" content="Profile / Zisty Accounts">
  <meta name="twitter:description" content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
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
    /* Profile */
    .input-button-group {
      display: flex;
      align-items: center;
      margin-bottom: 15px;
    }

    .input-button-group input {
      flex-grow: 1;
      margin-bottom: 0;
    }

    .input-button-group button {
      margin-left: 10px;
      margin-top: 0;
      height: 38px;
      width: 50px;
      margin-bottom: -5px;
      border: 1px solid #dcdcdc67;
      background-color: #111111;
      color: #979797;
      transition: 0.3s;
    }

    .input-button-group button:hover {
      transform: scale(1.00);
      background-color: #0e0f0f;
    }

    .input-button-group button:disabled {
      cursor: not-allowed;
    }


    .eyes {
      font-size: 12px;
      margin-bottom: -7px;
      color: #dcdcdc67;
    }

    .eves i {
      margin-right: 4px;
    }

    .icon-container {
      position: relative;
      display: inline-block;
      margin-bottom: 10px;
    }

    .user_icon {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      box-shadow: 0 0px 25px 0 rgba(58, 58, 58, 0.5);
      transition: opacity 0.3s ease;
      cursor: pointer;
    }

    .icon-container i {
      position: absolute;
      transform: translateX(-100%);
      font-size: 24px;
      color: #ffffff83;
      opacity: 0;
      transition: opacity 0.3s ease;
      pointer-events: none;
    }

    .icon-container:hover .user_icon {
      opacity: 0.6;
    }

    .icon-container:hover i {
      opacity: 1;
    }

    .tag-container {
      display: flex;
      flex-wrap: wrap;
      justify-content: left;
      margin-top: 10px;
      margin-bottom: 15px;
    }

    .tag {
      background-color: #d4d4d400;
      border: 1px solid #ffffff4d;
      color: #797979;
      padding: 5px 10px;
      margin-right: 8px;
      border-radius: 20px;
      font-size: 12px;
    }

    .tag i {
      font-size: 14px;
      margin-right: 3px;
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
          <li class="nav-item koko" role="menuitem">
            <i class="bi bi-person-fill"></i>
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
      <h2>プロフィール</h2>
      <form method="post" action="" id="profile-form" onsubmit="return validateAuthForm()" enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
        <input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response">

        <div class="icon-container"><img src="<?php echo htmlspecialchars($icon_path) . '?v=' . time(); ?>" class="user_icon" id="userIcon" onclick="document.getElementById('icon').click();"><input type="file" id="icon" name="icon" style="display: none;" accept="image/*" onchange="previewIcon(event)"><i class="fa-regular fa-pen-to-square"></i></div>
        <script>
          function previewIcon(event) {
            const file = event.target.files[0];
            if (file) {
              if (file.size > 5 * 1024 * 1024) {
                showDialog("画像のサイズが5MBをオーバーしてしまいました。");
                event.target.value = '';
                return;
              }
              const reader = new FileReader();
              reader.onload = function(e) {
                document.getElementById('userIcon').src = e.target.result;
              };
              reader.readAsDataURL(file);
            }
          }
        </script>

        <label for="username">ユーザー名</label>
        <input type="text" id="username" name="username" style="pointer-events: none;" value="<?php echo htmlspecialchars($username); ?>" required>

        <label for="name">名前</label>
        <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($name); ?>" required>

        <label for="date">作成日</label>
        <input type="text" id="date" name="date" style="pointer-events: none;" value="<?php echo htmlspecialchars($created_at); ?>" required>

        <p class="eyes"><i class="bi bi-eye"></i> これらの情報は他のユーザーから見られる可能性があります。</p>
        <br>

        <button type="submit" id="submitBtn" class="btn btn-primary">送信</button>
      </form>
    </div>
  </main>

  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
</body>

</html>