<?php
// セッション設定
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 1);

// セッション開始
if (session_status() === PHP_SESSION_NONE) {
  session_start();
}

// Google Authenticator クラスの読み込み
require 'libs/GoogleAuthenticator.php';

// データベースに接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_errno) {
  echo "データベースの接続に失敗しました: " . $mysqli->connect_error;
  exit();
}

// URLのクエリパラメータから'error'の値を取得
$error = isset($_GET['error']) ? htmlspecialchars($_GET['error']) : '';

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

// ユーザー情報を取得
$query = "SELECT username, email FROM users WHERE id = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$stmt->bind_result($username, $email);
$stmt->fetch();
$stmt->close();

if (empty($email)) {
  header("Location: ../?error=Emailが設定されていません。");
  exit();
}

// Google Authenticator の設定
$g = new PHPGangsta_GoogleAuthenticator();

// ユーザーの二段階認証の状態を確認
$stmt = $mysqli->prepare("SELECT two_factor_enabled, two_factor_secret FROM users_factor WHERE username = ?");
if ($stmt === false) {
  die('Prepare statement failed: ' . $mysqli->error);
}
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
$factor_data = $result->fetch_assoc();
$stmt->close();

if ($factor_data && $factor_data['two_factor_enabled'] == 1) {
  $secret = $factor_data['two_factor_secret'];
} else {
  $secret = $g->createSecret();

  // 既存のエントリを削除
  $stmt_delete = $mysqli->prepare("DELETE FROM users_factor WHERE username = ?");
  if ($stmt_delete) {
    $stmt_delete->bind_param("s", $username);
    $stmt_delete->execute();
    $stmt_delete->close();
  }

  // 新しいエントリを挿入
  $stmt_insert = $mysqli->prepare("INSERT INTO users_factor (username, two_factor_secret) VALUES (?, ?)");
  if ($stmt_insert) {
    $stmt_insert->bind_param("ss", $username, $secret);
    $stmt_insert->execute();
    $stmt_insert->close();
  }
}

$issuer = 'Zisty';
$accountName = $username;
$qrCodeUrl = $g->getQRCodeGoogleUrl($accountName, $secret, $issuer);


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
  <title>App｜Security｜Zisty</title>
  <meta name="keywords" content=" Zisty,ジスティー">
  <meta name="description"
    content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
  <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
  <!-- OGP Meta Tags -->
  <meta property="og:title" content="App" />
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
  <meta name="twitter:title" content="App / Zisty Accounts">
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
      width: 100%;
    }

    .settings-btn:hover {
      border: 1px solid #636363;
      background-color: #1b1b1b;
    }

    .qr {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px;
      border: 1px solid #585858;
      border-radius: 5px;
      width: 200px;
      background-color: #ffffff;
    }

    .digit-input {
      width: 30px;
      height: 40px;
      text-align: center;
      font-size: 2em;
      border: 2px solid #808080;
      border-radius: 10px;
      transition: border-color 0.3s ease, background-color 0.3s ease;
      outline: none;
      margin-right: 5px;
    }

    .digit-input:hover {
      border: 2px solid #007BFF;
    }

    .digit-input:focus {
      border: 2px solid #007BFF;
    }

    .digit-input::-webkit-outer-spin-button,
    .digit-input::-webkit-inner-spin-button {
      -webkit-appearance: none;
    }

    .digit-input[type="number"] {
      -moz-appearance: textfield;
    }

    .digit-input:-webkit-autofill,
    .digit-input:-webkit-autofill:hover,
    .digit-input:-webkit-autofill:focus {
      -webkit-text-fill-color: #979797 !important;
      -webkit-box-shadow: 0 0 0 30px #181a1b inset !important;
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
      <section>
        <h2>2段階認証アプリ</h2>
        <p>2段階認証(2FA)として認証アプリを使用します。スマートフォンまたはタブレット用の認証アプリや拡張機能などを使用することによって取得できるコードを使って認証することができます。</p>

        <?php if ($factor_data && $factor_data['two_factor_enabled'] == 1): ?>
          <h3>要素の無効化</h3>
          <p>二段階認証を無効化にするにはパスワードを入力する必要があります。</p>
          <form action="disable_2fa.php" method="post">
            <label for="current_password">パスワード<br></label>
            <input type="password" name="password" required>
            <script>
              const inputs = document.querySelectorAll('.digit-input');
              inputs.forEach((input, index) => {
                input.addEventListener('input', (e) => {
                  const value = e.target.value;
                  if (value.length === 1) {
                    if (index < inputs.length - 1) {
                      inputs[index + 1].focus();
                    }
                  }
                  if (value.length > 1) {
                    e.target.value = value.slice(0, 1);
                  }
                });
                input.addEventListener('keydown', (e) => {
                  if (e.key === 'Backspace' && input.value === '' && index > 0) {
                    inputs[index - 1].focus();
                  }
                });
              });
            </script>

            <button class="settings-btn">アプリの無効化</button>
          </form>

        <?php else: ?>
          <h3>QRコードをスキャンする</h3>
          <p>スマートフォンまたはタブレットで以下のQRコードをスキャンします。</p>
          <div class="qr"><img
              src=" <?php echo htmlspecialchars($qrCodeUrl); ?>"
              alt="QR Code"></div>
          <p style="font-size: 15px;">手動キー：<?php echo htmlspecialchars($secret); ?></p>


          <h3>コードの確認</h3>
          <p>2段階認証(2FA)追加に成功したらセキュリティコードを入力し、2段階認証を有効にしてください。</p>
          <form action="verify_2fa.php" method="post">
            <div class="input-container">
              <input type="number" name="code1" class="digit-input" maxlength="1" required>
              <input type="number" name="code2" class="digit-input" maxlength="1" required>
              <input type="number" name="code3" class="digit-input" maxlength="1" required>
              <input type="number" name="code4" class="digit-input" maxlength="1" required>
              <input type="number" name="code5" class="digit-input" maxlength="1" required>
              <input type="number" name="code6" class="digit-input" maxlength="1" required>
            </div>
            <script src="/js/querySelectorAll.js"></script>

            <br>

            <button class="settings-btn">アプリの有効化</button>
          </form>
        <?php endif; ?>
      </section>
    </div>
  </main>

  <script src="/js/Warning.js"></script>
  <script src="/js/notification.js"></script>
</body>

</html>