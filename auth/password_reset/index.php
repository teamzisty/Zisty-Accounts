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

// データベース接続のエラーハンドリング
if ($mysqli->connect_error) {
    die('データベースの接続に失敗しました: ' . $mysqli->connect_error);
}

// ユーザーエージェントのチェック
if (!isset($_SESSION['user_agent'])) {
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
} elseif ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    session_unset();
    session_destroy();
    session_start();
}

// トークンチェック
if (isset($_GET['token'])) {
    $token = $_GET['token'];

    $stmt = $mysqli->prepare("SELECT user_id, type, email, expires_at, is_verified FROM users_verification WHERE token = ?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $stmt->bind_result($user_id, $type, $email, $expires_at, $is_verified);
    $stmt->fetch();
    $stmt->close();

    if ($user_id) {
        if ($is_verified) {
            header("Location: failed/");
            exit();
        } elseif (new DateTime() < new DateTime($expires_at)) {

        } else {
            header("Location: failed/");
            exit();
        }
    } else {
        header("Location: failed/");
        exit();
    }
} else {
    header("Location: failed/");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'], $_POST['csrf_token']) && $_POST['csrf_token'] === $_SESSION['csrf_token']) {
    // CSRFトークンの検証
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Invalid CSRF token.');
    }

    // 新しいパスワードの取得
    $new_password = $_POST['password'];

    // パスワードをハッシュ化
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

    // パスワードの更新クエリ
    $stmt = $mysqli->prepare("UPDATE users SET password = ? WHERE username = ?");
    $stmt->bind_param("ss", $hashed_password, $username);
    $stmt->execute();
    $stmt->close();

    // 使用済みリクエスト
    $stmt = $mysqli->prepare("UPDATE users_verification SET is_verified = TRUE WHERE token = ?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $stmt->close();

    // ログイン画面へリダイレクト
    header("Location: /login/");
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
    <meta charset="utf-8" />
    <title>Password Reset｜Zisty</title>
    <meta name="description"
        content="Confirmation of whether or not to deactivate the account">
    <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">
    <script src="https://www.google.com/recaptcha/api.js"></script>
    <script>
        const timeStamp = new Date().getTime();
        document.write('<link rel="stylesheet" href="/css/login.css?time=' + timeStamp + '">');
    </script>
    <style>
        .background {
            flex-grow: 1;
            background-image: url('./image.png');
            background-size: cover;
            background-position: center;
            filter: grayscale(70%);
        }
    </style>
</head>

<body>
    <div class="login-container">
        <div class="login-form">
            <div class="form">
                <div class="icon">
                    <a href="https://zisty.net"><img src="logo.png"></a>
                </div>


                <form id="loginForm" method="post" action="" onsubmit="return validateForm()"><input type="hidden"
                        name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                    <div class="error-container">
                        <i class="fas fa-exclamation-circle error-icon"></i>
                        <span class="error-text">An error has occurred! Please try again later.</span>
                    </div>

                    <h1>Password Reset</h1>
                    <p class="details">Reset your password</p>

                    <p>Identity confirmed. Please enter your new password.
                        <br><br>
                        When the password is updated, the user is redirected to the login screen.
                    </p>

                    <div class="input-group">
                        <label for="new_password">New Password</label>
                        <input type="password" name="password" id="UserNewPassword" oninput="convertToLowercase(this)" class=""
                            placeholder="" required>
                    </div>

                    <button type="submit">Update</button>
                </form>

                <div class="terms">
                    <p>By continuing, you agree to Zisty's <a>Terms of Use</a> and <a>Privacy
                            Policy</a>.<br>This site is protected by reCAPTCHA Enterprise and the Google <a
                            href="https://policies.google.com/privacy" target="_blank">Privacy Policy</a> and <a
                            href="https://policies.google.com/terms" target="_blank">Terms of Service</a> apply.</p>
                </div>
            </div>
        </div>
        <div class="background"></div>
    </div>

    <script data-cfasync="false" src="/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js"></script>
    <script src="../Warning.js"></script>
    <script src="https://www.google.com/recaptcha/api.js?render="></script>
    <script>
        function onSubmit(token) {
            document.getElementById("loginForm").submit();
        }

        grecaptcha.ready(function() {
            grecaptcha.execute('', {
                    action: 'login'
                })
                .then(function(token) {
                    var recaptchaResponse = document.createElement('input');
                    recaptchaResponse.setAttribute('type', 'hidden');
                    recaptchaResponse.setAttribute('name', 'g-recaptcha-response');
                    recaptchaResponse.setAttribute('value', token);
                    document.getElementById('loginForm').appendChild(recaptchaResponse);
                });
        });
    </script>

</body>

</html>