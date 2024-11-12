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
if ($mysqli->connect_error) {
    die('Database connection error: ' . $mysqli->connect_error);
}

// セッションの初期化
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

// ユーザーエージェントのチェック
if (!isset($_SESSION['user_agent'])) {
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
} elseif ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    session_unset();
    session_destroy();
    session_start();
}

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
        header("Location: /security/recovery-codes?error=" . urlencode('無効なリクエストです。'));
        exit();
    }

    $username = $mysqli->real_escape_string(trim(strtolower($_POST['username'])));
    $email = $mysqli->real_escape_string(trim(strtolower($_POST['email'])));

    // ユーザー名の存在を確認
    $query = "SELECT * FROM users WHERE username = '$username'";
    $result = $mysqli->query($query);

    if ($result->num_rows > 0) {
        // SSOがNULLであるかを確認
        $user = $result->fetch_assoc();
        if ($user['SSO'] !== NULL) {
            header("Location: ./?error=サードパーティーの認証によりログインするアカウントのため、パスワードのリセットは利用できません。");
            exit();
        }

        // Emailの存在を確認
        $query = "SELECT * FROM users WHERE username = '$username' AND email = '$email'";
        $result = $mysqli->query($query);

        if ($result->num_rows > 0) {
            // 既存の検証エントリを削除
            $stmt = $mysqli->prepare("DELETE FROM users_verification WHERE user_id = ? AND type = 'password_reset'");
            $stmt->bind_param("i", $user_id);
            $stmt->execute();
            $stmt->close();

            // トークンを生成
            $token = bin2hex(random_bytes(32));
            $expires_at = (new DateTime())->add(new DateInterval('PT10M'))->format('Y-m-d H:i:s');

            // テーブルにエントリを挿入
            $stmt = $mysqli->prepare("INSERT INTO users_verification (user_id, token, expires_at, email, type, created_at) VALUES (?, ?, ?, ?, 'password_reset', NOW())");
            $stmt->bind_param("isss", $user_id, $token, $expires_at, $email);
            $stmt->execute();
            $stmt->close();

            // 認証リンクの作成
            $reset_url = "https://accounts.zisty.net/auth/password_reset/?token=" . $token;

            // メール送信
            $to = $email;
            $subject = "パスワードリセットリクエストの確認";
            $message = "
                <html>
                <head>
                  <title>パスワードリセットの認証｜Zisty</title>
                </head>
                <body>
                  <p>" . $username . " 様</p>
                  <p>パスワードのリセットがリクエストされました。パスワードをリセットするには、次のリンクをクリックしてください。</p>
                  <a href='" . $reset_url . "'>" . $reset_url . "</a>
                  <p>このリクエストを依頼していない場合は、このメールを無視してください。</p>
                  <p>よろしくお願い致します。</p>
                  <p>TeamZisty / Zisty Accounts</p>
                </body>
                </html>
          ";

            // ヘッダー
            $headers = "MIME-Version: 1.0" . "\r\n";
            $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
            $headers .= "From: Zisty Accounts <no-reply@zisty.net>" . "\r\n";
            $headers .= 'X-Mailer: PHP/' . phpversion();

            if (mail($email, $subject, $message, $headers)) {
                header("Location: success/");
            } else {
                $error_message = "不明なエラーが発生しました。";

                // 既存の検証エントリを削除
                $stmt = $mysqli->prepare("DELETE FROM users_verification WHERE user_id = ? AND type = 'password_reset'");
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $stmt->close();
            }
        } else {
            $error_message = "このユーザー名は登録されていません。";
        }
    } else {
        $error_message = "このユーザー名は登録されていません。";
    }
    echo "<script>
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelector('.error-text').innerText = " . json_encode($error_message) . ";
        document.querySelector('.error-container').style.display = 'flex';
    });
    </script>";
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
    <meta charset="utf-8" />
    <title>Password Reset｜Zisty</title>
    <meta name="description" content="Confirmation of whether or not to deactivate the account">
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
            filter: grayscale(100%);
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

                <form id="authForm" method="post" action="" onsubmit="return validateForm()"><input type="hidden"
                        name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                    <div class="error-container">
                        <i class="fas fa-exclamation-circle error-icon"></i>
                        <span class="error-text">An error has occurred! Please try again later.</span>
                    </div>

                    <h1>Password Reset</h1>
                    <p class="details">Reset your password</p>

                    <p>Enter the email address registered in your account and you will receive a URL to reset your
                        password.<br><br>
                        If no email address has been set up, it cannot be restored.
                    </p>

                    <div class="input-group">
                        <label for="username">Username</label>
                        <input type="text" name="username" id="UserName" oninput="convertToLowercase(this)" class=""
                            placeholder="" required>
                    </div>
                    <div class="input-group">
                        <label for="email">Email</label>
                        <input type="email" name="email" id="UserEmail" oninput="convertToLowercase(this)" class=""
                            placeholder="" required>
                    </div>

                    <button type="submit">Send</button>
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
            document.getElementById("authForm").submit();
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
                    document.getElementById('authForm').appendChild(recaptchaResponse);
                });
        });
    </script>

</body>

</html>