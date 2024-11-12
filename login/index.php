<?php
// ファイルの読み込み
require 'libs/GoogleAuthenticator.php';
require_once 'SSO/vendor/autoload.php';

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

// データベース接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_error) {
    die('Database connection error: ' . $mysqli->connect_error);
}

// セッションIDの検証と再生成
if (isset($_COOKIE[session_name()])) {
    if (!preg_match('/^[a-zA-Z0-9,-]{48,96}$/', $_COOKIE[session_name()])) {
        session_id(bin2hex(random_bytes(32)));
    }
}

// セッション開始
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// セッションの初期化
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
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

    if (!isset($_SESSION['last_regeneration'])) {
        $_SESSION['last_regeneration'] = time();
    } else if (time() - $_SESSION['last_regeneration'] > 300) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }

    return true;
}

// ログインチェック
if (isset($_SESSION["user_id"])) {
    $user_id = $_SESSION["user_id"];
    $session_id = session_id();

    $stmt = $mysqli->prepare("
    SELECT 
        username, 
        last_login_at 
    FROM users_session 
    WHERE session_id = ? AND username = (
        SELECT username 
        FROM users 
        WHERE id = ?
    )
");
    $stmt->bind_param("si", $session_id, $user_id);
    $stmt->execute();
    $stmt->bind_result($username, $last_login_at);
    $stmt->fetch();
    $stmt->close();

    if ($last_login_at) {
        $current_time = new DateTime();
        $last_login_time = new DateTime($last_login_at);
        $interval = $current_time->diff($last_login_time);

        if ($interval->days < 3) {
            header("Location: /");
            exit();
        } else {
            session_unset();
            session_destroy();
        }
    }
}

// 既存のエラーメッセージの初期化
$error_message = '';

// GETパラメーターからエラーメッセージを取得
if (isset($_GET['error'])) {
    $error_message = htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8');
}

// 既存のエラーメッセージがある場合、JavaScriptでダイアログを表示
if (!empty($error_message)) {
    echo "<script>
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelector('.error-text').innerText = " . json_encode($error_message) . ";
        document.querySelector('.error-container').style.display = 'flex';
    });
    </script>";
}

// POST リクエスト処理
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

    // ユーザー名とパスワードでのログイン処理
    if (isset($_POST["username"]) && isset($_POST["password"])) {
        $username = htmlspecialchars(trim($_POST["username"]), ENT_QUOTES, 'UTF-8');
        $password = trim($_POST["password"]);

        if (!empty($username) && !empty($password)) {
            $username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');

            $stmt = $mysqli->prepare("
                SELECT 
                    u.id,
                    u.username,
                    u.password,
                    uf.two_factor_enabled,
                    uf.two_factor_secret
                FROM users u
                LEFT JOIN users_factor uf ON u.username = uf.username
                WHERE u.username = ?
            ");

            if ($stmt === false) {
                error_log("Database prepare error: " . $mysqli->error);
                die('Database error occurred');
            }

            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();

                if (password_verify($password, $user['password'])) {
                    error_log("Password verified successfully");

                    if ($user['two_factor_enabled'] == 1) {
                        $_SESSION["pending_2fa_user_id"] = $user['id'];
                        $_SESSION["pending_2fa_secret"] = $user['two_factor_secret'];

                        echo '<script>
                        window.onload = function() {
                            document.getElementById("loginForm").style.display = "none";
                            document.getElementById("authForm").style.display = "block";
                        };
                        </script>';
                    } else {
                        completeLogin($user['id'], $user['username'], $mysqli);
                    }
                } else {
                    $error_message = "ユーザー名またはパスワードが正しくありません。";
                }
            } else {
                $error_message = "ユーザー名またはパスワードが正しくありません。";
            }

            $stmt->close();
        } else {
            $error_message = "ユーザー名とパスワードを入力してください。";
        }
    }
    // 2FAコード検証
    elseif (
        isset($_POST["code1"], $_POST["code2"], $_POST["code3"], $_POST["code4"], $_POST["code5"], $_POST["code6"]) &&
        isset($_SESSION["pending_2fa_user_id"]) && isset($_SESSION["pending_2fa_secret"])
    ) {

        $user_id = $_SESSION["pending_2fa_user_id"];
        $secret = $_SESSION["pending_2fa_secret"];

        $code = $_POST["code1"] . $_POST["code2"] . $_POST["code3"] . $_POST["code4"] . $_POST["code5"] . $_POST["code6"];

        require_once 'libs/GoogleAuthenticator.php';
        $g = new PHPGangsta_GoogleAuthenticator();

        if ($g->verifyCode($secret, $code, 2)) {
            error_log("2FA code verified successfully");

            $stmt = $mysqli->prepare("SELECT username FROM users WHERE id = ?");
            if ($stmt) {
                $stmt->bind_param("i", $user_id);
                $stmt->execute();
                $stmt->bind_result($username);
                $stmt->fetch();
                $stmt->close();

                if ($username) {
                    completeLogin($user_id, $username, $mysqli);
                } else {
                    $error_message = "ユーザー情報の取得に失敗しました。";
                }
            } else {
                $error_message = "データベースエラーが発生しました。";
            }
        } else {
            $error_message = "無効なセキュリティコードです。";
        }
    }

    if (!empty($error_message)) {
        echo "<script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelector('.error-text').innerText = " . json_encode($error_message) . ";
            document.querySelector('.error-container').style.display = 'flex';
        });
        </script>";
    }
}

// ログイン完了処理
function completeLogin($user_id, $username, $mysqli)
{
    error_log("Completing login for user: " . $username);

    session_regenerate_id(true);
    $_SESSION["user_id"] = $user_id;

    // IPアドレスの取得
    $ip_address = $_SERVER['REMOTE_ADDR'];
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip_address = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $x_forwarded_for = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip_address = trim($x_forwarded_for[0]);
    }

    $session_id = session_id();

    // セッション情報の更新
    $stmt = $mysqli->prepare("
    INSERT INTO users_session (
        username, session_id, ip_address, created_at, last_login_at
    ) 
    VALUES (?, ?, ?, NOW(), NOW()) 
    ON DUPLICATE KEY UPDATE 
        session_id = VALUES(session_id), 
        ip_address = VALUES(ip_address), 
        last_login_at = NOW()
");

    if ($stmt) {
        $stmt->bind_param("sss", $username, $session_id, $ip_address);
        $success = $stmt->execute();
        if (!$success) {
            header("Location: /login?error=" . urlencode('セッション情報の更新に失敗しました。'));
        }
        $stmt->close();
    } else {
        header("Location: /login?error=" . urlencode('セッション情報の更新に失敗しました。'));
    }

    // セッションCookieの設定
    $expire = time() + (100 * 365 * 24 * 60 * 60);
    setcookie(session_name(), $session_id, [
        'expires' => $expire,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);

    // セキュリティメールを送信
    $email = '';  // 初期化
    $stmt = $mysqli->prepare("SELECT email FROM users WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $stmt->bind_result($email);
        if ($stmt->fetch() && !empty($email)) {
            $subject = "セキュリティメール";
            $message = "
            <html>
            <head>
              <title>セキュリティメール｜Zisty</title>
            </head>
            <body>
              <p>" . $username . " 様</p>
              <p>ユーザーのZisty Accountsに新しいログインが検出されました。心当たりのないログインがある場合は、すぐにパスワードを変更してください。</p>
              <p>よろしくお願い致します。</p>
              <p>TeamZisty / Zisty Accounts</p>
            </body>
            </html>
      ";
            $headers = "MIME-Version: 1.0" . "\r\n";
            $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
            $headers .= "From: Zisty Accounts <no-reply@zisty.net>" . "\r\n";
            $headers .= 'X-Mailer: PHP/' . phpversion();

            mail($email, $subject, $message, $headers);
        }
        $stmt->close();
    }

    // リダイレクト処理
    if (isset($_GET['auth'])) {
        $client_id = htmlspecialchars(trim($_POST["auth"]), ENT_QUOTES, 'UTF-8');
        $redirect_url = "https://accounts.zisty.net/oauth/?client_id=" . urlencode($client_id);
    } else {
        $redirect_url = '/';
    }

    header("Location: $redirect_url");
    exit();
}

// CSRFトークンの生成
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$_SESSION['csrf_token_time'] = time();

// サードパーティーによる認証
$client = new Google_Client();
$client->setClientId('.apps.googleusercontent.com');
$client->setClientSecret('GOCSPX-');
$client->setRedirectUri('https://accounts.zisty.net/login/SSO/callback/google.php');
$client->addScope('email');
$client->addScope('profile');
$googleUrl = $client->createAuthUrl();

$client_id = '';
$client_secret = '';
$redirect_uri = 'https://accounts.zisty.net/login/SSO/callback/github.php';
$githubUrl = "https://github.com/login/oauth/authorize?client_id={$client_id}&redirect_uri={$redirect_uri}";
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
    <title>Login｜Zisty</title>
    <meta name="keywords" content=" Zisty,ジスティー">
    <meta name="description"
        content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
    <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
    <!-- OGP Meta Tags -->
    <meta property="og:title" content="Sign in to Zisty" />
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
    <meta name="twitter:title" content="Sign in to Zisty">
    <meta name="twitter:description"
        content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
    <meta name="twitter:image" content="https://accounts.zisty.net/images/header.jpg">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">
    <script src="https://www.google.com/recaptcha/api.js"></script>
    <script>
        const timeStamp = new Date().getTime();
        document.write('<link rel="stylesheet" href="https://accounts.zisty.net/css/login.css?time=' + timeStamp + '">');
    </script>
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

                    <h1>Welcome back</h1>
                    <p class="details">Sign in to your enterprise account</p>
                    <div class="input-group">
                        <label for="username">Username</label>
                        <input type="text" name="username" id="UserName" oninput="convertToLowercase(this)" class=""
                            placeholder="" required>
                    </div>
                    <div class="input-group">
                        <div class="password-group">
                            <label for="password">Password</label>
                            <a href="/password_reset/" class="forgot-password">Forgot Password?</a>
                        </div>
                        <input type="password" name="password" id="UserPassword" oninput="convertToLowercase(this)"
                            class="" placeholder="" required>
                    </div>
                    <button type="submit">Sign In</button>

                    <p class="signup">Don't have an account? <a href="/register/">Sign up</a></p>

                    <div class="divider">
                        <span>or</span>
                    </div>
                    <div class="social-login">
                        <a href="<?php echo $githubUrl; ?>"><i class="fa-brands fa-github"></i> Continue with GitHub</a>
                        <a href="<?php echo $googleUrl; ?>"><i class="fa-brands fa-google"></i> Continue with Google</a>
                        <a href="/login/SSO/"><i class="fa-solid fa-key"></i> Continue with SSO</a>
                    </div>
                </form>

                <form id="authForm" method="post" style="display:none;" onsubmit="return validateAuthForm()">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="g-recaptcha-response" id="auth-g-recaptcha-response">
                    <h1>Two-factor authentication</h1>
                    <p class="details">Enter the authentication code from your two-factor authentication app</p>
                    <div class="input-container">
                        <input type="number" name="code1" class="digit-input" maxlength="1" required>
                        <input type="number" name="code2" class="digit-input" maxlength="1" required>
                        <input type="number" name="code3" class="digit-input" maxlength="1" required>
                        <input type="number" name="code4" class="digit-input" maxlength="1" required>
                        <input type="number" name="code5" class="digit-input" maxlength="1" required>
                        <input type="number" name="code6" class="digit-input" maxlength="1" required>
                    </div>
                    <script>
                        const inputs = document.querySelectorAll('.digit-input');
                        inputs.forEach((input, index) => {
                            input.addEventListener('input', (e) => {
                                const value = e.target.value;
                                if (value.length === 1) {
                                    if (index < inputs.length - 1) {
                                        inputs[index + 1].focus();
                                    } else {
                                        document.getElementById("authForm").submit();
                                    }
                                }
                                if (value.length > 1) {
                                    e.target.value = value.slice(0, 1);
                                }
                            });

                            input.addEventListener('keydown', (e) => {
                                if (e.key === 'Backspace') {
                                    if (input.value === '' && index > 0) {
                                        inputs[index - 1].focus();
                                    } else {
                                        input.value = '';
                                    }
                                }
                            });
                        });
                    </script>
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
    <script src="/js/Warning.js"></script>
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