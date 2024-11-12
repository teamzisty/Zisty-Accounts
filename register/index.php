<?php
// ファイルの読み込み
require_once '../login/SSO/vendor/autoload.php';

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
session_start();

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

    $stmt = $mysqli->prepare("SELECT username, last_login_at FROM users_session WHERE session_id = ? AND username = (SELECT username FROM users WHERE id = ?)");
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

// user_idを生成する関数
function generate18DigitUserId()
{
    $timestamp = time();
    $random = mt_rand(100000, 999999);
    return sprintf("%s%06d", $timestamp, $random);
}

// UUIDを発行する関数
function generateUUID()
{
    return sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0xffff)
    );
}

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


// 既存のエラーメッセージの初期化
$error_message = '';

// GETパラメーターからエラーメッセージを取得
if (isset($_GET['error'])) {
    $error_message = isset($_GET['error']) ? htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8') : '';
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

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // CSRFトークン検証
    if (
        !isset($_POST['csrf_token']) ||
        !isset($_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']) ||
        !isset($_SESSION['csrf_token_time']) ||
        time() - $_SESSION['csrf_token_time'] > CSRF_TOKEN_EXPIRE
    ) {
        header("Location: /login?error=" . urlencode('無効なリクエストです'));
        exit();
    }

    // reCAPTCHAの検証
    $recaptcha_secret = "";
    $recaptcha_response = $_POST['g-recaptcha-response'];

    $verify_response = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret=' . $recaptcha_secret . '&response=' . $recaptcha_response);
    $response_data = json_decode($verify_response);

    if (!$response_data->success || $response_data->score < 0.5) {
        $username = $_POST["username"];
        $password = $_POST["password"];

        if (!preg_match('/^[A-Z0-9_]{3,}$/i', $username)) {
            $error_message = "ユーザー名は3文字以上、かつ1～9、A～Z、アンダースコアのみ使用できます。";
        } else {
            if (!preg_match('/^[A-Z0-9!@#$%^&*()_+-=]{6,}$/i', $password)) {
                $error_message = "パスワードは6文字以上、かつ1～9、A～Z、記号のみ使用できます。";
            }
        }

        if (empty($error_message)) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            $public_id = generateUUID();
            $private_id = generateUUID();

            $encrypted_username = encryptUsername($username, $private_id);

            $icon_files = [
                '/@/default.webp',
                '/@/default2.webp',
                '/@/default3.webp',
                '/@/default4.webp',
                '/@/default5.webp',
                '/@/default6.webp',
                '/@/default7.webp',
                '/@/default8.webp',
                '/@/default9.webp',
                '/@/default10.webp',
                '/@/default11.webp'
            ];
            $selected_icon = $icon_files[array_rand($icon_files)];

            $check_stmt = $mysqli->prepare("SELECT id FROM users WHERE username = ?");
            $check_stmt->bind_param("s", $username);
            $check_stmt->execute();
            $check_stmt->store_result();

            if ($check_stmt->num_rows > 0) {
                $error_message = "このユーザー名は既に使用されています。";
            } else {
                $check_stmt->close();

                $insert_stmt = $mysqli->prepare("INSERT INTO users (username, name, password, public_id, private_id, icon_path) VALUES (?, ?, ?, ?, ?, ?)");
                $insert_stmt->bind_param("ssssss", $username, $encrypted_username, $hashed_password, $public_id, $private_id, $selected_icon);

                if ($insert_stmt->execute()) {
                    $new_user_id = $mysqli->insert_id;

                    session_regenerate_id(true);
                    $_SESSION["user_id"] = $new_user_id;

                    $expire = time() + (100 * 365 * 24 * 60 * 60);
                    setcookie(session_name(), session_id(), [
                        'lifetime' => SESSION_LIFETIME,
                        'path' => '/',
                        'domain' => 'accounts.zisty.net',
                        'secure' => true,
                        'httponly' => true,
                        'samesite' => 'Strict'
                    ]);

                    $ip_address = $_SERVER['REMOTE_ADDR'];
                    $session_id = session_id();

                    // IPアドレスの取得
                    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
                        $ip_address = $_SERVER['HTTP_CLIENT_IP'];
                    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                        $x_forwarded_for = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                        $ip_address = trim($x_forwarded_for[0]);
                    } else {
                        $ip_address = $_SERVER['REMOTE_ADDR'];
                    }

                    // `users_session`テーブルにデータを挿入
                    $stmt_session_insert = $mysqli->prepare("INSERT INTO users_session (username, session_id, ip_address, created_at, last_login_at) VALUES (?, ?, ?, NOW(), NOW()) ON DUPLICATE KEY UPDATE last_login_at = NOW()");
                    if ($stmt_session_insert) {
                        $stmt_session_insert->bind_param("sss", $username, $session_id, $ip_address);
                        $stmt_session_insert->execute();
                        $stmt_session_insert->close();
                    }

                    $redirect_url = isset($_GET['auth']) ? filter_var($_GET['auth'], FILTER_SANITIZE_URL) : '/';
                    if (filter_var($redirect_url, FILTER_VALIDATE_URL)) {
                        header("Location: $redirect_url");
                    } else {
                        header("Location: /");
                    }
                    exit();
                } else {
                    $error_message = "アカウント作成中にエラーが発生しました。";
                }

                $insert_stmt->close();
            }
        } else {
            $error_message = "不正な動作を検出しました。";
        }
        echo "<script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelector('.error-text').innerText = " . json_encode($error_message) . ";
            document.querySelector('.error-container').style.display = 'flex';
        });
        </script>";
    }
}

// CSRFトークンの生成
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$_SESSION['csrf_token_time'] = time();

// Google Client設定
$client = new Google_Client();
$client->setClientId('.apps.googleusercontent.com');
$client->setClientSecret('');
$client->setRedirectUri('https://accounts.zisty.net/login/SSO/callback/google.php');
$client->addScope('email');
$client->addScope('profile');
$googleUrl = $client->createAuthUrl();

// GitHub OAuthの設定
$client_id = '';
$client_secret = '';
$redirect_uri = 'https://accounts.zisty.net/login/SSO/callback/github.php';
$githubUrl = "https://github.com/login/oauth/authorize?client_id={$client_id}&redirect_uri={$redirect_uri}";
?>

<!DOCTYPE html>
<html lang="ja">

<head>
    <meta charset="UTF-8">
    <title>Register｜Zisty</title>
    <meta name="keywords" content=" Zisty,ジスティー">
    <meta name="description"
        content="Zisty Accounts is a service that allows you to easily integrate with Zisty's services. Why not give it a try?">
    <meta name="copyright" content="Copyright &copy; 2024 Zisty. All rights reserved." />
    <!-- OGP Meta Tags -->
    <meta property="og:title" content="Sign up to Zisty" />
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
    <meta name="twitter:title" content="Sign up to Zisty">
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
    <style>
        .terms-text {
            margin-top: 15px;
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

                <div class="error-container">
                    <i class="fas fa-exclamation-circle error-icon"></i>
                    <span class="error-text">An error has occurred! Please try again later.</span>
                </div>

                <form id="SignForm" method="post" action="" onsubmit="return validateForm()">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <h1>Get started</h1>
                    <p class="details">Create a new account</p>
                    <div class="input-group">
                        <label for="Username">Username</label>
                        <input type="text" name="username" id="UserName" class="" placeholder="" required>
                    </div>
                    <div class="input-group">
                        <div class="password-group">
                            <label for="password">Password</label>
                        </div>
                        <input type="password" name="password" id="UserPassword" class="" placeholder="" required>
                    </div>
                    <button type="submit">Sign Up</button>

                    <p class="signup">Have an account? <a href="/login/">Sign in</a></p>

                    <div class="divider">
                        <span>or</span>
                    </div>
                    <div class="social-login">
                        <a href="<?php echo $githubUrl; ?>"><i class="fa-brands fa-github"></i> Continue with GitHub</a>
                        <a href="<?php echo $googleUrl; ?>"><i class="fa-brands fa-google"></i> Continue with Google</a>
                        <a href="/login/sso/"><i class="fa-solid fa-key"></i> Continue with SSO</a>
                    </div>

                    <div class="terms">
                        <p>By continuing, you agree to Zisty's <a>Terms of Use</a> and <a>Privacy Policy</a>.<br>This site is protected by reCAPTCHA Enterprise and the Google <a href="https://policies.google.com/privacy" target="_blank">Privacy Policy</a> and <a href="https://policies.google.com/terms" target="_blank">Terms of Service</a> apply.</p>
                    </div>
                </form>
            </div>
        </div>
        <div class="background"></div>
    </div>

    <script src="https://www.google.com/recaptcha/api.js?render="></script>
    <script>
        function onSubmit(token) {
            document.getElementById("SignForm").submit();
        }

        grecaptcha.ready(function() {
            grecaptcha.execute('', {
                action: 'login'
            }).then(function(token) {
                var recaptchaResponse = document.createElement('input');
                recaptchaResponse.setAttribute('type', 'hidden');
                recaptchaResponse.setAttribute('name', 'g-recaptcha-response');
                recaptchaResponse.setAttribute('value', token);
                document.getElementById('SignForm').appendChild(recaptchaResponse);
            });
        });
    </script>

</body>

</html>