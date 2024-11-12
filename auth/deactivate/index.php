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
}

// ユーザーエージェントのチェック
if (!isset($_SESSION['user_agent'])) {
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
} elseif ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    session_unset();
    session_destroy();
    session_start();
}

// ログイン状態の確認
if (!isset($_SESSION["user_id"])) {
    header("Location: /login/");
    exit();
}

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

// ログインの有効期限を確認
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
            $stmt = $mysqli->prepare("UPDATE users_verification SET is_verified = TRUE WHERE token = ?");
            $stmt->bind_param("s", $token);
            $stmt->execute();
            $stmt->close();
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


// アカウント削除処理
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // reCAPTCHAの検証
    $recaptcha_secret = "";
    $recaptcha_response = $_POST['g-recaptcha-response'];

    $verify_response = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret=' . $recaptcha_secret . '&response=' . $recaptcha_response);
    $response_data = json_decode($verify_response);

    if (!$response_data->success || $response_data->score < 0.5) {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $error_message = "認証に失敗しました。";
        } else {
            $userId = $_SESSION['user_id'];

            $sql = "DELETE FROM users WHERE id = ?";
            $stmt = $mysqli->prepare($sql);
            $stmt->bind_param("i", $userId);

            if ($stmt->execute()) {
                session_unset();
                session_destroy();
                header("Location: /login/");
                exit();
            } else {
                $error_message = "アカウントの削除に失敗しました: " . $stmt->error;
            }

            $stmt->close();
        }
    } else {
        $error_message = "不正な動作を検出しました。";
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
    <title>Deactivate｜Zisty</title>
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
        form button {
            background-color: #7a3535;
            color: #ffffff;
            border: 1px solid #b65050;
        }

        form button:hover {
            background-color: #4d2121;
            color: #ffffff;
            border: 1px solid #7a3535;
        }

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

                    <h1>Deactivate</h1>
                    <p class="details">Confirmation of whether or not to deactivate the account</p>

                    <p>Are you sure you want to deactivate your account? If you continue, you will never be able to log
                        in to your account again, and all linkages will be removed and no longer available for use.
                        <br><br>
                        Once deactivated, it cannot be restored again. Please proceed only if you are willing to do so.
                    </p>

                    <button type="submit">See you 👋</button>
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