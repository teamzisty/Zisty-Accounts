<?php
session_start();

// データベース接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_error) {
  die('データベースの接続に失敗しました: ' . $mysqli->connect_error);
  exit();
}

$user_id = $_SESSION["user_id"];

// ログイン状態の確認
if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
  $ip_address = $_SERVER['HTTP_CLIENT_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
  $x_forwarded_for = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
  $ip_address = trim($x_forwarded_for[0]);
} else {
  $ip_address = $_SERVER['REMOTE_ADDR'];
}
if (isset($_SESSION["user_id"])) {
  $user_id = $_SESSION["user_id"];
  $session_id = session_id();

  $stmt = $mysqli->prepare("SELECT last_login_at, ip_address FROM users_session WHERE session_id = ? AND username = (SELECT username FROM users WHERE id = ?)");
  if ($stmt === false) {
    die('Prepare statement failed: ' . $mysqli->error);
  }
  $stmt->bind_param("si", $session_id, $user_id);
  $stmt->execute();
  $stmt->bind_result($last_login_at, $session_ip_address);
  $stmt->fetch();
  $stmt->close();

  if ($last_login_at && $session_ip_address === $ip_address) {
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
} else {
  header("Location: /login/");
  exit();
}

$userId = $_SESSION['user_id'];

// ユーザー名、名前、通知を取得
$query = "SELECT username, name, notifications FROM users WHERE id = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("i", $userId);
$stmt->execute();
$stmt->bind_result($username, $name, $notifications);
$stmt->fetch();
$stmt->close();
$mysqli->close();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  // 入力されたデータの取得
  $service_name = $_POST["name"];
  $service_description = $_POST["message"];
  $icon_url = $_POST["icon"];
  $auth_url = $_POST["authentication"];
  $terms_url = $_POST["Terms"];
  $privacy_url = $_POST["Privacy"];
  $service_url = $_POST["Service"];

  // データベース接続の再開
  $mysqli = new mysqli("", "", "", "");

  if ($mysqli->connect_error) {
    die('データベースの接続に失敗しました: ' . $mysqli->connect_error);
  }

  // サービス名が英数字のみで構成されているかチェック
  if (!preg_match('/^[a-zA-Z0-9]+$/', $service_name)) {
    $error_message = "サービス名は英数字のみ使用できます。";
  } else {
    // サービス名が既に存在するかチェック
    $stmt = $mysqli->prepare("SELECT COUNT(*) FROM link_services WHERE name = ?");
    $stmt->bind_param("s", $service_name);
    $stmt->execute();
    $stmt->bind_result($count);
    $stmt->fetch();
    $stmt->close();

    if ($count > 0) {
      // サービス名が既に存在する場合
      $error_message = "既に存在するサービス名です。別の名前を選んでください。";
    } else {
      // 20桁のservice_idを生成
      $service_id = str_pad(mt_rand(0, 999999999), 10, '0', STR_PAD_LEFT) . str_pad(mt_rand(0, 999999999), 10, '0', STR_PAD_LEFT);

      // ユーザー名、名前、通知を取得
      $query = "SELECT username FROM users WHERE id = ?";
      $stmt = $mysqli->prepare($query);
      $stmt->bind_param("i", $userId);
      $stmt->execute();
      $stmt->bind_result($username);
      $stmt->fetch();
      $stmt->close();

      // テーブルにデータを挿入
      $stmt = $mysqli->prepare("INSERT INTO link_services (service_id, name, description, icon_url, Authentication_URL, Terms_URL, Privacy_URL, Service_URL, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
      $stmt->bind_param("sssssssss", $service_id, $service_name, $service_description, $icon_url, $auth_url, $terms_url, $privacy_url, $service_url, $username);

      if ($stmt->execute()) {
        $success_message = "サービス情報が正常に記録されました。<br>生成されたサービスID: " . htmlspecialchars($service_id);
      } else {
        $error_message = "エラーが発生しました: " . $stmt->error;
      }

      $stmt->close();
    }
  }

  $mysqli->close();
}
?>

<!DOCTYPE html>
<html lang="ja">

<head>
  <meta charset="UTF-8">
  <title>Service Add</title>
  <meta name="keywords" content=" HTMLPreview">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <link rel="shortcut icon" type="image/x-icon" href="favicon.ico">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.6.0/css/all.min.css">
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      display: flex;
      overflow: hidden;
      background-color: #181a1b;
      display: flex;
    }

    .container {
      padding: 2rem;
      border-radius: 10px;
      margin: 0 auto;
      height: 100vh;
    }

    h2 {
      color: #ffffff;
      text-align: center;
      margin-bottom: 1.5rem;
    }

    p {
      color: #b0b0b0;
    }

    form {
      display: flex;
      flex-direction: column;
    }

    label {
      margin-bottom: 0.5rem;
      color: #b0b0b0;
    }

    input,
    textarea {
      padding: 0.5rem;
      margin-bottom: 1rem;
      border: 1px solid #3a3a3a;
      border-radius: 4px;
      font-size: 1rem;
      background-color: #2a2a2a;
      color: #e0e0e0;
    }

    textarea {
      resize: vertical;
      min-height: 100px;
    }

    input[type="submit"] {
      background-color: #4CAF50;
      color: white;
      border: none;
      padding: 0.75rem;
      font-size: 1rem;
      cursor: pointer;
      transition: background-color 0.3s ease;
    }

    input[type="submit"]:hover {
      background-color: #45a049;
    }

    a {
      color: #fff;
      text-decoration-line: none;
    }

    hr {
      margin-top: 17px;
      margin-bottom: 17px;
    }

    iframe {
      border: none;
      width: 100%;
    }

    #sidebar {
      height: 100dvh;
      background-color: #333;
      color: #fff;
      padding: 15px;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
    }

    #sidebar .user-info {
      margin-top: 20px;
    }

    .imgs {
      max-width: 100%;
      height: auto;
      max-height: 100px;
      border-radius: 100px;
      margin-top: 20px;
    }

    .icon-button {
      display: inline-block;
      padding: 10px;
      border-radius: 30%;
      transition: background-color 0.3s;
    }

    .icon-button.clicked {
      background-color: rgba(255, 255, 255, 0.1);
    }

    .icon-button:hover {
      background-color: rgba(255, 255, 255, 0.1);
    }

    .kore {
      background-color: rgba(255, 255, 255, 0.1);
    }

    .hey {
      font-size: 20px;
    }
  </style>
</head>

<body>
  <div id="sidebar">
    <div class="title-bar">
    </div>

    <div class="user-info">
      <a href="" id="home_button" class="icon-button kore"><i class="fa-regular fa-square-plus hey"></i></a>
      <br><br>
      <a href="../service_del/" id="settings_button" class="icon-button"><i class="fa-solid fa-trash hey"></i></a>
    </div>
  </div>

  <div class="container">
    <h2>連携サービスの追加</h2>
    <p>連携サービスの追加を行える場所です。現在ログインされているアカウント（<?php echo $name; ?>）を使用して作成されます。</p>
    <form action="" method="post">
      <label for="name">サービス名:</label>
      <input type="text" id="name" name="name" required>

      <label for="message">サービスの説明:</label>
      <textarea id="message" name="message" rows="4" required></textarea>

      <label for="icon">Icon URL:</label>
      <input type="text" id="icon" name="icon" required>

      <label for="subject">Authentication URL:</label>
      <input type="text" id="authentication" name="authentication" required>

      <label for="subject">Terms URL:</label>
      <input type="text" id="Terms" name="Terms" required>

      <label for="subject">Privacy URL:</label>
      <input type="text" id="Privacy" name="Privacy" required>

      <label for="subject">Service URL:</label>
      <input type="text" id="Service" name="Service" required>

      <?php if (isset($error_message)): ?>
        <div style="color: red;">
          <strong><?php echo htmlspecialchars($error_message); ?></strong>
        </div>
      <?php endif; ?>

      <?php if (isset($success_message)): ?>
        <div style="color: green;">
          <strong><?php echo htmlspecialchars($success_message); ?></strong>
        </div>
      <?php endif; ?>

      <input type="submit" value="送信">
    </form>
  </div>
</body>

</html>