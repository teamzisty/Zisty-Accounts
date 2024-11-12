<?php
session_start();

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// データベース接続
$mysqli = new mysqli("", "", "", "");
if ($mysqli->connect_error) {
  die('データベースの接続に失敗しました: ' . $mysqli->connect_error);
  exit();
}

// メッセージの初期化
$error_message = '';
$success_message = '';

// ユーザー情報を取得
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

// ユーザー名、名前を取得
$query = "SELECT username, name FROM users WHERE id = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("i", $userId);
$stmt->execute();
$stmt->bind_result($username, $name);
$stmt->fetch();
$stmt->close();

// ユーザーが作成したサービスを取得
$query = "SELECT service_id, name, description, icon_url FROM link_services WHERE username = ?";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

// サービス削除処理
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['remove_service'])) {
  $service_id = $_POST['service_id'];

  // サービス削除
  $stmt = $mysqli->prepare("DELETE FROM link_services WHERE service_id = ? AND username = ?");
  $stmt->bind_param("ss", $service_id, $username);

  if ($stmt->execute()) {
    $success_message = "サービスが正常に削除されました。";
  } else {
    $error_message = "エラーが発生しました: " . $stmt->error;
  }

  $stmt->close();

  // サービス一覧を再取得
  $stmt = $mysqli->prepare($query);
  $stmt->bind_param("s", $username);
  $stmt->execute();
  $result = $stmt->get_result();
}

$mysqli->close();
?>

<!DOCTYPE html>
<html lang="ja">

<head>
  <meta charset="UTF-8">
  <title>Service Del</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
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

    .box {
      display: flex;
      border-radius: 15px;
      overflow: hidden;
      background-color: #64646452;
      margin-top: 14px;
      margin-bottom: 10px;
      transition: 0.5s;
    }

    .box:hover {
      background-color: #44444452;
    }

    .image-container {
      max-width: 100px;
      flex: 1;
      overflow: hidden;
      display: flex;
      justify-content: center;
      align-items: center;
      text-align: center;
    }

    .images {
      max-width: 70%;
      max-height: 50%;
      width: auto;
      height: auto;
      object-fit: contain;
      margin: auto;
    }

    .text-container {
      flex: 4;
      padding: 20px;
      background-color: #202325;
    }

    .service {
      font-size: 22px;
      margin: 0;
      margin-bottom: -10px;
      font-weight: bold;
    }

    .moji {
      font-size: 20px;
      color: #b1b1b1;
    }

    button {
      background-color: #202325;
      color: #ff3f3f;
      cursor: pointer;
      border: none;
      text-decoration: none;
      font-size: 20px;
      text-align: left;
      margin-left: -3px;

      transition: 0.5s;

    }

    button:hover {
      color: #ff0000;
    }

    .fa-circle-minus {
      margin-right: 5px;
    }
  </style>
</head>

<body>
  <div id="sidebar">
    <div class="title-bar">
    </div>

    <div class="user-info">
      <a href="../service_add/" id="home_button" class="icon-button"><i class="fa-regular fa-square-plus hey"></i></a>
      <br><br>
      <a href="" id="settings_button" class="icon-button kore"><i class="fa-solid fa-trash hey"></i></a>
    </div>
  </div>

  <div class="container">
    <h2>連携サービスの削除</h2>
    <p>連携サービスの削除を行える場所です。現在ログインされているアカウント（<?php echo $name; ?>）を使用して削除されます。
    </p>

    <?php if ($error_message): ?>
      <div style="color: red;">
        <strong><?php echo htmlspecialchars($error_message); ?></strong>
      </div>
    <?php endif; ?>

    <?php if ($success_message): ?>
      <div style="color: green;">
        <strong><?php echo htmlspecialchars($success_message); ?></strong>
      </div>
    <?php endif; ?>
    
    <?php while ($row = $result->fetch_assoc()): ?>
      <div class="box">
        <div class="image-container">
          <img src="<?php echo htmlspecialchars($row['icon_url']); ?>" class="images" alt="<?php echo htmlspecialchars($row['name']); ?>">
        </div>
        <div class="text-container">
          <p class="service"><?php echo htmlspecialchars($row['name']); ?></p>
          <p class="moji"><?php echo htmlspecialchars($row['description']); ?></p>
          <form method="POST" action="">
            <input type="hidden" name="service_id" value="<?php echo htmlspecialchars($row['service_id']); ?>">
            <button type="submit" name="remove_service" class="button">
              <i class="fa-solid fa-circle-minus"></i> サービス解除
            </button>
          </form>
        </div>
      </div>
    <?php endwhile; ?>

    </main>
  </div>
</body>

</html>