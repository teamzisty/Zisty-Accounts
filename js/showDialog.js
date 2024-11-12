function showDialog(message) {
  const dialog = document.getElementById('notification-message');
  dialog.textContent = message;
  setTimeout(() => {
    document.getElementById('notification').classList.add('show');
  }, 1000);
  setTimeout(() => {
    document.getElementById('notification').classList.remove('show');
  }, 6000);
}

function account_error(message) {
  const dialog = document.getElementById('dialog');
  dialog.textContent = message;
  setTimeout(() => {
    document.getElementById('notification').classList.add('show');
  }, 100);
  setTimeout(() => {
    dialog.classList.remove('show');
  }, 3000);
}