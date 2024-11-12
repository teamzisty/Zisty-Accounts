function showDialog(message) {
  const dialog = document.getElementById('notification-message');
  dialog.textContent = message;
  setTimeout(() => {
    document.getElementById('notification').classList.add('show');
  }, 500);
  setTimeout(() => {
    document.getElementById('notification').classList.remove('show');
  }, 6000);
}