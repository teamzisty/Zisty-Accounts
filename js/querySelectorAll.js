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
    if (e.key === 'Backspace') {
      if (input.value === '' && index > 0) {
        inputs[index - 1].focus();
      } else {
        input.value = '';
      }
    }
  });
});