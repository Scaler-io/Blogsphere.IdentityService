(() => {
  const init = () => {
    document.querySelectorAll('[data-otp-input]').forEach(setupOtpGroup);
    document.querySelectorAll('[data-password-toggle]').forEach(setupPasswordToggle);
  };

  const setupOtpGroup = (group) => {
    const digits = Array.from(group.querySelectorAll('[data-otp-digit]'));
    const targetId = group.getAttribute('data-otp-target');
    const hidden = targetId ? document.getElementById(targetId) : group.querySelector('.blogsphere-otp__hidden');
    if (!digits.length || !hidden) {
      return;
    }

    const syncHidden = () => {
      hidden.value = digits.map((d) => d.value).join('');
    };

    digits.forEach((digit, index) => {
      digit.addEventListener('input', () => {
        digit.value = digit.value.replace(/\D/g, '').slice(-1);
        syncHidden();
        if (digit.value && index < digits.length - 1) {
          digits[index + 1].focus();
        }
      });

      digit.addEventListener('keydown', (event) => {
        if (event.key === 'Backspace' && !digit.value && index > 0) {
          digits[index - 1].focus();
        }
        if (event.key === 'ArrowLeft' && index > 0) {
          digits[index - 1].focus();
        }
        if (event.key === 'ArrowRight' && index < digits.length - 1) {
          digits[index + 1].focus();
        }
      });

      digit.addEventListener('paste', (event) => {
        event.preventDefault();
        const pasted = (event.clipboardData || window.clipboardData)
          .getData('text')
          .replace(/\D/g, '')
          .slice(0, 6);
        pasted.split('').forEach((char, i) => {
          if (digits[i]) {
            digits[i].value = char;
          }
        });
        syncHidden();
        const focusIndex = Math.min(pasted.length, digits.length - 1);
        digits[focusIndex].focus();
      });
    });

    const form = group.closest('form');
    if (form) {
      form.addEventListener('submit', syncHidden);
    }
  };

  const setupPasswordToggle = (button) => {
    const wrap = button.closest('.blogsphere-field__control-wrap');
    const input = wrap ? wrap.querySelector('input[type="password"], input[type="text"].blogsphere-field__input') : null;
    const showIcon = button.querySelector('[data-icon-show]');
    const hideIcon = button.querySelector('[data-icon-hide]');
    if (!input) {
      return;
    }

    button.addEventListener('click', () => {
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      if (showIcon) showIcon.hidden = isPassword;
      if (hideIcon) hideIcon.hidden = !isPassword;
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
