(() => {
  const OTP_SELECTOR =
    'input[autocomplete="one-time-code"], input[name*="OneTimeCode"], input[name*="VerificationCode"], input[name="Code"]';
  const PHONE_SELECTOR = 'input[type="tel"], input.phone-input-control';

  const init = () => {
    document.querySelectorAll('.account-form').forEach(enhanceForm);
    scrollToFirstServerError();
    window.addEventListener('pageshow', onPageShow);
  };

  const onPageShow = (event) => {
    document.querySelectorAll('.account-form button[type="submit"]').forEach((button) => {
      setSubmitBusy(button, false);
    });
  };

  const enhanceForm = (form) => {
    if (form.dataset.accountFormEnhanced === 'true') {
      return;
    }

    form.dataset.accountFormEnhanced = 'true';
    const $form = window.jQuery ? window.jQuery(form) : null;
    const validator = $form && $form.data('validator');

    form.querySelectorAll('input, select, textarea').forEach((field) => {
      field.addEventListener('blur', () => validateField($form, field));
      field.addEventListener('input', () => onFieldInput($form, field, form));
    });

    form.querySelectorAll(PHONE_SELECTOR).forEach((field) => {
      field.addEventListener('input', () => sanitizePhoneInput(field));
    });

    form.querySelectorAll(OTP_SELECTOR).forEach((field) => {
      field.addEventListener('input', () => sanitizeOtpInput(field));
      field.addEventListener('paste', (event) => onOtpPaste(event, field));
    });

    setupPasswordMatchHints(form);

    form.addEventListener('submit', (event) => {
      if ($form && typeof $form.valid === 'function' && !$form.valid()) {
        event.preventDefault();
        event.stopPropagation();
        focusFirstInvalid(form);
        shakeInvalidGroups(form);
        return;
      }

      const submitter = event.submitter;
      if (submitter && submitter.type === 'submit') {
        setSubmitBusy(submitter, true);
      }
    }, { capture: false });
  };

  const validateField = ($form, field) => {
    if (!$form || !$form.length) {
      return;
    }

    const validator = $form.data('validator');
    if (!validator) {
      return;
    }

    window.jQuery(field).valid();
  };

  const onFieldInput = ($form, field, form) => {
    if ($form && $form.length) {
      const validator = $form.data('validator');
      if (validator && field.classList.contains('input-validation-error')) {
        window.jQuery(field).valid();
      }
    }

    updatePasswordMatchHint(form, field);
  };

  const sanitizePhoneInput = (field) => {
    const raw = field.value.replace(/[^\d+]/g, '');
    if (raw.startsWith('+91')) {
      field.value = raw.slice(0, 13);
      return;
    }

    if (raw.startsWith('+')) {
      field.value = raw.slice(0, 13);
      return;
    }

    field.value = raw.replace(/\D/g, '').slice(0, 10);
  };

  const sanitizeOtpInput = (field) => {
    const maxLength = field.maxLength > 0 ? field.maxLength : 6;
    field.value = field.value.replace(/\D/g, '').slice(0, maxLength);
  };

  const onOtpPaste = (event, field) => {
    event.preventDefault();
    const pasted = (event.clipboardData || window.clipboardData)
      .getData('text')
      .replace(/\D/g, '');
    const maxLength = field.maxLength > 0 ? field.maxLength : 6;
    field.value = pasted.slice(0, maxLength);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  };

  const setupPasswordMatchHints = (form) => {
    const confirmField = form.querySelector('input[name*="ConfirmPassword"]');
    const passwordField =
      form.querySelector('input[name*="NewPassword"]') ||
      form.querySelector('input[name*="Password"]:not([name*="Confirm"])');

    if (!confirmField || !passwordField) {
      return;
    }

    let hint = confirmField.closest('.form-group')?.querySelector('.password-match-hint');
    if (!hint) {
      hint = document.createElement('span');
      hint.className = 'password-match-hint';
      hint.setAttribute('aria-live', 'polite');
      confirmField.closest('.form-group')?.appendChild(hint);
    }

    hint.dataset.passwordHint = 'true';
    updatePasswordMatchHint(form, confirmField);
  };

  const updatePasswordMatchHint = (form, field) => {
    if (!field.name.includes('ConfirmPassword') && !field.name.includes('Password')) {
      return;
    }

    const confirmField = form.querySelector('input[name*="ConfirmPassword"]');
    const passwordField =
      form.querySelector('input[name*="NewPassword"]') ||
      form.querySelector('input[name*="Password"]:not([name*="Confirm"])');

    if (!confirmField || !passwordField) {
      return;
    }

    const hint = confirmField.closest('.form-group')?.querySelector('.password-match-hint');
    if (!hint) {
      return;
    }

    if (!confirmField.value) {
      hint.textContent = '';
      hint.className = 'password-match-hint';
      return;
    }

    if (passwordField.value === confirmField.value) {
      hint.textContent = 'Passwords match';
      hint.className = 'password-match-hint password-match-hint--match';
      return;
    }

    hint.textContent = 'Passwords do not match';
    hint.className = 'password-match-hint password-match-hint--mismatch';
  };

  const focusFirstInvalid = (form) => {
    const invalid =
      form.querySelector('.input-validation-error') ||
      form.querySelector('[aria-invalid="true"]');

    if (invalid) {
      invalid.focus();
    }
  };

  const shakeInvalidGroups = (form) => {
    form.querySelectorAll('.form-group').forEach((group) => {
      group.classList.remove('form-group--invalid');
    });

    form.querySelectorAll('.input-validation-error').forEach((field) => {
      field.closest('.form-group')?.classList.add('form-group--invalid');
    });
  };

  const scrollToFirstServerError = () => {
    const target =
      document.querySelector('.validation-summary-errors') ||
      document.querySelector('.validation-error:not(:empty)') ||
      document.querySelector('.field-validation-error:not(:empty)');

    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      const field = target.previousElementSibling;
      if (field && field.matches('input, select, textarea')) {
        field.focus();
      }
    }
  };

  const setSubmitBusy = (button, isBusy) => {
    if (isBusy) {
      button.setAttribute('aria-busy', 'true');
      button.classList.add('btn-continue--busy');
      return;
    }

    button.removeAttribute('aria-busy');
    button.classList.remove('btn-continue--busy');
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
