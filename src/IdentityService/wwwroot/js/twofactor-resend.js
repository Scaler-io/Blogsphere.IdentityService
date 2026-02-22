(() => {
  const init = () => {
    const btn = document.getElementById("resendBtn");
    const timerSpan = document.getElementById("resendTimer");
    const form = document.getElementById("resendForm");

    if (!btn || !timerSpan || !form) {
      return;
    }

    const cooldownAttr = btn.getAttribute("data-cooldown");
    const cooldown = Number.parseInt(cooldownAttr, 10);
    const cooldownSeconds = Number.isFinite(cooldown) && cooldown > 0 ? cooldown : 30;
    let remaining = cooldownSeconds;
    let intervalId = null;

    const setDisabled = (isDisabled) => {
      if (isDisabled) {
        btn.setAttribute("disabled", "disabled");
      } else {
        btn.removeAttribute("disabled");
      }
    };

    const startCooldown = () => {
      remaining = cooldownSeconds;
      setDisabled(true);
      timerSpan.textContent = `(${remaining}s)`;

      if (intervalId) {
        clearInterval(intervalId);
      }

      intervalId = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
          clearInterval(intervalId);
          intervalId = null;
          setDisabled(false);
          timerSpan.textContent = "";
        } else {
          timerSpan.textContent = `(${remaining}s)`;
        }
      }, 1000);
    };

    form.addEventListener("submit", () => {
      startCooldown();
    });

    startCooldown();
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
