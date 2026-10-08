// EVChargeSecure - Main Client Script

document.addEventListener("DOMContentLoaded", function () {
  // 1. Quick credential fill for demonstration
  window.fillLogin = function (user, pass) {
    const userInput = document.getElementById("username");
    const passInput = document.getElementById("password");
    if (userInput && passInput) {
      userInput.value = user;
      passInput.value = pass;
    }
  };

  // 2. Active charging session live meter simulation
  const meterElem = document.getElementById("liveEnergyKwh");
  const costElem = document.getElementById("liveCostInr");
  const powerElem = document.getElementById("livePowerKw");

  if (meterElem && powerElem && costElem) {
    const powerKw = parseFloat(powerElem.dataset.power || "60.0");
    const tariff = parseFloat(costElem.dataset.tariff || "18.5");
    let currentKwh = parseFloat(meterElem.dataset.initial || "12.5");

    // Increment simulated energy every 2 seconds
    setInterval(function () {
      // Simulate energy accumulation: ~ (power / 3600) * 2 seconds * factor
      const increment = (powerKw / 3600) * 2 * 0.85;
      currentKwh += increment;
      const currentCost = currentKwh * tariff;

      meterElem.textContent = currentKwh.toFixed(2);
      costElem.textContent = "₹" + currentCost.toFixed(2);
    }, 2000);
  }

  // 3. Helper to fetch CSRF token from page meta or form
  window.getCSRFToken = function () {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) return meta.getAttribute("content");
    const input = document.querySelector('input[name="csrf_token"]');
    if (input) return input.value;
    return "";
  };
});
