// EVChargeSecure - Security Laboratory Interactive Comparison Script

async function runDemo(endpoint, payload, outputElementId) {
  const outputBox = document.getElementById(outputElementId);
  if (!outputBox) return;

  outputBox.textContent = "Executing request...";
  try {
    const csrfToken = window.getCSRFToken();
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    outputBox.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    outputBox.textContent = "Error executing lab demonstration: " + err.message;
  }
}

// 1. SQLi Demo
function testSQLi(mode) {
  const inputVal = document.getElementById("sqliInput").value;
  runDemo("/security-lab/demo/sqli", { mode: mode, input: inputVal }, "sqliOutput");
}

// 2. Password Storage Demo
function testPassword(mode) {
  const inputVal = document.getElementById("passInput").value;
  runDemo("/security-lab/demo/password-storage", { mode: mode, password: inputVal }, "passOutput");
}

// 3. Authorization Demo
function testAuthz(mode) {
  const roleVal = document.getElementById("authzRole").value;
  runDemo("/security-lab/demo/authorization", { mode: mode, role: roleVal }, "authzOutput");
}

// 4. Payment Tampering Demo
function testPayment(mode) {
  const clientAmt = document.getElementById("paymentInput").value;
  runDemo("/security-lab/demo/payment-tampering", { mode: mode, client_amount: clientAmt }, "paymentOutput");
}

// 5. Race Condition Demo
function testRace(mode) {
  const pointId = document.getElementById("racePointId").value;
  runDemo("/security-lab/demo/race-condition", { mode: mode, point_id: pointId }, "raceOutput");
}

// 6. IDOR Demo
function testIDOR(mode) {
  const sessionId = document.getElementById("idorSessionId").value;
  runDemo("/security-lab/demo/idor", { mode: mode, session_id: sessionId }, "idorOutput");
}
