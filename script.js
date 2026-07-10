/* ==========================================================
   WI-FI SECURITY ANALYZER — SCRIPT.JS
   Handles: form data collection, score calculation,
   report generation, random simulation, reset, and
   animated UI updates.
========================================================== */

// ---------- DOM REFERENCES ----------
const ssidInput = document.getElementById('ssid');
const routerTypeSelect = document.getElementById('routerType');
const encryptionSelect = document.getElementById('encryption');
const firmwareSelect = document.getElementById('firmware');

const pwStrengthSlider = document.getElementById('pwStrength');
const pwStrengthLabel = document.getElementById('pwStrengthLabel');
const pwLengthSlider = document.getElementById('pwLength');
const pwLengthLabel = document.getElementById('pwLengthLabel');

const hiddenNetworkToggle = document.getElementById('hiddenNetwork');
const macFilteringToggle = document.getElementById('macFiltering');
const firewallToggle = document.getElementById('firewall');
const wpsToggle = document.getElementById('wps');

const analyzeBtn = document.getElementById('analyzeBtn');
const randomBtn = document.getElementById('randomBtn');
const resetBtn = document.getElementById('resetBtn');

const scoreProgress = document.getElementById('scoreProgress');
const scoreNumber = document.getElementById('scoreNumber');
const scoreStatus = document.getElementById('scoreStatus');

const reportSection = document.getElementById('reportSection');
const summaryList = document.getElementById('summaryList');
const strengthList = document.getElementById('strengthList');
const warningList = document.getElementById('warningList');
const recommendList = document.getElementById('recommendList');

// Password strength labels mapped to slider value (0-4)
const PASSWORD_STRENGTH_LABELS = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'];

// Circle circumference for the score meter (r=85 -> 2 * PI * 85 ≈ 534)
const CIRCLE_CIRCUMFERENCE = 534;

/* ==========================================================
   LIVE LABEL UPDATES FOR SLIDERS
========================================================== */
pwStrengthSlider.addEventListener('input', () => {
  pwStrengthLabel.textContent = PASSWORD_STRENGTH_LABELS[pwStrengthSlider.value];
});

pwLengthSlider.addEventListener('input', () => {
  pwLengthLabel.textContent = pwLengthSlider.value;
});

/* ==========================================================
   SCORE CALCULATION ENGINE
========================================================== */
function calculateSecurityScore(config) {
  let score = 0;
  const strengths = [];
  const warnings = [];
  const recommendations = [];

  // --- Encryption scoring ---
  const encryptionScores = {
    'WPA3': 35,
    'WPA2-AES': 30,
    'WPA2-TKIP': 20,
    'WPA': 10,
    'WEP': 5,
    'Open': 0
  };
  score += encryptionScores[config.encryption];

  if (config.encryption === 'WPA3' || config.encryption === 'WPA2-AES') {
    strengths.push(`Strong Encryption (${config.encryption})`);
  } else if (config.encryption === 'WPA2-TKIP') {
    warnings.push('Your network uses WPA2-TKIP, an older and weaker encryption mode.');
    recommendations.push('Upgrade to WPA2-AES or WPA3 encryption.');
  } else if (config.encryption === 'WPA') {
    warnings.push('Your network uses outdated WPA encryption.');
    recommendations.push('Upgrade to WPA3 encryption.');
  } else if (config.encryption === 'WEP') {
    warnings.push('WEP encryption is critically insecure and easily cracked.');
    recommendations.push('Replace WEP with WPA3 encryption immediately.');
  } else if (config.encryption === 'Open') {
    warnings.push('Open networks allow unauthorized access to anyone nearby.');
    recommendations.push('Enable WPA3 encryption to secure your network.');
  }

  // --- Password strength scoring ---
  const strengthScores = [0, 5, 10, 15, 20]; // Very Weak..Very Strong
  score += strengthScores[config.pwStrength];

  if (config.pwStrength >= 3) {
    strengths.push('Strong Password Strength');
  } else {
    warnings.push('Your password strength is below recommended levels.');
    recommendations.push('Choose a stronger, more complex password.');
  }

  // --- Password length scoring ---
  let lengthScore = 0;
  if (config.pwLength >= 25) lengthScore = 10;
  else if (config.pwLength >= 15) lengthScore = 7;
  else if (config.pwLength >= 8) lengthScore = 4;
  else lengthScore = 0;
  score += lengthScore;

  if (config.pwLength < 8) {
    warnings.push('Password length is too short, making it vulnerable to brute-force attacks.');
    recommendations.push('Use a longer password (at least 15 characters).');
  } else if (config.pwLength >= 15) {
    strengths.push('Sufficient Password Length');
  }

  // --- Security features ---
  if (config.hiddenNetwork) {
    score += 5;
    strengths.push('Hidden Network Enabled');
  }

  if (config.macFiltering) {
    score += 5;
    strengths.push('MAC Filtering Enabled');
  } else {
    recommendations.push('Enable MAC filtering for an extra access-control layer.');
  }

  if (config.firewall) {
    score += 5;
    strengths.push('Firewall Enabled');
  } else {
    warnings.push('Firewall is disabled, leaving the network exposed to inbound threats.');
    recommendations.push('Enable router firewall.');
  }

  if (config.firmware === 'Updated') {
    score += 5;
    strengths.push('Firmware Updated');
  } else {
    score -= 10;
    warnings.push('Outdated firmware may contain unpatched security vulnerabilities.');
    recommendations.push('Update router firmware.');
  }

  // --- Risk factors ---
  if (config.wps) {
    score -= 10;
    warnings.push('WPS enabled increases brute-force risks.');
    recommendations.push('Disable WPS.');
  }

  // Clamp score between 0 and 100
  score = Math.max(0, Math.min(100, score));

  return { score, strengths, warnings, recommendations };
}

/* ==========================================================
   COLLECT CURRENT FORM CONFIGURATION
========================================================== */
function getCurrentConfig() {
  return {
    ssid: ssidInput.value.trim() || 'Unnamed Network',
    routerType: routerTypeSelect.value,
    encryption: encryptionSelect.value,
    firmware: firmwareSelect.value,
    pwStrength: parseInt(pwStrengthSlider.value, 10),
    pwLength: parseInt(pwLengthSlider.value, 10),
    hiddenNetwork: hiddenNetworkToggle.checked,
    macFiltering: macFilteringToggle.checked,
    firewall: firewallToggle.checked,
    wps: wpsToggle.checked
  };
}

/* ==========================================================
   ANIMATE THE CIRCULAR SCORE METER + NUMBER
========================================================== */
function animateScore(targetScore) {
  // Update circle stroke offset
  const offset = CIRCLE_CIRCUMFERENCE - (CIRCLE_CIRCUMFERENCE * targetScore) / 100;
  scoreProgress.style.strokeDashoffset = offset;

  // Determine color + status label based on score range
  let colorVar, statusText, statusClass;
  if (targetScore >= 90) {
    colorVar = 'var(--color-excellent)';
    statusText = 'Excellent';
    statusClass = 'status-excellent';
  } else if (targetScore >= 70) {
    colorVar = 'var(--color-good)';
    statusText = 'Good';
    statusClass = 'status-good';
  } else if (targetScore >= 40) {
    colorVar = 'var(--color-moderate)';
    statusText = 'Moderate';
    statusClass = 'status-moderate';
  } else {
    colorVar = 'var(--color-weak)';
    statusText = 'Weak';
    statusClass = 'status-weak';
  }

  scoreProgress.style.stroke = colorVar;
  scoreStatus.textContent = statusText;
  scoreStatus.className = 'score-status ' + statusClass;

  // Animate the number counting up
  let current = 0;
  const duration = 1000;
  const stepTime = 16;
  const totalSteps = duration / stepTime;
  const increment = targetScore / totalSteps;

  const counter = setInterval(() => {
    current += increment;
    if (current >= targetScore) {
      current = targetScore;
      clearInterval(counter);
    }
    scoreNumber.textContent = Math.round(current);
  }, stepTime);
}

/* ==========================================================
   BUILD THE DETAILED REPORT
========================================================== */
function buildReport(config, result) {
  // --- Network Summary ---
  summaryList.innerHTML = '';
  const summaryItems = [
    `SSID: ${config.ssid}`,
    `Router Type: ${config.routerType}`,
    `Encryption: ${config.encryption}`,
    `Password Rating: ${PASSWORD_STRENGTH_LABELS[config.pwStrength]}`
  ];
  summaryItems.forEach(text => {
    const li = document.createElement('li');
    li.textContent = text;
    summaryList.appendChild(li);
  });

  // --- Strengths ---
  strengthList.innerHTML = '';
  if (result.strengths.length === 0) {
    strengthList.appendChild(createListItem('No notable security strengths detected.'));
  } else {
    result.strengths.forEach(s => strengthList.appendChild(createListItem('✔ ' + s)));
  }

  // --- Warnings ---
  warningList.innerHTML = '';
  if (result.warnings.length === 0) {
    warningList.appendChild(createListItem('✔ No major warnings detected.'));
  } else {
    result.warnings.forEach(w => warningList.appendChild(createListItem('⚠ ' + w)));
  }

  // --- Recommendations ---
  recommendList.innerHTML = '';
  if (result.recommendations.length === 0) {
    recommendList.appendChild(createListItem('Your configuration already follows best practices.'));
  } else {
    result.recommendations.forEach(r => recommendList.appendChild(createListItem('→ ' + r)));
  }

  reportSection.style.display = 'block';
  reportSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Helper to create a <li> element
function createListItem(text) {
  const li = document.createElement('li');
  li.textContent = text;
  return li;
}

/* ==========================================================
   MAIN ANALYZE HANDLER
========================================================== */
function analyzeNetwork() {
  const config = getCurrentConfig();
  const result = calculateSecurityScore(config);
  animateScore(result.score);
  buildReport(config, result);
}

analyzeBtn.addEventListener('click', analyzeNetwork);

/* ==========================================================
   RANDOM NETWORK GENERATOR
========================================================== */
function generateRandomNetwork() {
  const ssidPrefixes = ['Home', 'Office', 'Cafe', 'Studio', 'Garage', 'Loft', 'Skyline', 'Nimbus', 'Falcon', 'Orbit'];
  const ssidSuffixes = ['Network', 'WiFi', '5G', 'Guest', 'Secure', 'Zone', 'Hub', 'Link'];
  const encryptions = ['WPA3', 'WPA2-AES', 'WPA2-TKIP', 'WPA', 'WEP', 'Open'];
  const routerTypes = ['Home Router', 'Enterprise Router', 'Public Wi-Fi', 'Mobile Hotspot', 'Custom Network'];
  const firmwareOptions = ['Updated', 'Outdated'];

  // Random SSID
  const randomSSID =
    ssidPrefixes[Math.floor(Math.random() * ssidPrefixes.length)] +
    '_' +
    ssidSuffixes[Math.floor(Math.random() * ssidSuffixes.length)] +
    Math.floor(Math.random() * 100);

  ssidInput.value = randomSSID;
  routerTypeSelect.value = routerTypes[Math.floor(Math.random() * routerTypes.length)];
  encryptionSelect.value = encryptions[Math.floor(Math.random() * encryptions.length)];
  firmwareSelect.value = firmwareOptions[Math.floor(Math.random() * firmwareOptions.length)];

  const randomPwStrength = Math.floor(Math.random() * 5);
  pwStrengthSlider.value = randomPwStrength;
  pwStrengthLabel.textContent = PASSWORD_STRENGTH_LABELS[randomPwStrength];

  const randomPwLength = Math.floor(Math.random() * 31);
  pwLengthSlider.value = randomPwLength;
  pwLengthLabel.textContent = randomPwLength;

  hiddenNetworkToggle.checked = Math.random() > 0.5;
  macFilteringToggle.checked = Math.random() > 0.5;
  firewallToggle.checked = Math.random() > 0.5;
  wpsToggle.checked = Math.random() > 0.5;

  // Automatically re-run the analysis with the new random config
  analyzeNetwork();
}

randomBtn.addEventListener('click', generateRandomNetwork);

/* ==========================================================
   RESET ANALYZER
========================================================== */
function resetAnalyzer() {
  ssidInput.value = 'MyHomeNetwork';
  routerTypeSelect.value = 'Home Router';
  encryptionSelect.value = 'WPA2-AES';
  firmwareSelect.value = 'Updated';

  pwStrengthSlider.value = 2;
  pwStrengthLabel.textContent = PASSWORD_STRENGTH_LABELS[2];

  pwLengthSlider.value = 12;
  pwLengthLabel.textContent = '12';

  hiddenNetworkToggle.checked = false;
  macFilteringToggle.checked = false;
  firewallToggle.checked = true;
  wpsToggle.checked = true;

  // Reset score display
  scoreProgress.style.strokeDashoffset = CIRCLE_CIRCUMFERENCE;
  scoreProgress.style.stroke = 'var(--primary-color)';
  scoreNumber.textContent = '0';
  scoreStatus.textContent = 'Awaiting Analysis';
  scoreStatus.className = 'score-status';

  reportSection.style.display = 'none';
}

resetBtn.addEventListener('click', resetAnalyzer);

/* ==========================================================
   INITIAL SETUP ON PAGE LOAD
========================================================== */
window.addEventListener('DOMContentLoaded', () => {
  // Initialize the score circle at 0
  scoreProgress.style.strokeDashoffset = CIRCLE_CIRCUMFERENCE;
});
