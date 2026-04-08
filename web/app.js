const page = document.body.dataset.page;
const statusBar = document.getElementById("statusBar");

const STORAGE_KEYS = {
  publicKey: "elsign_2048_public_key",
  privateKey: "elsign_2048_private_key",
  ciphertext: "elsign_2048_ciphertext",
};

function setStatus(message, isError = false) {
  statusBar.textContent = message;
  statusBar.style.color = isError ? "#8b1e1e" : "#2f7069";
}

function normalizeMessage(value) {
  return value.toUpperCase().replace(/[^A-Z]/g, "");
}

function formatJson(data) {
  return JSON.stringify(data, null, 2);
}

function parseJsonFromText(text, fieldName) {
  const raw = text.trim();
  if (!raw) {
    throw new Error(`Ban chua nhap ${fieldName}.`);
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${fieldName} phai la JSON hop le.`);
  }
}

async function postJson(url, payload = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Yeu cau that bai.");
  }
  return data;
}

function downloadText(filename, content) {
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function saveToStorage(key, value) {
  localStorage.setItem(key, value);
}

function loadFromStorage(key) {
  return localStorage.getItem(key) || "";
}

function setupReceiverPage() {
  const publicKeyArea = document.getElementById("publicKeyArea");
  const privateKeyArea = document.getElementById("privateKeyArea");
  const decryptPrivateKeyArea = document.getElementById("decryptPrivateKeyArea");
  const decryptCiphertextArea = document.getElementById("decryptCiphertextArea");
  const plaintextArea = document.getElementById("plaintextArea");

  const storedPublicKey = loadFromStorage(STORAGE_KEYS.publicKey);
  const storedPrivateKey = loadFromStorage(STORAGE_KEYS.privateKey);
  const storedCiphertext = loadFromStorage(STORAGE_KEYS.ciphertext);
  if (storedPublicKey) {
    publicKeyArea.value = storedPublicKey;
  }
  if (storedPrivateKey) {
    privateKeyArea.value = storedPrivateKey;
    decryptPrivateKeyArea.value = storedPrivateKey;
  }
  if (storedCiphertext) {
    decryptCiphertextArea.value = storedCiphertext;
  }

  document.getElementById("generateKeysBtn").addEventListener("click", async () => {
    try {
      const data = await postJson("/api/generate-keys");
      const publicKeyText = formatJson(data.public_key);
      const privateKeyText = formatJson(data.private_key);
      publicKeyArea.value = publicKeyText;
      privateKeyArea.value = privateKeyText;
      decryptPrivateKeyArea.value = privateKeyText;
      saveToStorage(STORAGE_KEYS.publicKey, publicKeyText);
      saveToStorage(STORAGE_KEYS.privateKey, privateKeyText);
      setStatus("Da tao cap khoa moi cho ben nhan.");
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  document.getElementById("downloadPublicBtn").addEventListener("click", () => {
    if (!publicKeyArea.value.trim()) {
      setStatus("Chua co khoa cong khai de tai.", true);
      return;
    }
    downloadText("receiver.public.json", publicKeyArea.value);
    setStatus("Da tai khoa cong khai.");
  });

  document.getElementById("downloadPrivateBtn").addEventListener("click", () => {
    if (!privateKeyArea.value.trim()) {
      setStatus("Chua co khoa bi mat de tai.", true);
      return;
    }
    downloadText("receiver.private.json", privateKeyArea.value);
    setStatus("Da tai khoa bi mat.");
  });

  document.getElementById("sendPublicKeyBtn").addEventListener("click", () => {
    if (!publicKeyArea.value.trim()) {
      setStatus("Chua co khoa cong khai de chuyen.", true);
      return;
    }
    saveToStorage(STORAGE_KEYS.publicKey, publicKeyArea.value);
    setStatus("Da chuyen khoa cong khai sang trang ben gui trong trinh duyet nay.");
  });

  document.getElementById("loadCipherBtn").addEventListener("click", () => {
    const cipher = loadFromStorage(STORAGE_KEYS.ciphertext);
    if (!cipher) {
      setStatus("Chua co ban ma nao tu ben gui.", true);
      return;
    }
    decryptCiphertextArea.value = cipher;
    setStatus("Da nap ban ma tu ben gui.");
  });

  document.getElementById("decryptBtn").addEventListener("click", async () => {
    try {
      const privateKey = parseJsonFromText(decryptPrivateKeyArea.value, "khoa bi mat");
      const ciphertext = parseJsonFromText(decryptCiphertextArea.value, "ban ma");
      const data = await postJson("/api/decrypt", { private_key: privateKey, ciphertext });
      plaintextArea.value = data.plaintext;
      saveToStorage(STORAGE_KEYS.privateKey, decryptPrivateKeyArea.value);
      saveToStorage(STORAGE_KEYS.ciphertext, decryptCiphertextArea.value);
      setStatus("Ben nhan da giai ma thanh cong.");
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  document.getElementById("copyPlaintextBtn").addEventListener("click", async () => {
    if (!plaintextArea.value.trim()) {
      setStatus("Chua co ket qua giai ma de sao chep.", true);
      return;
    }
    try {
      await navigator.clipboard.writeText(plaintextArea.value);
      setStatus("Da sao chep thong diep giai ma.");
    } catch {
      setStatus("Khong the sao chep tu dong. Hay sao chep thu cong.", true);
    }
  });
}

function setupSenderPage() {
  const senderMessage = document.getElementById("senderMessage");
  const normalizedPreview = document.getElementById("normalizedPreview");
  const senderPublicKeyArea = document.getElementById("senderPublicKeyArea");
  const ciphertextArea = document.getElementById("ciphertextArea");

  const storedPublicKey = loadFromStorage(STORAGE_KEYS.publicKey);
  const storedCiphertext = loadFromStorage(STORAGE_KEYS.ciphertext);
  if (storedPublicKey) {
    senderPublicKeyArea.value = storedPublicKey;
  }
  if (storedCiphertext) {
    ciphertextArea.value = storedCiphertext;
  }

  senderMessage.addEventListener("input", () => {
    normalizedPreview.value = normalizeMessage(senderMessage.value);
  });

  document.getElementById("loadPublicKeyBtn").addEventListener("click", () => {
    const publicKey = loadFromStorage(STORAGE_KEYS.publicKey);
    if (!publicKey) {
      setStatus("Chua co khoa cong khai nao tu ben nhan.", true);
      return;
    }
    senderPublicKeyArea.value = publicKey;
    setStatus("Da nap khoa cong khai tu ben nhan.");
  });

  document.getElementById("encryptBtn").addEventListener("click", async () => {
    try {
      const message = senderMessage.value;
      const publicKey = parseJsonFromText(senderPublicKeyArea.value, "khoa cong khai");
      const data = await postJson("/api/encrypt", { message, public_key: publicKey });
      normalizedPreview.value = data.normalized;
      ciphertextArea.value = formatJson(data.ciphertext);
      saveToStorage(STORAGE_KEYS.publicKey, senderPublicKeyArea.value);
      saveToStorage(STORAGE_KEYS.ciphertext, ciphertextArea.value);
      setStatus("Ben gui da ma hoa thong diep thanh cong.");
    } catch (error) {
      setStatus(error.message, true);
    }
  });

  document.getElementById("downloadCipherBtn").addEventListener("click", () => {
    if (!ciphertextArea.value.trim()) {
      setStatus("Chua co ban ma de tai.", true);
      return;
    }
    downloadText("cipher.json", ciphertextArea.value);
    setStatus("Da tai ban ma.");
  });

  document.getElementById("sendCipherBtn").addEventListener("click", () => {
    if (!ciphertextArea.value.trim()) {
      setStatus("Chua co ban ma de chuyen.", true);
      return;
    }
    saveToStorage(STORAGE_KEYS.ciphertext, ciphertextArea.value);
    setStatus("Da chuyen ban ma sang trang ben nhan trong trinh duyet nay.");
  });
}

if (page === "receiver") {
  setupReceiverPage();
} else if (page === "sender") {
  setupSenderPage();
}
