const statusBar = document.getElementById("statusBar");
const publicKeyArea = document.getElementById("publicKeyArea");
const privateKeyArea = document.getElementById("privateKeyArea");
const senderMessage = document.getElementById("senderMessage");
const normalizedPreview = document.getElementById("normalizedPreview");
const senderPublicKeyArea = document.getElementById("senderPublicKeyArea");
const ciphertextArea = document.getElementById("ciphertextArea");
const decryptPrivateKeyArea = document.getElementById("decryptPrivateKeyArea");
const decryptCiphertextArea = document.getElementById("decryptCiphertextArea");
const plaintextArea = document.getElementById("plaintextArea");

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

function parseJsonFromArea(element, fieldName) {
  const raw = element.value.trim();
  if (!raw) {
    throw new Error(`Bạn chưa nhập ${fieldName}.`);
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${fieldName} phải là JSON hợp lệ.`);
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
    throw new Error(data.error || "Yêu cầu thất bại.");
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

senderMessage.addEventListener("input", () => {
  normalizedPreview.value = normalizeMessage(senderMessage.value);
});

document.getElementById("generateKeysBtn").addEventListener("click", async () => {
  try {
    const data = await postJson("/api/generate-keys");
    const publicKeyText = formatJson(data.public_key);
    const privateKeyText = formatJson(data.private_key);
    publicKeyArea.value = publicKeyText;
    privateKeyArea.value = privateKeyText;
    senderPublicKeyArea.value = publicKeyText;
    decryptPrivateKeyArea.value = privateKeyText;
    setStatus("Đã tạo cặp khóa mới cho bên nhận.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("encryptBtn").addEventListener("click", async () => {
  try {
    const message = senderMessage.value;
    const publicKey = parseJsonFromArea(senderPublicKeyArea, "khóa công khai");
    const data = await postJson("/api/encrypt", { message, public_key: publicKey });
    normalizedPreview.value = data.normalized;
    ciphertextArea.value = formatJson(data.ciphertext);
    decryptCiphertextArea.value = formatJson(data.ciphertext);
    setStatus("Bên gửi đã mã hóa thông điệp thành công.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("decryptBtn").addEventListener("click", async () => {
  try {
    const privateKey = parseJsonFromArea(decryptPrivateKeyArea, "khóa bí mật");
    const ciphertext = parseJsonFromArea(decryptCiphertextArea, "bản mã");
    const data = await postJson("/api/decrypt", { private_key: privateKey, ciphertext });
    plaintextArea.value = data.plaintext;
    setStatus("Bên nhận đã giải mã thành công.");
  } catch (error) {
    setStatus(error.message, true);
  }
});

document.getElementById("downloadPublicBtn").addEventListener("click", () => {
  if (!publicKeyArea.value.trim()) {
    setStatus("Chưa có khóa công khai để tải.", true);
    return;
  }
  downloadText("receiver.public.json", publicKeyArea.value);
  setStatus("Đã tải khóa công khai.");
});

document.getElementById("downloadPrivateBtn").addEventListener("click", () => {
  if (!privateKeyArea.value.trim()) {
    setStatus("Chưa có khóa bí mật để tải.", true);
    return;
  }
  downloadText("receiver.private.json", privateKeyArea.value);
  setStatus("Đã tải khóa bí mật.");
});

document.getElementById("downloadCipherBtn").addEventListener("click", () => {
  if (!ciphertextArea.value.trim()) {
    setStatus("Chưa có bản mã để tải.", true);
    return;
  }
  downloadText("cipher.json", ciphertextArea.value);
  setStatus("Đã tải bản mã.");
});

document.getElementById("copyPlaintextBtn").addEventListener("click", async () => {
  if (!plaintextArea.value.trim()) {
    setStatus("Chưa có kết quả giải mã để sao chép.", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(plaintextArea.value);
    setStatus("Đã sao chép thông điệp giải mã.");
  } catch {
    setStatus("Không thể sao chép tự động. Hãy sao chép thủ công.", true);
  }
});
