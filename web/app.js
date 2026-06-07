if (typeof document !== "undefined") {
  const page = document.body.dataset.page;
  const statusBar = document.getElementById("statusBar");
  const progressContainer = document.getElementById("progressContainer");

  const STORAGE_KEYS = {
    receiverPublicKey: "elsign_2048_receiver_public_key",
    receiverPrivateKey: "elsign_2048_receiver_private_key",
    senderPublicKey: "elsign_2048_sender_public_key",
    senderPrivateKey: "elsign_2048_sender_private_key",
    ciphertext: "elsign_2048_ciphertext",
    signature: "elsign_2048_signature",
    signedPackage: "elsign_2048_signed_package",
  };

  function showProgress() {
    if (progressContainer) progressContainer.style.display = "block";
  }

  function hideProgress() {
    if (progressContainer) progressContainer.style.display = "none";
  }

  function setStatus(message, isError = false) {
    if (!statusBar) return;
    statusBar.textContent = message;
    statusBar.style.color = isError ? "var(--error)" : "#bfdbfe";
  }

  function normalizeMessage(value) {
    return value.toUpperCase().replace(/[^A-Z]/g, "");
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result.split(",")[1]);
      reader.onerror = (error) => reject(error);
      reader.readAsDataURL(file);
    });
  }

  function base64ToBlob(base64, mimeType = "application/octet-stream") {
    const byteString = atob(base64);
    const buffer = new ArrayBuffer(byteString.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < byteString.length; i += 1) {
      view[i] = byteString.charCodeAt(i);
    }
    return new Blob([buffer], { type: mimeType || "application/octet-stream" });
  }

  function formatJson(data) {
    return JSON.stringify(data, null, 2);
  }

  function parseJsonFromText(text, fieldName) {
    const raw = text.trim();
    if (!raw) throw new Error(`Ban chua nhap ${fieldName}.`);
    try {
      return JSON.parse(raw);
    } catch {
      throw new Error(`${fieldName} phai la JSON hop le.`);
    }
  }

  function parseJsonFromStorage(key) {
    const raw = loadFromStorage(key);
    return raw ? JSON.parse(raw) : null;
  }

  function selectRadio(name, value) {
    const radio = document.querySelector(`input[name="${name}"][value="${value}"]`);
    if (radio) {
      radio.checked = true;
      radio.dispatchEvent(new Event("change"));
    }
  }

  async function postJson(url, payload = {}) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Yeu cau that bai.");
    return data;
  }

  function downloadText(filename, content) {
    const blob = new Blob([content], { type: "application/json;charset=utf-8" });
    downloadBlob(filename, blob);
  }

  function downloadBlob(filename, blob) {
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

  function setModeVisibility(radios, containers) {
    radios.forEach((radio) => {
      radio.addEventListener("change", (event) => {
        Object.entries(containers).forEach(([value, element]) => {
          if (element) element.style.display = event.target.value === value ? "block" : "none";
        });
      });
    });
  }

  function setupReceiverPage() {
    const publicKeyArea = document.getElementById("publicKeyArea");
    const privateKeyArea = document.getElementById("privateKeyArea");
    const decryptPrivateKeyArea = document.getElementById("decryptPrivateKeyArea");
    const decryptCiphertextArea = document.getElementById("decryptCiphertextArea");
    const plaintextArea = document.getElementById("plaintextArea");
    const verifyPublicKeyArea = document.getElementById("verifyPublicKeyArea");

    const storedPublicKey = loadFromStorage(STORAGE_KEYS.receiverPublicKey);
    const storedPrivateKey = loadFromStorage(STORAGE_KEYS.receiverPrivateKey);
    const storedSenderPublicKey = loadFromStorage(STORAGE_KEYS.senderPublicKey);
    const storedCiphertext = loadFromStorage(STORAGE_KEYS.ciphertext);

    if (storedPublicKey) {
      publicKeyArea.value = storedPublicKey;
    }
    if (storedSenderPublicKey) {
      verifyPublicKeyArea.value = storedSenderPublicKey;
    }
    if (storedPrivateKey) {
      privateKeyArea.value = storedPrivateKey;
      decryptPrivateKeyArea.value = storedPrivateKey;
    }
    if (storedCiphertext) decryptCiphertextArea.value = storedCiphertext;

    document.getElementById("generateKeysBtn").addEventListener("click", async () => {
      try {
        const mode = document.getElementById("primeModeSelect").value;
        setStatus(mode === "3" ? "Dang sinh so nguyen to co chung chi, vui long doi." : "Dang sinh cap khoa, vui long doi.");
        showProgress();
        const data = await postJson("/api/generate-keys", { prime_mode: Number.parseInt(mode, 10) });
        const publicKeyText = formatJson(data.public_key);
        const privateKeyText = formatJson(data.private_key);
        publicKeyArea.value = publicKeyText;
        privateKeyArea.value = privateKeyText;
        decryptPrivateKeyArea.value = privateKeyText;
        saveToStorage(STORAGE_KEYS.receiverPublicKey, publicKeyText);
        saveToStorage(STORAGE_KEYS.receiverPrivateKey, privateKeyText);
        setStatus("Da tao cap khoa moi cho nguoi nhan.");
      } catch (error) {
        setStatus(error.message, true);
      } finally {
        hideProgress();
      }
    });

    document.getElementById("downloadPublicBtn").addEventListener("click", () => {
      if (!publicKeyArea.value.trim()) return setStatus("Chua co public key de tai.", true);
      downloadText("receiver.public.json", publicKeyArea.value);
      setStatus("Da tai public key.");
    });

    document.getElementById("downloadPrivateBtn").addEventListener("click", () => {
      if (!privateKeyArea.value.trim()) return setStatus("Chua co private key de tai.", true);
      downloadText("receiver.private.json", privateKeyArea.value);
      setStatus("Da tai private key.");
    });

    document.getElementById("sendPublicKeyBtn").addEventListener("click", () => {
      if (!publicKeyArea.value.trim()) return setStatus("Chua co public key de chuyen.", true);
      saveToStorage(STORAGE_KEYS.receiverPublicKey, publicKeyArea.value);
      setStatus("Da chuyen public key sang trang Nguoi gui.");
    });

    document.getElementById("loadCipherBtn").addEventListener("click", () => {
      const cipher = loadFromStorage(STORAGE_KEYS.ciphertext);
      if (!cipher || cipher.startsWith("[")) {
        setStatus("Chua co ban ma tu nguoi gui, hoac ban ma qua lon. Hay tai file JSON len.", true);
        return;
      }
      decryptCiphertextArea.value = cipher;
      setStatus("Da nap ban ma tu nguoi gui.");
    });

    document.getElementById("uploadCipherFile").addEventListener("change", (event) => {
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result);
          window.currentReceiverCiphertextData = data;
          decryptCiphertextArea.value = reader.result.length > 50000 ? "[Ban ma da duoc tai len. Bam Giai ma de tiep tuc.]" : formatJson(data);
          setStatus("Da tai ban ma JSON tu file.");
        } catch {
          setStatus("File khong phai JSON hop le.", true);
        }
      };
      reader.readAsText(file);
    });

    document.getElementById("decryptBtn").addEventListener("click", async () => {
      try {
        setStatus("Dang giai ma du lieu, vui long doi.");
        showProgress();
        const privateKey = parseJsonFromText(decryptPrivateKeyArea.value, "private key");
        const ciphertext =
          window.currentReceiverCiphertextData && decryptCiphertextArea.value.startsWith("[")
            ? window.currentReceiverCiphertextData
            : parseJsonFromText(decryptCiphertextArea.value, "ban ma");
        const data = await postJson("/api/decrypt", { private_key: privateKey, ciphertext });

        if (data.is_file) {
          const filename = data.file_name || "decrypted_file.bin";
          plaintextArea.value = `[File da giai ma: ${filename}. Trinh duyet dang tai xuong.]`;
          downloadBlob(filename, base64ToBlob(data.file_base64, data.mime_type));
          setStatus(`Da giai ma va tai file ${filename}.`);
        } else {
          plaintextArea.value = data.plaintext;
          setStatus("Da giai ma thanh cong.");
        }

        if (!decryptCiphertextArea.value.startsWith("[")) {
          saveToStorage(STORAGE_KEYS.receiverPrivateKey, decryptPrivateKeyArea.value);
          saveToStorage(STORAGE_KEYS.ciphertext, decryptCiphertextArea.value);
        }
      } catch (error) {
        setStatus(error.message, true);
      } finally {
        hideProgress();
      }
    });

    document.getElementById("copyPlaintextBtn").addEventListener("click", async () => {
      if (!plaintextArea.value.trim()) return setStatus("Chua co ket qua de sao chep.", true);
      try {
        await navigator.clipboard.writeText(plaintextArea.value);
        setStatus("Da sao chep ket qua.");
      } catch {
        setStatus("Khong the sao chep tu dong. Hay sao chep thu cong.", true);
      }
    });

    setupVerifyPanel();
  }

  function setupVerifyPanel() {
    const verifyPublicKeyArea = document.getElementById("verifyPublicKeyArea");
    const verifySignatureArea = document.getElementById("verifySignatureArea");
    const verifyResultArea = document.getElementById("verifyResultArea");
    const verifyMessage = document.getElementById("verifyMessage");
    const verifyModeRadios = document.querySelectorAll('input[name="verifyMode"]');

    setModeVisibility(verifyModeRadios, {
      text: document.getElementById("verifyTextModeContainer"),
      file: document.getElementById("verifyFileModeContainer"),
    });

    document.getElementById("loadSenderPublicKeyBtn").addEventListener("click", () => {
      const senderPublicKey = loadFromStorage(STORAGE_KEYS.senderPublicKey);
      if (!senderPublicKey) return setStatus("Chua co public key nao tu nguoi gui.", true);
      verifyPublicKeyArea.value = senderPublicKey;
      setStatus("Da nap public key cua nguoi gui de xac minh.");
    });

    document.getElementById("loadSignatureBtn").addEventListener("click", () => {
      const signature = loadFromStorage(STORAGE_KEYS.signature);
      if (!signature) return setStatus("Chua co chu ky nao tu nguoi gui.", true);
      verifySignatureArea.value = signature;
      setStatus("Da nap chu ky tu nguoi gui.");
    });

    function applySignedPackage(pkg) {
      if (!pkg || pkg.type !== "Elsign-Signed-Package") {
        throw new Error("Goi da ky khong dung dinh dang Elsign.");
      }
      verifyPublicKeyArea.value = formatJson(pkg.sender_public_key);
      verifySignatureArea.value = formatJson(pkg.signature);

      if (pkg.content_type === "text") {
        selectRadio("verifyMode", "text");
        verifyMessage.value = pkg.message || "";
        window.currentSignedPackageFileBase64 = null;
        window.currentSignedPackageFileName = "";
        setStatus("Da nap goi van ban da ky.");
      } else if (pkg.content_type === "file") {
        selectRadio("verifyMode", "file");
        verifyMessage.value = "";
        window.currentSignedPackageFileBase64 = pkg.file_base64;
        window.currentSignedPackageFileName = pkg.file_name || "signed_file.bin";
        window.currentSignedPackageMimeType = pkg.mime_type || "application/octet-stream";
        setStatus(`Da nap goi file da ky: ${window.currentSignedPackageFileName}. Bam Kiem tra chu ky.`);
      } else {
        throw new Error("Goi da ky thieu loai noi dung.");
      }
    }

    document.getElementById("loadSignedPackageBtn").addEventListener("click", () => {
      try {
        const pkg = parseJsonFromStorage(STORAGE_KEYS.signedPackage);
        if (!pkg) return setStatus("Chua co goi da ky nao tu nguoi gui.", true);
        applySignedPackage(pkg);
      } catch (error) {
        setStatus(error.message, true);
      }
    });

    document.getElementById("uploadSignatureFile").addEventListener("change", (event) => {
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          verifySignatureArea.value = formatJson(JSON.parse(reader.result));
          setStatus("Da tai chu ky JSON tu file.");
        } catch {
          setStatus("File chu ky khong phai JSON hop le.", true);
        }
      };
      reader.readAsText(file);
    });

    document.getElementById("uploadSignedPackageFile").addEventListener("change", (event) => {
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const pkg = JSON.parse(reader.result);
          applySignedPackage(pkg);
        } catch (error) {
          setStatus(error.message || "File goi da ky khong hop le.", true);
        }
      };
      reader.readAsText(file);
    });

    document.getElementById("verifyBtn").addEventListener("click", async () => {
      try {
        setStatus("Dang kiem tra chu ky, vui long doi.");
        showProgress();
        verifyResultArea.classList.remove("valid", "invalid");
        const publicKey = parseJsonFromText(verifyPublicKeyArea.value, "public key");
        const signature = parseJsonFromText(verifySignatureArea.value, "chu ky");
        const payload = { public_key: publicKey, signature };
        const mode = document.querySelector('input[name="verifyMode"]:checked')?.value || "text";

        if (mode === "text") {
          payload.message = verifyMessage.value;
        } else {
          const fileInput = document.getElementById("verifyFile");
          if (window.currentSignedPackageFileBase64) {
            payload.file_base64 = window.currentSignedPackageFileBase64;
          } else {
            if (!fileInput.files || fileInput.files.length === 0) throw new Error("Vui long chon mot file de kiem tra.");
            payload.file_base64 = await fileToBase64(fileInput.files[0]);
          }
        }

        const data = await postJson("/api/verify", payload);
        if (data.is_valid) {
          verifyResultArea.value = "HOP LE: Chu ky dung. Noi dung con nguyen ven va khop voi public key cua nguoi gui.";
          verifyResultArea.classList.add("valid");
          setStatus("Kiem tra thanh cong: chu ky hop le.");
        } else {
          verifyResultArea.value = "KHONG HOP LE: Noi dung, chu ky hoac public key khong khop.";
          verifyResultArea.classList.add("invalid");
          setStatus("Kiem tra thanh cong: chu ky khong hop le.", true);
        }
      } catch (error) {
        verifyResultArea.value = "LOI: " + error.message;
        verifyResultArea.classList.remove("valid");
        verifyResultArea.classList.add("invalid");
        setStatus(error.message, true);
      } finally {
        hideProgress();
      }
    });
  }

  function setupSenderPage() {
    const senderMessage = document.getElementById("senderMessage");
    const normalizedPreview = document.getElementById("normalizedPreview");
    const senderPublicKeyArea = document.getElementById("senderPublicKeyArea");
    const ciphertextArea = document.getElementById("ciphertextArea");

    const storedPublicKey = loadFromStorage(STORAGE_KEYS.receiverPublicKey);
    const storedCiphertext = loadFromStorage(STORAGE_KEYS.ciphertext);
    if (storedPublicKey) senderPublicKeyArea.value = storedPublicKey;
    if (storedCiphertext && !storedCiphertext.startsWith("[")) ciphertextArea.value = storedCiphertext;

    senderMessage.addEventListener("input", () => {
      normalizedPreview.value = normalizeMessage(senderMessage.value);
    });

    document.getElementById("loadPublicKeyBtn").addEventListener("click", () => {
      const publicKey = loadFromStorage(STORAGE_KEYS.receiverPublicKey);
      if (!publicKey) return setStatus("Chua co public key nao tu nguoi nhan.", true);
      senderPublicKeyArea.value = publicKey;
      setStatus("Da nap public key tu nguoi nhan.");
    });

    setupSenderKeyPanel();
    setupEncryptPanel();
    setupSignPanel();
  }

  function setupSenderKeyPanel() {
    const senderSigningPublicKeyArea = document.getElementById("senderSigningPublicKeyArea");
    const senderPrivateKeyArea = document.getElementById("senderPrivateKeyArea");

    const storedSenderPublicKey = loadFromStorage(STORAGE_KEYS.senderPublicKey);
    const storedSenderPrivateKey = loadFromStorage(STORAGE_KEYS.senderPrivateKey);
    if (storedSenderPublicKey) senderSigningPublicKeyArea.value = storedSenderPublicKey;
    if (storedSenderPrivateKey) senderPrivateKeyArea.value = storedSenderPrivateKey;

    document.getElementById("generateSenderKeysBtn").addEventListener("click", async () => {
      try {
        const mode = document.getElementById("senderPrimeModeSelect").value;
        setStatus(mode === "3" ? "Dang sinh khoa ky so co chung chi, vui long doi." : "Dang sinh khoa ky so cho nguoi gui.");
        showProgress();
        const data = await postJson("/api/generate-keys", { prime_mode: Number.parseInt(mode, 10) });
        const publicKeyText = formatJson(data.public_key);
        const privateKeyText = formatJson(data.private_key);
        senderSigningPublicKeyArea.value = publicKeyText;
        senderPrivateKeyArea.value = privateKeyText;
        saveToStorage(STORAGE_KEYS.senderPublicKey, publicKeyText);
        saveToStorage(STORAGE_KEYS.senderPrivateKey, privateKeyText);
        setStatus("Da tao khoa ky so cho nguoi gui.");
      } catch (error) {
        setStatus(error.message, true);
      } finally {
        hideProgress();
      }
    });

    document.getElementById("downloadSenderPublicBtn").addEventListener("click", () => {
      if (!senderSigningPublicKeyArea.value.trim()) return setStatus("Chua co public key nguoi gui de tai.", true);
      downloadText("sender.public.json", senderSigningPublicKeyArea.value);
      setStatus("Da tai public key nguoi gui.");
    });

    document.getElementById("downloadSenderPrivateBtn").addEventListener("click", () => {
      if (!senderPrivateKeyArea.value.trim()) return setStatus("Chua co private key nguoi gui de tai.", true);
      downloadText("sender.private.json", senderPrivateKeyArea.value);
      setStatus("Da tai private key nguoi gui.");
    });

    document.getElementById("sendSenderPublicKeyBtn").addEventListener("click", () => {
      if (!senderSigningPublicKeyArea.value.trim()) return setStatus("Chua co public key nguoi gui de chuyen.", true);
      saveToStorage(STORAGE_KEYS.senderPublicKey, senderSigningPublicKeyArea.value);
      setStatus("Da chuyen public key nguoi gui sang trang Nguoi nhan.");
    });
  }

  function setupEncryptPanel() {
    const senderMessage = document.getElementById("senderMessage");
    const normalizedPreview = document.getElementById("normalizedPreview");
    const senderPublicKeyArea = document.getElementById("senderPublicKeyArea");
    const ciphertextArea = document.getElementById("ciphertextArea");
    const encryptModeRadios = document.querySelectorAll('input[name="encryptMode"]');

    setModeVisibility(encryptModeRadios, {
      text: document.getElementById("textModeContainer"),
      file: document.getElementById("fileModeContainer"),
    });

    document.addEventListener("paste", (event) => {
      const items = event.clipboardData?.items || [];
      for (const item of items) {
        if (item.kind !== "file") continue;
        const blob = item.getAsFile();
        if (!blob) continue;
        encryptModeRadios.forEach((radio) => {
          if (radio.value === "file") {
            radio.checked = true;
            radio.dispatchEvent(new Event("change"));
          }
        });
        const fileInput = document.getElementById("senderFile");
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(new File([blob], "pasted_image.png", { type: blob.type }));
        fileInput.files = dataTransfer.files;
        setStatus("Da nhan file tu clipboard. Ban co the bam Ma hoa.");
        break;
      }
    });

    document.getElementById("encryptBtn").addEventListener("click", async () => {
      try {
        setStatus("Dang ma hoa du lieu, vui long doi.");
        showProgress();
        const publicKey = parseJsonFromText(senderPublicKeyArea.value, "public key");
        const payload = { public_key: publicKey };
        const mode = document.querySelector('input[name="encryptMode"]:checked')?.value || "text";

        if (mode === "text") {
          payload.message = senderMessage.value;
        } else {
          const fileInput = document.getElementById("senderFile");
          if (!fileInput.files || fileInput.files.length === 0) throw new Error("Vui long chon mot file de ma hoa.");
          const file = fileInput.files[0];
          payload.file_base64 = await fileToBase64(file);
          payload.file_name = file.name;
          payload.mime_type = file.type || "application/octet-stream";
        }

        const data = await postJson("/api/encrypt", payload);
        normalizedPreview.value = data.is_file ? "[File da ma hoa]" : data.normalized;
        const jsonText = formatJson(data.ciphertext);
        window.currentCiphertextData = data.ciphertext;

        if (data.is_file || jsonText.length > 50000) {
          ciphertextArea.value = "[Du lieu qua lon de hien thi truc tiep.\n\nBam 'Tai ban ma' de luu file cipher.json,\nsau do sang trang Nguoi nhan de tai file len va giai ma.]";
          localStorage.removeItem(STORAGE_KEYS.ciphertext);
        } else {
          ciphertextArea.value = jsonText;
          saveToStorage(STORAGE_KEYS.ciphertext, jsonText);
        }

        saveToStorage(STORAGE_KEYS.receiverPublicKey, senderPublicKeyArea.value);
        setStatus("Nguoi gui da ma hoa thanh cong.");
      } catch (error) {
        setStatus(error.message, true);
      } finally {
        hideProgress();
      }
    });

    document.getElementById("downloadCipherBtn").addEventListener("click", () => {
      const content = window.currentCiphertextData ? formatJson(window.currentCiphertextData) : ciphertextArea.value;
      if (!content || content.trim().startsWith("[")) return setStatus("Chua co ban ma de tai.", true);
      downloadText("cipher.json", content);
      setStatus("Da tai ban ma.");
    });

    document.getElementById("sendCipherBtn").addEventListener("click", () => {
      if (!ciphertextArea.value.trim() || ciphertextArea.value.trim().startsWith("[")) {
        setStatus("Chua co ban ma nho de chuyen. Voi file lon, hay tai ban ma JSON.", true);
        return;
      }
      saveToStorage(STORAGE_KEYS.ciphertext, ciphertextArea.value);
      setStatus("Da chuyen ban ma sang trang Nguoi nhan.");
    });
  }

  function setupSignPanel() {
    const senderSigningPublicKeyArea = document.getElementById("senderSigningPublicKeyArea");
    const senderPrivateKeyArea = document.getElementById("senderPrivateKeyArea");
    const signatureArea = document.getElementById("signatureArea");
    const signMessage = document.getElementById("signMessage");
    const signModeRadios = document.querySelectorAll('input[name="signMode"]');

    const storedPrivateKey = loadFromStorage(STORAGE_KEYS.senderPrivateKey);
    if (storedPrivateKey) senderPrivateKeyArea.value = storedPrivateKey;

    setModeVisibility(signModeRadios, {
      text: document.getElementById("signTextModeContainer"),
      file: document.getElementById("signFileModeContainer"),
    });

    document.getElementById("signBtn").addEventListener("click", async () => {
      try {
        setStatus("Dang tao chu ky, vui long doi.");
        showProgress();
        const privateKey = parseJsonFromText(senderPrivateKeyArea.value, "private key");
        const senderPublicKey = parseJsonFromText(senderSigningPublicKeyArea.value, "public key nguoi gui");
        const payload = { private_key: privateKey };
        const mode = document.querySelector('input[name="signMode"]:checked')?.value || "text";
        let packagePayload;

        if (mode === "text") {
          payload.message = signMessage.value;
          packagePayload = {
            type: "Elsign-Signed-Package",
            content_type: "text",
            message: signMessage.value,
            sender_public_key: senderPublicKey,
          };
        } else {
          const fileInput = document.getElementById("signFile");
          if (!fileInput.files || fileInput.files.length === 0) throw new Error("Vui long chon mot file de ky.");
          const file = fileInput.files[0];
          const fileBase64 = await fileToBase64(file);
          payload.file_base64 = fileBase64;
          packagePayload = {
            type: "Elsign-Signed-Package",
            content_type: "file",
            file_name: file.name,
            mime_type: file.type || "application/octet-stream",
            file_base64: fileBase64,
            sender_public_key: senderPublicKey,
          };
        }

        const data = await postJson("/api/sign", payload);
        signatureArea.value = formatJson(data.signature);
        packagePayload.signature = data.signature;
        packagePayload.signature_hash = data.signature.hash || "SHA-256";
        packagePayload.created_at = new Date().toISOString();
        window.currentSignedPackage = packagePayload;
        saveToStorage(STORAGE_KEYS.signature, formatJson(data.signature));
        saveToStorage(STORAGE_KEYS.signedPackage, formatJson(packagePayload));
        setStatus("Tao chu ky thanh cong.");
      } catch (error) {
        setStatus(error.message, true);
      } finally {
        hideProgress();
      }
    });

    document.getElementById("downloadSignatureBtn").addEventListener("click", () => {
      if (!signatureArea.value.trim()) return setStatus("Chua co chu ky de tai.", true);
      downloadText("signature.json", signatureArea.value);
      setStatus("Da tai chu ky.");
    });

    document.getElementById("sendSignatureBtn").addEventListener("click", () => {
      if (!signatureArea.value.trim()) return setStatus("Chua co chu ky de chuyen.", true);
      saveToStorage(STORAGE_KEYS.signature, signatureArea.value);
      setStatus("Da chuyen chu ky sang trang Nguoi nhan.");
    });

    document.getElementById("downloadSignedPackageBtn").addEventListener("click", () => {
      const content = window.currentSignedPackage ? formatJson(window.currentSignedPackage) : loadFromStorage(STORAGE_KEYS.signedPackage);
      if (!content) return setStatus("Chua co goi da ky de tai.", true);
      downloadText("signed_package.json", content);
      setStatus("Da tai goi da ky.");
    });

    document.getElementById("sendSignedPackageBtn").addEventListener("click", () => {
      const content = window.currentSignedPackage ? formatJson(window.currentSignedPackage) : loadFromStorage(STORAGE_KEYS.signedPackage);
      if (!content) return setStatus("Chua co goi da ky de chuyen.", true);
      saveToStorage(STORAGE_KEYS.signedPackage, content);
      setStatus("Da chuyen goi da ky sang trang Nguoi nhan.");
    });
  }

  if (page === "receiver") {
    setupReceiverPage();
  } else if (page === "sender") {
    setupSenderPage();
  }
}
