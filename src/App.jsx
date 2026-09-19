import { useState, useCallback } from "react";

const DELIMITER = "<<<END_OF_SECRET_MESSAGE>>>";

function textToBits(text) {
  const bytes = new TextEncoder().encode(text);
  return [...bytes].map((b) => b.toString(2).padStart(8, "0")).join("");
}

function bitsToText(bits) {
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

async function getAESKey(password, salt) {
  const enc = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(message, password) {
  const enc = new TextEncoder();

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await getAESKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(message)
  );

  const payload = {
    salt: Array.from(salt),
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(encrypted)),
  };

  return JSON.stringify(payload);
}

async function decryptMessage(encryptedText, password) {
  const payload = JSON.parse(encryptedText);

  const salt = new Uint8Array(payload.salt);
  const iv = new Uint8Array(payload.iv);
  const data = new Uint8Array(payload.data);

  const key = await getAESKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}

function encodeLSB(imageData, message) {
  const fullMessage = message + DELIMITER;
  const bits = textToBits(fullMessage);
  const data = new Uint8ClampedArray(imageData.data);

  const capacity = Math.floor((data.length / 4) * 3);

  if (bits.length > capacity) {
    throw new Error("Mesajul este prea lung pentru această imagine.");
  }

  let bitIndex = 0;

  for (let i = 0; i < data.length && bitIndex < bits.length; i++) {
    if ((i + 1) % 4 === 0) continue;
    data[i] = (data[i] & 0xfe) | Number(bits[bitIndex]);
    bitIndex++;
  }

  return new ImageData(data, imageData.width, imageData.height);
}

function decodeLSB(imageData) {
  const data = imageData.data;
  let bits = "";

  for (let i = 0; i < data.length; i++) {
    if ((i + 1) % 4 === 0) continue;

    bits += data[i] & 1;

    if (bits.length % 8 === 0) {
      const text = bitsToText(bits);

      if (text.includes(DELIMITER)) {
        return text.split(DELIMITER)[0];
      }
    }
  }

  throw new Error("Nu s-a găsit niciun mesaj ascuns.");
}

export default function SteganographyApp() {
  const [image, setImage] = useState(null);
  const [imageData, setImageData] = useState(null);
  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");
  const [decoded, setDecoded] = useState("");
  const [error, setError] = useState("");

  const loadImage = useCallback((file) => {
    if (!file) return;

    const url = URL.createObjectURL(file);
    const img = new Image();

    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;

      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);

      const data = ctx.getImageData(0, 0, img.width, img.height);

      setImage(url);
      setImageData(data);
      setDecoded("");
      setError("");
    };

    img.src = url;
  }, []);

  const handleEncode = async () => {
    try {
      setError("");
      setDecoded("");

      if (!imageData) throw new Error("Alege mai întâi o imagine.");
      if (!message) throw new Error("Scrie un mesaj secret.");
      if (!password) throw new Error("Introdu o parolă AES.");

      const encryptedMessage = await encryptMessage(message, password);
      const stegData = encodeLSB(imageData, encryptedMessage);

      const canvas = document.createElement("canvas");
      canvas.width = stegData.width;
      canvas.height = stegData.height;

      const ctx = canvas.getContext("2d");
      ctx.putImageData(stegData, 0, 0);

      const stegUrl = canvas.toDataURL("image/png");

      setImage(stegUrl);
      setImageData(stegData);

      alert("Mesajul a fost criptat cu AES și ascuns în imagine.");
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDecode = async () => {
    try {
      setError("");
      setDecoded("");

      if (!imageData) throw new Error("Alege mai întâi o imagine.");
      if (!password) throw new Error("Introdu parola AES.");

      const encryptedText = decodeLSB(imageData);
      const originalMessage = await decryptMessage(encryptedText, password);

      setDecoded(originalMessage);
    } catch {
      setError("Nu s-a putut extrage/decripta mesajul. Verifică imaginea și parola.");
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0d1117",
        color: "white",
        padding: "40px",
        fontFamily: "Arial",
      }}
    >
      <h1 style={{ fontSize: "56px", textAlign: "center" }}>
        StegaCrypt AES
      </h1>

      <p style={{ textAlign: "center", fontSize: "20px" }}>
        AES-256-GCM + LSB Image Steganography
      </p>

      <div
        style={{
          background: "#161b22",
          padding: "25px",
          borderRadius: "12px",
          maxWidth: "900px",
          margin: "40px auto",
        }}
      >
        <input
          type="file"
          accept="image/*"
          onChange={(e) => loadImage(e.target.files[0])}
        />

        <br />
        <br />

        <input
          type="password"
          placeholder="Introdu cheia/parola AES"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{
            width: "100%",
            background: "#0d1117",
            color: "white",
            border: "1px solid #30363d",
            padding: "15px",
            fontSize: "16px",
            marginBottom: "15px",
          }}
        />

        <textarea
          rows="6"
          placeholder="Introdu mesajul secret..."
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          style={{
            width: "100%",
            background: "#0d1117",
            color: "white",
            border: "1px solid #30363d",
            padding: "15px",
            fontSize: "16px",
          }}
        />

        <br />
        <br />

        <button
          onClick={handleEncode}
          style={{
            padding: "14px 24px",
            background: "#238636",
            color: "white",
            border: "none",
            borderRadius: "8px",
            fontSize: "17px",
            cursor: "pointer",
          }}
        >
          Criptează AES + Ascunde mesaj
        </button>

        <button
          onClick={handleDecode}
          style={{
            padding: "14px 24px",
            background: "#1f6feb",
            color: "white",
            border: "none",
            borderRadius: "8px",
            fontSize: "17px",
            marginLeft: "10px",
            cursor: "pointer",
          }}
        >
          Extrage + Decriptează
        </button>

        {error && (
          <div style={{ marginTop: "20px", color: "#ff7b72" }}>
            {error}
          </div>
        )}

        {decoded && (
          <div
            style={{
              marginTop: "25px",
              background: "#0d1117",
              padding: "20px",
              borderRadius: "8px",
            }}
          >
            <strong>Mesaj decriptat:</strong>
            <p>{decoded}</p>
          </div>
        )}

        {image && (
          <div style={{ marginTop: "25px" }}>
            <img
              src={image}
              alt="preview"
              style={{
                width: "100%",
                borderRadius: "12px",
              }}
            />

            <a
              href={image}
              download="imagine_aes_steganografiata.png"
              style={{
                display: "inline-block",
                marginTop: "20px",
                padding: "14px 24px",
                background: "#8957e5",
                color: "white",
                borderRadius: "8px",
                textDecoration: "none",
                fontSize: "17px",
              }}
            >
              Descarcă imaginea
            </a>
          </div>
        )}
      </div>
    </div>
  );
}