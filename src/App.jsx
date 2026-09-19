import { useState, useCallback } from "react";

/*
 * StegaCrypt AES
 *
 * Encryption:
 * Password -> PBKDF2-SHA256 -> AES-256-GCM key
 *
 * Steganography:
 * [32-bit payload length][encrypted payload]
 *
 * Each bit is stored in the least significant bit (LSB)
 * of the RGB channels of the image.
 */

const HEADER_BITS = 32;
const PBKDF2_ITERATIONS = 100000;

// ----------------------------------------------------
// TEXT / BIT CONVERSION
// ----------------------------------------------------

function bytesToBits(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(2).padStart(8, "0"))
    .join("");
}

function bitsToBytes(bits) {
  const bytes = [];

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return new Uint8Array(bytes);
}

function textToBits(text) {
  const bytes = new TextEncoder().encode(text);
  return bytesToBits(bytes);
}

function bitsToText(bits) {
  const bytes = bitsToBytes(bits);
  return new TextDecoder().decode(bytes);
}

// ----------------------------------------------------
// AES KEY DERIVATION
// ----------------------------------------------------

async function getAESKey(password, salt) {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

// ----------------------------------------------------
// AES ENCRYPTION
// ----------------------------------------------------

async function encryptMessage(message, password) {
  const encoder = new TextEncoder();

  // Random salt for PBKDF2
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // 96-bit IV recommended for AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await getAESKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encoder.encode(message)
  );

  /*
   * Salt and IV are not secret.
   * They are stored together with the ciphertext so that
   * the AES key can be derived again during decryption.
   */
  const payload = {
    version: 1,
    salt: Array.from(salt),
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(encrypted)),
  };

  return JSON.stringify(payload);
}

// ----------------------------------------------------
// AES DECRYPTION
// ----------------------------------------------------

async function decryptMessage(encryptedText, password) {
  let payload;

  try {
    payload = JSON.parse(encryptedText);
  } catch {
    throw new Error("Payload-ul criptat nu este valid.");
  }

  // Basic payload validation
  if (
    !payload ||
    payload.version !== 1 ||
    !Array.isArray(payload.salt) ||
    !Array.isArray(payload.iv) ||
    !Array.isArray(payload.data)
  ) {
    throw new Error("Structura payload-ului nu este validă.");
  }

  if (payload.salt.length !== 16) {
    throw new Error("Salt invalid.");
  }

  if (payload.iv.length !== 12) {
    throw new Error("IV invalid.");
  }

  if (payload.data.length === 0) {
    throw new Error("Ciphertext invalid.");
  }

  const salt = new Uint8Array(payload.salt);
  const iv = new Uint8Array(payload.iv);
  const data = new Uint8Array(payload.data);

  const key = await getAESKey(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}

// ----------------------------------------------------
// 32-BIT LENGTH HEADER
// ----------------------------------------------------

function numberTo32BitBinary(number) {
  if (!Number.isSafeInteger(number) || number < 0 || number > 0xffffffff) {
    throw new Error("Dimensiunea payload-ului nu este validă.");
  }

  return number.toString(2).padStart(HEADER_BITS, "0");
}

function binary32ToNumber(bits) {
  if (bits.length !== HEADER_BITS) {
    throw new Error("Header invalid.");
  }

  return parseInt(bits, 2);
}

// ----------------------------------------------------
// LSB ENCODING
// ----------------------------------------------------

function encodeLSB(imageData, message) {
  const messageBits = textToBits(message);

  /*
   * First 32 bits = payload length in bits.
   * Remaining bits = encrypted payload.
   */
  const lengthHeader = numberTo32BitBinary(messageBits.length);
  const bits = lengthHeader + messageBits;

  const data = new Uint8ClampedArray(imageData.data);

  /*
   * Every pixel has:
   * R, G, B, A
   *
   * We use only RGB, therefore 3 bits per pixel.
   */
  const capacity = Math.floor((data.length / 4) * 3);

  if (bits.length > capacity) {
    throw new Error(
      "Mesajul criptat este prea lung pentru această imagine."
    );
  }

  let bitIndex = 0;

  for (let i = 0; i < data.length && bitIndex < bits.length; i++) {
    // Skip alpha channel
    if ((i + 1) % 4 === 0) {
      continue;
    }

    /*
     * Clear the current least significant bit
     * and replace it with our payload bit.
     */
    data[i] = (data[i] & 0xfe) | Number(bits[bitIndex]);

    bitIndex++;
  }

  return new ImageData(
    data,
    imageData.width,
    imageData.height
  );
}

// ----------------------------------------------------
// LSB DECODING
// ----------------------------------------------------

function decodeLSB(imageData) {
  const data = imageData.data;

  const capacity = Math.floor((data.length / 4) * 3);

  if (capacity < HEADER_BITS) {
    throw new Error("Imaginea este prea mică.");
  }

  let headerBits = "";
  let payloadBits = "";

  let payloadLength = null;
  let readableBitIndex = 0;

  for (let i = 0; i < data.length; i++) {
    // Skip alpha channel
    if ((i + 1) % 4 === 0) {
      continue;
    }

    const bit = String(data[i] & 1);

    /*
     * Read the first 32 RGB LSBs as the length header.
     */
    if (readableBitIndex < HEADER_BITS) {
      headerBits += bit;
      readableBitIndex++;

      if (readableBitIndex === HEADER_BITS) {
        payloadLength = binary32ToNumber(headerBits);

        /*
         * Validate the declared payload size.
         *
         * This also prevents random normal images from causing
         * us to attempt to read an impossible amount of data.
         */
        const availablePayloadBits = capacity - HEADER_BITS;

        if (
          payloadLength <= 0 ||
          payloadLength > availablePayloadBits ||
          payloadLength % 8 !== 0
        ) {
          throw new Error(
            "Imaginea nu conține un payload StegaCrypt valid."
          );
        }
      }

      continue;
    }

    if (payloadLength !== null && payloadBits.length < payloadLength) {
      payloadBits += bit;
    }

    if (
      payloadLength !== null &&
      payloadBits.length === payloadLength
    ) {
      return bitsToText(payloadBits);
    }
  }

  throw new Error(
    "Nu s-a putut extrage payload-ul complet din imagine."
  );
}

// ----------------------------------------------------
// REACT COMPONENT
// ----------------------------------------------------

export default function SteganographyApp() {
  const [image, setImage] = useState(null);
  const [imageData, setImageData] = useState(null);

  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");

  const [decoded, setDecoded] = useState("");
  const [error, setError] = useState("");

  // --------------------------------------------------
  // IMAGE LOADING
  // --------------------------------------------------

  const loadImage = useCallback((file) => {
    if (!file) {
      return;
    }

    const url = URL.createObjectURL(file);
    const img = new Image();

    img.onload = () => {
      try {
        const canvas = document.createElement("canvas");

        canvas.width = img.width;
        canvas.height = img.height;

        const ctx = canvas.getContext("2d");

        if (!ctx) {
          throw new Error(
            "Browserul nu a putut inițializa Canvas."
          );
        }

        ctx.drawImage(img, 0, 0);

        const data = ctx.getImageData(
          0,
          0,
          img.width,
          img.height
        );

        setImage(url);
        setImageData(data);

        setDecoded("");
        setError("");
      } catch (err) {
        URL.revokeObjectURL(url);

        setImage(null);
        setImageData(null);

        setError(
          err instanceof Error
            ? err.message
            : "Imaginea nu a putut fi încărcată."
        );
      }
    };

    img.onerror = () => {
      URL.revokeObjectURL(url);

      setImage(null);
      setImageData(null);

      setError(
        "Fișierul selectat nu a putut fi încărcat ca imagine."
      );
    };

    img.src = url;
  }, []);

  // --------------------------------------------------
  // ENCRYPT + HIDE
  // --------------------------------------------------

  const handleEncode = async () => {
    try {
      setError("");
      setDecoded("");

      if (!imageData) {
        throw new Error("Alege mai întâi o imagine.");
      }

      if (!message.trim()) {
        throw new Error("Scrie un mesaj secret.");
      }

      if (!password) {
        throw new Error("Introdu o parolă.");
      }

      const encryptedMessage = await encryptMessage(
        message,
        password
      );

      const stegData = encodeLSB(
        imageData,
        encryptedMessage
      );

      const canvas = document.createElement("canvas");

      canvas.width = stegData.width;
      canvas.height = stegData.height;

      const ctx = canvas.getContext("2d");

      if (!ctx) {
        throw new Error(
          "Browserul nu a putut inițializa Canvas."
        );
      }

      ctx.putImageData(stegData, 0, 0);

      /*
       * PNG is used because it is lossless.
       * Lossy compression such as JPEG can destroy LSB data.
       */
      const stegUrl = canvas.toDataURL("image/png");

      setImage(stegUrl);
      setImageData(stegData);

      alert(
        "Mesajul a fost criptat cu AES-256-GCM și ascuns în imagine."
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "A apărut o eroare la criptare."
      );
    }
  };

  // --------------------------------------------------
  // EXTRACT + DECRYPT
  // --------------------------------------------------

  const handleDecode = async () => {
    try {
      setError("");
      setDecoded("");

      if (!imageData) {
        throw new Error("Alege mai întâi o imagine.");
      }

      if (!password) {
        throw new Error("Introdu parola.");
      }

      const encryptedText = decodeLSB(imageData);

      const originalMessage = await decryptMessage(
        encryptedText,
        password
      );

      setDecoded(originalMessage);
    } catch {
      setError(
        "Nu s-a putut extrage/decripta mesajul. Verifică imaginea și parola."
      );
    }
  };

  // --------------------------------------------------
  // UI
  // --------------------------------------------------

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
      <h1
        style={{
          fontSize: "56px",
          textAlign: "center",
        }}
      >
        StegaCrypt AES
      </h1>

      <p
        style={{
          textAlign: "center",
          fontSize: "20px",
        }}
      >
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
          onChange={(e) =>
            loadImage(e.target.files?.[0])
          }
        />

        <br />
        <br />

        <input
          type="password"
          placeholder="Introdu parola"
          value={password}
          onChange={(e) =>
            setPassword(e.target.value)
          }
          style={{
            width: "100%",
            boxSizing: "border-box",
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
          onChange={(e) =>
            setMessage(e.target.value)
          }
          style={{
            width: "100%",
            boxSizing: "border-box",
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
          <div
            style={{
              marginTop: "20px",
              color: "#ff7b72",
            }}
          >
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

            <p
              style={{
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {decoded}
            </p>
          </div>
        )}

        {image && (
          <div
            style={{
              marginTop: "25px",
            }}
          >
            <img
              src={image}
              alt="StegaCrypt preview"
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