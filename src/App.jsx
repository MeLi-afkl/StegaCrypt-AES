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

  const salt = crypto.getRandomValues(new Uint8Array(16));
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
    throw new Error("The encrypted payload is invalid.");
  }

  if (
    !payload ||
    payload.version !== 1 ||
    !Array.isArray(payload.salt) ||
    !Array.isArray(payload.iv) ||
    !Array.isArray(payload.data)
  ) {
    throw new Error("Invalid payload structure.");
  }

  if (payload.salt.length !== 16) {
    throw new Error("Invalid salt.");
  }

  if (payload.iv.length !== 12) {
    throw new Error("Invalid IV.");
  }

  if (payload.data.length === 0) {
    throw new Error("Invalid ciphertext.");
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
    throw new Error("Invalid payload size.");
  }

  return number.toString(2).padStart(HEADER_BITS, "0");
}

function binary32ToNumber(bits) {
  if (bits.length !== HEADER_BITS) {
    throw new Error("Invalid header.");
  }

  return parseInt(bits, 2);
}

// ----------------------------------------------------
// LSB ENCODING
// ----------------------------------------------------

function encodeLSB(imageData, message) {
  const messageBits = textToBits(message);

  const lengthHeader = numberTo32BitBinary(messageBits.length);
  const bits = lengthHeader + messageBits;

  const data = new Uint8ClampedArray(imageData.data);

  // Three usable channels per pixel: R, G and B.
  const capacity = Math.floor((data.length / 4) * 3);

  if (bits.length > capacity) {
    throw new Error(
      "The encrypted message is too large for this image."
    );
  }

  let bitIndex = 0;

  for (let i = 0; i < data.length && bitIndex < bits.length; i++) {
    // Skip the alpha channel.
    if ((i + 1) % 4 === 0) {
      continue;
    }

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
    throw new Error("The image is too small.");
  }

  let headerBits = "";
  let payloadBits = "";

  let payloadLength = null;
  let readableBitIndex = 0;

  for (let i = 0; i < data.length; i++) {
    // Skip the alpha channel.
    if ((i + 1) % 4 === 0) {
      continue;
    }

    const bit = String(data[i] & 1);

    if (readableBitIndex < HEADER_BITS) {
      headerBits += bit;
      readableBitIndex++;

      if (readableBitIndex === HEADER_BITS) {
        payloadLength = binary32ToNumber(headerBits);

        const availablePayloadBits = capacity - HEADER_BITS;

        if (
          payloadLength <= 0 ||
          payloadLength > availablePayloadBits ||
          payloadLength % 8 !== 0
        ) {
          throw new Error(
            "This image does not contain a valid StegaCrypt payload."
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
    "The complete payload could not be extracted from the image."
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
            "The browser could not initialize Canvas."
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
            : "The image could not be loaded."
        );
      }
    };

    img.onerror = () => {
      URL.revokeObjectURL(url);

      setImage(null);
      setImageData(null);

      setError(
        "The selected file could not be loaded as an image."
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
        throw new Error("Please select an image first.");
      }

      if (!message.trim()) {
        throw new Error("Please enter a secret message.");
      }

      if (!password) {
        throw new Error("Please enter a password.");
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
          "The browser could not initialize Canvas."
        );
      }

      ctx.putImageData(stegData, 0, 0);

      // PNG is lossless and preserves the modified LSB values.
      const stegUrl = canvas.toDataURL("image/png");

      setImage(stegUrl);
      setImageData(stegData);

      alert(
        "The message was encrypted with AES-256-GCM and hidden in the image."
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "An error occurred during encryption."
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
        throw new Error("Please select an image first.");
      }

      if (!password) {
        throw new Error("Please enter the password.");
      }

      const encryptedText = decodeLSB(imageData);

      const originalMessage = await decryptMessage(
        encryptedText,
        password
      );

      setDecoded(originalMessage);
    } catch {
      setError(
        "The message could not be extracted or decrypted. Check the image and password."
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
          placeholder="Enter password"
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
          placeholder="Enter your secret message..."
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
          Encrypt & Hide Message
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
          Extract & Decrypt
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
            <strong>Decrypted message:</strong>

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
              download="stegacrypt-encrypted-image.png"
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
              Download Stego Image
            </a>
          </div>
        )}
      </div>
    </div>
  );
}