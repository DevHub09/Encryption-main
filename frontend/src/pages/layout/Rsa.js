import React, { useState } from "react";
import {
  Container,
  TextField,
  Button,
  Typography,
  Box,
  Paper,
} from "@mui/material";

// Utility functions for hashing and encryption
async function hashMessage(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hashHex;
}

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: { name: "SHA-256" },
    },
    true,
    ["encrypt", "decrypt"]
  );
  return keyPair;
}

async function encryptMessage(message, publicKey) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    data
  );
  return encryptedData;
}

async function decryptMessage(encryptedData, privateKey) {
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encryptedData
  );
  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
}

const Encrypt = () => {
  const [message, setMessage] = useState("");
  const [encryptedMessage, setEncryptedMessage] = useState(null);
  const [decryptedMessage, setDecryptedMessage] = useState("");
  const [keyPair, setKeyPair] = useState(null);

  const handleGenerateKeys = async () => {
    const keys = await generateKeyPair();
    setKeyPair(keys);
  };

  const handleEncrypt = async () => {
    if (!keyPair) {
      await handleGenerateKeys();
    }
    const { publicKey } = keyPair;
    const encryptedData = await encryptMessage(message, publicKey);
    setEncryptedMessage(encryptedData);
  };

  const handleDecrypt = async () => {
    if (encryptedMessage && keyPair) {
      const { privateKey } = keyPair;
      const decrypted = await decryptMessage(encryptedMessage, privateKey);
      setDecryptedMessage(decrypted);
    }
  };

  return (
    <Container maxWidth="sm">
      <Paper elevation={3} sx={{ padding: 3, marginTop: 3 }}>
        <Typography
          variant="h4"
          gutterBottom
          style={{ textAlign: "center", marginBottom: "2rem" }}
        >
          Cryptography Using RSA
        </Typography>
        <TextField
          fullWidth
          multiline
          rows={4}
          variant="outlined"
          label="Enter your message here"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          sx={{ marginBottom: 2 }}
        />
        <Box
          sx={{
            display: "flex",
            justifyContent: "space-between",
            marginBottom: 2,
          }}
        >
          <Button variant="contained" color="secondary" onClick={handleEncrypt}>
            Encrypt Message
          </Button>
          <Button variant="contained" color="success" onClick={handleDecrypt}>
            Decrypt Message
          </Button>
        </Box>
        {encryptedMessage && (
          <Box sx={{ marginBottom: 2 }}>
            <Typography variant="h6">Encrypted Message</Typography>
            <Paper elevation={1} sx={{ padding: 1, wordBreak: "break-all" }}>
              <Typography variant="body1">
                {Array.from(new Uint8Array(encryptedMessage))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("")}
              </Typography>
            </Paper>
          </Box>
        )}
        {decryptedMessage && (
          <Box>
            <Typography variant="h6">Decrypted Message</Typography>
            <Paper elevation={1} sx={{ padding: 1 }}>
              <Typography variant="body1">{decryptedMessage}</Typography>
            </Paper>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default Encrypt;
