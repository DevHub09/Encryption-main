import React, { useState } from "react";
import {
  Container,
  TextField,
  Button,
  Typography,
  Box,
  Paper,
} from "@mui/material";
import CryptoJS from "crypto-js";

// Utility functions for hashing and encryption
function hashMessage(message) {
  const hash = CryptoJS.SHA256(message);
  return hash.toString(CryptoJS.enc.Hex);
}

function generateKey() {
  // For DES, a 64-bit key is typically used
  const key = CryptoJS.lib.WordArray.random(8); // 64 bits
  return key;
}

function encryptMessage(message, key) {
  const iv = CryptoJS.lib.WordArray.random(8); // 64 bits for DES
  const encrypted = CryptoJS.DES.encrypt(message, key, { iv: iv });
  return {
    encryptedData: encrypted.toString(),
    iv: iv.toString(CryptoJS.enc.Hex),
  };
}

function decryptMessage(encryptedData, iv, key) {
  const decrypted = CryptoJS.DES.decrypt(encryptedData, key, {
    iv: CryptoJS.enc.Hex.parse(iv),
  });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

const Encrypt = () => {
  const [message, setMessage] = useState("");
  const [encryptedMessage, setEncryptedMessage] = useState(null);
  const [decryptedMessage, setDecryptedMessage] = useState("");
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [iv, setIv] = useState(null);

  const handleEncrypt = async () => {
    const key = encryptionKey || generateKey();
    const { encryptedData, iv } = encryptMessage(message, key);
    setEncryptionKey(key);
    setEncryptedMessage(encryptedData);
    setIv(iv);
  };

  const handleDecrypt = async () => {
    if (encryptedMessage && encryptionKey && iv) {
      const decrypted = decryptMessage(encryptedMessage, iv, encryptionKey);
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
          Cryptography Using DES
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
            <Paper elevation={1} sx={{ padding: 1 }}>
              <Typography variant="body1">{encryptedMessage}</Typography>
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
