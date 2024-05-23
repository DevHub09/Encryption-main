import React, { useState } from 'react';
import { Container, TextField, Button, Typography, Box, Paper } from '@mui/material';

// Utility functions for hashing and encryption
async function hashMessage(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

async function generateKey() {
    const key = await crypto.subtle.generateKey({
        name: "AES-GCM", //AES with Galois/Counter Mode (AES-GCM) provides both authenticated encryption (confidentiality and authentication) and the ability to check the integrity and authentication of additional authenticated data (AAD) that is sent in the clear
        length: 256,
    }, true, ["encrypt", "decrypt"]);
    return key;
}

async function encryptMessage(message, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Secure random IV
    const encryptedData = await crypto.subtle.encrypt({
        name: "AES-GCM",
        iv: iv,
    }, key, data);
    return { encryptedData, iv };
}

async function decryptMessage(encryptedData, iv, key) {
    const decryptedData = await crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: iv,
    }, key, encryptedData);
    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
}

const Encrypt = () => {
    const [message, setMessage] = useState('');
    const [encryptedMessage, setEncryptedMessage] = useState(null);
    const [decryptedMessage, setDecryptedMessage] = useState('');
    const [encryptionKey, setEncryptionKey] = useState(null);
    const [iv, setIv] = useState(null);


    const handleEncrypt = async () => {
        const key = encryptionKey || await generateKey();
        const { encryptedData, iv } = await encryptMessage(message, key);
        setEncryptionKey(key);
        setEncryptedMessage(encryptedData);
        setIv(iv);
    };

    const handleDecrypt = async () => {
        if (encryptedMessage && encryptionKey && iv) {
            const decrypted = await decryptMessage(encryptedMessage, iv, encryptionKey);
            setDecryptedMessage(decrypted);
        }
    };

    return (
        <Container maxWidth="sm">
            <Paper elevation={3} sx={{ padding: 3, marginTop: 3 }}>
                <Typography variant="h4" gutterBottom style={{textAlign:"center",marginBottom:"2rem"}}>
                    Cryptography Using AES
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
                <Box sx={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
               
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
                            <Typography variant="body1">
                                {Array.from(new Uint8Array(encryptedMessage)).map(b => b.toString(16).padStart(2, '0')).join('')}
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
