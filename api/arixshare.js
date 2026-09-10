const express = require('express');
const multer = require('multer');
const cors = require('cors');
const zlib = require('zlib');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const QRCode = require('qrcode');
const archiver = require('archiver');
const { Readable } = require('stream');

// Initialize Express application
const app = express();
app.use(cors());
app.use(express.json());

// --- UPSTASH CONFIGURATION ---
const RAW_URL = "https://immortal-eagle-36171.upstash.io";
const RAW_TOKEN = "AY1LAAIgcDE5MjFiMmNkNGQ4M2M0ODQ2YWNhYjU0YmFmMzlhNjliNw";

const UPSTASH_URL = RAW_URL.trim().replace(/\/$/, '');
const UPSTASH_TOKEN = RAW_TOKEN.trim();

// --- SYSTEM CONSTANTS ---
const MAX_TOTAL_SIZE = 900 * 1024 * 1024; // 900 MB limit
const MAX_FILES = 5;
const CHUNK_SIZE = 1024 * 1024; // 1MB chunks to safely navigate REST API limits
const BATCH_SIZE = 5; // Batch 5 chunks per Upstash Pipeline request
const EXPIRE_SECONDS = 30 * 24 * 60 * 60; // 30 days expiration in Redis

// Setup Multer to store uploaded files temporarily on the disk (Memory storage would crash with 900MB)
const upload = multer({
    dest: os.tmpdir(),
    limits: { fileSize: MAX_TOTAL_SIZE, files: MAX_FILES }
});

// --- UPSTASH REDIS HELPER FUNCTIONS ---

/**
 * Executes a pipeline of commands to Upstash REST API.
 * This is crucial for performance and preventing rate-limits when uploading hundreds of chunks.
 */
async function upstashPipeline(commands) {
    const response = await fetch(`${UPSTASH_URL}/pipeline`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${UPSTASH_TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(commands)
    });
    
    if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Upstash Pipeline Error: ${response.status} - ${errText}`);
    }
    return await response.json();
}

/**
 * Gets a single value from Upstash
 */
async function upstashGet(key) {
    const response = await fetch(`${UPSTASH_URL}/get/${key}`, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${UPSTASH_TOKEN}` }
    });
    
    if (!response.ok) throw new Error(`Upstash Get Error: ${response.status}`);
    const data = await response.json();
    return data.result;
}

// --- UTILITIES ---

// Clean up temporary files synchronously to ensure no disk leaks
function cleanupTempFiles(files, dirPath) {
    try {
        if (files && Array.isArray(files)) {
            files.forEach(f => {
                if (fs.existsSync(f.path)) fs.unlinkSync(f.path);
            });
        }
        if (dirPath && fs.existsSync(dirPath)) {
            fs.rmSync(dirPath, { recursive: true, force: true });
        }
    } catch (err) {
        console.error("Cleanup Error:", err);
    }
}

// Generate a secure SHA-256 hash for passwords
function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

// Derive a 32-byte key for AES-256-CTR
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// --- ROUTES ---

/**
 * POST /api/upload
 * Handles file uploads, zips them, applies hyper-compression (Brotli), encrypts, and chunks to Redis.
 */
app.post('/api/upload', upload.array('files', MAX_FILES), async (req, res) => {
    const id = crypto.randomUUID();
    const reqTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `arixshare-${id}-`));
    const finalEncryptedPath = path.join(reqTmpDir, 'final.bin');
    
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: "No files uploaded." });
        }

        const { title = "Untitled Share", description = "", isPublic = "true", password = "" } = req.body;
        const hasPassword = password.trim().length > 0;
        
        // Setup Security Cryptography
        const salt = crypto.randomBytes(16).toString('hex');
        const iv = crypto.randomBytes(16);
        // If no password, use the system ID as an internal encryption key to ensure it is always protected at rest
        const encryptionKey = deriveKey(hasPassword ? password : id, salt); 

        console.log(`[ArixShare] Processing ${req.files.length} files. Initiating Hyper-Compression Algorithm...`);

        // 1. Setup processing pipeline streams
        const outputStream = fs.createWriteStream(finalEncryptedPath);
        
        // Highest level Brotli compression for maximum space saving ("Hyper Compressed")
        const compressStream = zlib.createBrotliCompress({
            chunkSize: 32 * 1024,
            params: {
                [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_GENERIC,
                [zlib.constants.BROTLI_PARAM_QUALITY]: zlib.constants.BROTLI_MAX_QUALITY, // Level 11
                [zlib.constants.BROTLI_PARAM_SIZE_HINT]: fs.statSync(req.files[0].path).size
            }
        });
        
        const cipherStream = crypto.createCipheriv('aes-256-ctr', encryptionKey, iv);

        // 2. Initialize Archiver to group multiple files into a single continuous Zip stream
        const archive = archiver('zip', { zlib: { level: 0 } }); // Compression is handled heavily by Brotli instead
        
        // Pipe sequence: Archiver -> Brotli Compression -> AES Encryption -> File Output
        archive.pipe(compressStream).pipe(cipherStream).pipe(outputStream);

        // Append files to the archive
        let originalSize = 0;
        for (const file of req.files) {
            archive.file(file.path, { name: file.originalname });
            originalSize += file.size;
        }
        await archive.finalize();

        // Wait for the entire pipeline to finish writing to disk
        await new Promise((resolve, reject) => {
            outputStream.on('finish', resolve);
            outputStream.on('error', reject);
        });

        // 3. Read the heavily compressed and encrypted file and chunk it to Upstash Redis
        const finalStat = fs.statSync(finalEncryptedPath);
        const compressedSize = finalStat.size;
        
        const fd = fs.openSync(finalEncryptedPath, 'r');
        let bytesRead = 0;
        let chunkIndex = 0;
        let batchCommands = [];

        while (bytesRead < compressedSize) {
            const buffer = Buffer.alloc(Math.min(CHUNK_SIZE, compressedSize - bytesRead));
            fs.readSync(fd, buffer, 0, buffer.length, bytesRead);
            bytesRead += buffer.length;
            
            const base64Data = buffer.toString('base64');
            const chunkKey = `ARIX_CHUNK_${id}_${chunkIndex}`;
            
            // Add to batch pipeline: SET key value EX expiration
            batchCommands.push(["SET", chunkKey, base64Data, "EX", EXPIRE_SECONDS]);
            
            if (batchCommands.length >= BATCH_SIZE || bytesRead >= compressedSize) {
                await upstashPipeline(batchCommands);
                batchCommands = []; // Reset batch
            }
            chunkIndex++;
        }
        fs.closeSync(fd);

        // 4. Save Share Metadata
        const metadata = {
            id,
            title,
            description,
            isPublic: isPublic === 'true',
            hasPassword,
            passwordHash: hasPassword ? hashPassword(password, salt) : null,
            salt,
            iv: iv.toString('hex'),
            totalChunks: chunkIndex,
            originalSize,
            compressedSize,
            createdAt: Date.now()
        };

        const metaCommands = [
            ["SET", `ARIX_META_${id}`, JSON.stringify(metadata), "EX", EXPIRE_SECONDS]
        ];

        if (metadata.isPublic) {
            // Add to a Redis Sorted Set for the public feed, scored by timestamp (newest first)
            metaCommands.push(["ZADD", "ARIX_PUBLIC_SHARES", metadata.createdAt, id]);
        }

        await upstashPipeline(metaCommands);

        // 5. Generate Share Links & QR Code
        const shareLink = `${req.protocol}://${req.get('host')}/share/${id}`;
        
        // Generating hyper-compressed QR Code string (Base64 Image) mapping to the link
        const qrCodeDataUrl = await QRCode.toDataURL(shareLink, {
            errorCorrectionLevel: 'H',
            margin: 2,
            color: { dark: '#000000', light: '#ffffff' }
        });

        res.json({
            success: true,
            message: "Files hyper-compressed, encrypted, and uploaded successfully.",
            data: {
                id,
                shareLink,
                qrCode: qrCodeDataUrl,
                originalSize: (originalSize / 1024 / 1024).toFixed(2) + " MB",
                compressedSize: (compressedSize / 1024 / 1024).toFixed(2) + " MB",
                chunks: chunkIndex
            }
        });

    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).json({ error: "An error occurred during the hyper-compression upload process." });
    } finally {
        // ALWAYS clean up temporary files to prevent server crashes
        cleanupTempFiles(req.files, reqTmpDir);
    }
});

/**
 * GET /api/metadata/:id
 * Retrieves information about the share before downloading.
 */
app.get('/api/metadata/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const metaStr = await upstashGet(`ARIX_META_${id}`);
        
        if (!metaStr) return res.status(404).json({ error: "Share not found or expired." });
        
        const meta = JSON.parse(metaStr);
        // Remove sensitive system data before sending to client
        delete meta.passwordHash;
        delete meta.salt;
        delete meta.iv;
        
        res.json({ success: true, metadata: meta });
    } catch (error) {
        res.status(500).json({ error: "Failed to retrieve share info." });
    }
});

/**
 * GET /api/public-shares
 * Retrieves the latest public shares using a Redis Sorted Set index.
 */
app.get('/api/public-shares', async (req, res) => {
    try {
        // Fetch up to 50 most recent public share IDs using ZREVRANGE
        const response = await fetch(`${UPSTASH_URL}/zrevrange/ARIX_PUBLIC_SHARES/0/50`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${UPSTASH_TOKEN}` }
        });
        
        if (!response.ok) throw new Error("Failed to fetch from Upstash");
        const data = await response.json();
        const publicIds = data.result;

        if (!publicIds || publicIds.length === 0) {
            return res.json({ success: true, shares: [] });
        }

        // Pipeline metadata fetching for maximum efficiency
        const metaCommands = publicIds.map(id => ["GET", `ARIX_META_${id}`]);
        const metaResults = await upstashPipeline(metaCommands);
        
        const activeShares = [];
        const expiredIds = [];

        metaResults.forEach((resultObj, idx) => {
            if (resultObj.error) {
                console.error("Pipeline GET error:", resultObj.error);
                return;
            }
            if (resultObj.result) {
                const meta = JSON.parse(resultObj.result);
                // Securely strip sensitive server-side cryptographic info
                delete meta.passwordHash;
                delete meta.salt;
                delete meta.iv;
                activeShares.push(meta);
            } else {
                // If the key is null, it means it expired in Redis (30 days limit). Track it for cleanup.
                expiredIds.push(publicIds[idx]);
            }
        });

        // Lazy background cleanup of expired shares from the sorted set
        if (expiredIds.length > 0) {
            const cleanupCommands = expiredIds.map(id => ["ZREM", "ARIX_PUBLIC_SHARES", id]);
            // Do not await this, let it process asynchronously so the user request isn't blocked
            upstashPipeline(cleanupCommands).catch(e => console.error("Lazy cleanup error:", e));
        }

        res.json({ success: true, shares: activeShares });
    } catch (error) {
        console.error("Public shares fetch error:", error);
        res.status(500).json({ error: "Failed to retrieve public shares feed." });
    }
});

/**
 * POST /api/download/:id
 * Authenticates, dynamically fetches chunks, decrypts, uncompresses, and streams to user.
 * We use POST to securely accept the password in the request body.
 */
app.post('/api/download/:id', async (req, res) => {
    const id = req.params.id;
    const { password = "" } = req.body;

    try {
        const metaStr = await upstashGet(`ARIX_META_${id}`);
        if (!metaStr) return res.status(404).json({ error: "Share not found or expired." });
        
        const meta = JSON.parse(metaStr);

        // Security check
        if (meta.hasPassword) {
            const hashedAttempt = hashPassword(password, meta.salt);
            if (hashedAttempt !== meta.passwordHash) {
                return res.status(401).json({ error: "Incorrect password." });
            }
        }

        // Setup Decryption Key
        const encryptionKey = deriveKey(meta.hasPassword ? password : id, meta.salt);
        const iv = Buffer.from(meta.iv, 'hex');

        // Create a custom Readable stream that dynamically fetches chunks from Upstash Redis
        class UpstashChunkStream extends Readable {
            constructor(options) {
                super(options);
                this.currentChunk = 0;
                this.totalChunks = meta.totalChunks;
            }

            async _read(size) {
                if (this.currentChunk >= this.totalChunks) {
                    this.push(null); // End of stream
                    return;
                }

                try {
                    const chunkKey = `ARIX_CHUNK_${id}_${this.currentChunk}`;
                    const base64Data = await upstashGet(chunkKey);
                    
                    if (!base64Data) {
                        this.emit('error', new Error("Missing chunk in database. Data corrupted."));
                        return;
                    }

                    const buffer = Buffer.from(base64Data, 'base64');
                    this.push(buffer);
                    this.currentChunk++;
                } catch (err) {
                    this.emit('error', err);
                }
            }
        }

        const chunkStream = new UpstashChunkStream();
        const decipherStream = crypto.createDecipheriv('aes-256-ctr', encryptionKey, iv);
        
        // Decompress using Brotli Level 11
        const decompressStream = zlib.createBrotliDecompress();

        // Set response headers to force download as a ZIP file
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="arixshare_${id}.zip"`);
        
        // Pipe the streams to immediately stream data to the user without holding in RAM
        chunkStream
            .pipe(decipherStream)
            .pipe(decompressStream)
            .pipe(res)
            .on('error', (err) => {
                console.error("Stream Pipeline Error:", err);
                if (!res.headersSent) res.status(500).send("Stream Error");
            });

    } catch (error) {
        console.error("Download Error:", error);
        if (!res.headersSent) res.status(500).json({ error: "Failed to process download." });
    }
});

// Start the Express Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[ArixShare] Server is securely running on port ${PORT}`);
    console.log(`[ArixShare] Upstash configuration active. Maximum payload: 900MB per request.`);
});
