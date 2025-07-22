import express from 'express'
import { CompactEncrypt, importSPKI } from 'jose'
import fs from 'fs'
import cors from 'cors'

// 讀入公鑰
const publicKeyPem = fs.readFileSync('./public.pem', 'utf8')
const publicKey = await importSPKI(publicKeyPem, 'RSA-OAEP')

// 啟動 Express app
const app = express()
app.use(express.json())
app.use(cors())

app.post('/api/encrypt', async (req, res) => {
  try {
    // 取得前端送來的 payload
    const data = req.body

    // 檢查必填欄位
    if (!data) {
      return res.status(400).json({ error: 'payload is required' })
    }

    // 編碼 payload
    const encoder = new TextEncoder()
    const payloadBytes = encoder.encode(JSON.stringify(data))

    // JWE 加密
    const jweString = await new CompactEncrypt(payloadBytes)
      .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
      .encrypt(publicKey)
    
    const [protectedHeader, encrypted_key, iv, ciphertext, tag] = jweString.split('.')

    res.json({
      protected: protectedHeader,
      encrypted_key: encrypted_key,
      iv: iv,
      ciphertext: ciphertext,
      tag: tag
    })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'internal error', detail: String(err) })
  }
})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API 啟動於 http://localhost:${PORT}/api/encrypt`);
});

