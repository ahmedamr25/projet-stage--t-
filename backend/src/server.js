import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import https from 'https';
import http from 'http';
import { fileURLToPath } from 'url';
import apiRouter from './routes.js';
import { antiReplayMiddleware } from './antiReplay.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.resolve(__dirname, '..', '.env') });
dotenv.config(); // fallback

const app = express();
const PORT = process.env.PORT || 5000;
const HTTPS_PORT = process.env.HTTPS_PORT || 5443;

// ==========================================
// SÉCURITÉ : HELMET (Headers HTTP sécurisés)
// ==========================================
// Implémentation manuelle des headers de sécurité (pas besoin de dépendance externe)
app.use((req, res, next) => {
  // Empêcher le sniffing MIME
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Protection XSS (navigateurs anciens)
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Empêcher le chargement dans un iframe (Clickjacking)
  res.setHeader('X-Frame-Options', 'DENY');
  // Politique de référent stricte
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Désactiver la détection du serveur
  res.removeHeader('X-Powered-By');
  // Strict Transport Security (HTTPS uniquement)
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  // Permissions Policy (désactiver les fonctionnalités inutiles)
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// ==========================================
// SÉCURITÉ : CORS RESTREINT
// ==========================================
const allowedOrigins = (process.env.CORS_ORIGINS || `http://localhost:${PORT},https://localhost:${HTTPS_PORT}`)
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Autoriser les requêtes sans origin (apps mobiles, Postman, extensions)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`[CORS] Origine bloquée : ${origin}`);
    return callback(new Error('Origine non autorisée par la politique CORS.'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Nonce', 'X-Request-Timestamp', 'X-Import-Format']
}));

// ==========================================
// MIDDLEWARES GLOBAUX
// ==========================================
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ type: ['text/*', 'application/json'], limit: '5mb' })); // Pour l'import de fichiers CSV/JSON en texte brut

// Log de requêtes simple
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ==========================================
// SÉCURITÉ : PROTECTION ANTI-REJEU
// ==========================================
// Appliqué sur les routes API uniquement (POST/PUT/DELETE vérifiés, GET passe)
app.use('/api', antiReplayMiddleware);

// Enregistrement des routes de l'API
app.use('/api', apiRouter);

// Service des fichiers statiques du Frontend (résolution absolue sécurisée)
const frontendPath = path.resolve(__dirname, '..', '..', 'frontend');
app.use(express.static(frontendPath));

// Pour toute autre route non API, renvoyer l'index.html du frontend (SPA Support)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) {
    return next();
  }
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// Gestionnaire d'erreurs global
app.use((err, req, res, next) => {
  // Erreur CORS
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: err.message });
  }
  console.error('[SERVER ERROR] :', err.stack);
  res.status(500).json({ error: 'Une erreur interne est survenue sur le serveur.' });
});

// ==========================================
// DÉMARRAGE DU SERVEUR (HTTP + HTTPS/TLS)
// ==========================================

// Démarrer le serveur HTTP
const httpServer = http.createServer(app);
httpServer.listen(PORT, () => {
  console.log('\n==================================================');
  console.log(`🔒 GESTIONNAIRE DE MOTS DE PASSE - BACKEND DÉMARRÉ`);
  console.log(`🚀 HTTP  : http://localhost:${PORT}`);
  console.log(`⚙️  Mode LDAP : ${process.env.LDAP_MOCK === 'true' ? ' MOCK (Simulé)' : ' ACTIVE DIRECTORY (Réel)'}`);
  console.log(`🛡️  Anti-Replay : ACTIVÉ`);
  console.log(`🔐 CORS : ${allowedOrigins.join(', ')}`);
});

// Démarrer le serveur HTTPS/TLS si les certificats sont disponibles
const tlsCertPath = process.env.TLS_CERT_PATH || path.resolve(__dirname, '..', 'certs', 'server.crt');
const tlsKeyPath = process.env.TLS_KEY_PATH || path.resolve(__dirname, '..', 'certs', 'server.key');

try {
  if (fs.existsSync(tlsCertPath) && fs.existsSync(tlsKeyPath)) {
    const httpsOptions = {
      cert: fs.readFileSync(tlsCertPath),
      key: fs.readFileSync(tlsKeyPath)
    };

    // Charger le certificat CA si configuré
    const caCertPath = process.env.TLS_CA_CERT_PATH;
    if (caCertPath && fs.existsSync(caCertPath)) {
      httpsOptions.ca = fs.readFileSync(caCertPath);
    }

    const httpsServer = https.createServer(httpsOptions, app);
    httpsServer.listen(HTTPS_PORT, () => {
      console.log(`🔒 HTTPS : https://localhost:${HTTPS_PORT}`);
      console.log('==================================================\n');
    });
  } else {
    console.log(`⚠️  HTTPS : Désactivé (certificats non trouvés)`);
    console.log(`   Pour activer HTTPS, placez les fichiers :`);
    console.log(`   - Certificat : ${tlsCertPath}`);
    console.log(`   - Clé privée : ${tlsKeyPath}`);
    console.log('==================================================\n');
  }
} catch (tlsErr) {
  console.warn(`⚠️  HTTPS : Erreur de chargement TLS (${tlsErr.message})`);
  console.log('==================================================\n');
}
