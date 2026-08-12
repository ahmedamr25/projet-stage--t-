import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

console.log('=== TEST DE CONNEXION POSTGRESQL ===');
console.log(`Hôte : ${process.env.PGHOST || 'localhost'}`);
console.log(`Port : ${process.env.PGPORT || '5432'}`);
console.log(`Base : ${process.env.PGDATABASE || 'securpass'}`);
console.log(`Utilisateur : ${process.env.PGUSER || 'postgres'}\n`);

const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: parseInt(process.env.PGPORT || '5432'),
  database: process.env.PGDATABASE || 'securpass',
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || '1234@AMR@@',
  connectionTimeoutMillis: 5000
});

async function runTest() {
  let client;
  try {
    console.log('[1] Tentative de connexion...');
    client = await pool.connect();
    console.log('✅ Connexion réussie à PostgreSQL.');

    console.log('[2] Vérification/Activation de l\'extension pgcrypto...');
    await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";');
    console.log('✅ Extension pgcrypto prête.');

    console.log('[3] Vérification de l\'accès à la table "passwords"...');
    const tableCheck = await client.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'passwords'
      );
    `);
    const exists = tableCheck.rows[0].exists;
    console.log(`✅ Table "passwords" existe : ${exists ? 'OUI' : 'NON'}`);

    if (exists) {
      console.log('[4] Comptage des enregistrements dans "passwords"...');
      const countRes = await client.query('SELECT COUNT(*) FROM passwords');
      console.log(`✅ Nombre d'enregistrements : ${countRes.rows[0].count}`);
    }

    console.log('\n🎉 TEST RÉUSSI AVEC SUCCÈS !');
  } catch (err) {
    console.error('\n❌ ERREUR DE TEST :', err.message);
  } finally {
    if (client) client.release();
    await pool.end();
  }
}

runTest();
