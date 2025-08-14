const bcrypt = require('bcrypt');

// Updated hash from auth.js
const updatedHash = '$2b$10$YylpldJdY2HSz8wnhvMKBecD7f1cm83HS.Q6nsurOwLzIFsKC94f6';

console.log('🔐 Verifying updated credentials...\n');
console.log(`Username: "hligon"`);
console.log(`Password: "sparqd2025!"`);
console.log(`Hash verification: ${bcrypt.compareSync('sparqd2025!', updatedHash) ? '✅ CORRECT' : '❌ FAILED'}`);

console.log('\n🎯 Login credentials:');
console.log('Username: hligon');
console.log('Password: sparqd2025!');
