const bcrypt = require('bcrypt');

// Current password hash in the system
const currentHash = '$2b$10$DDN0DoYRR7G6R0Mj6YlemeBLRZ6juETwvBGWJ9o6hCw9cPJeP5igC';

// Possible passwords to test
const testPasswords = [
    'sparqd2025!',
    'admin123',
    'password',
    'getsparqd',
    'hligon',
    'bhall'
];

console.log('🔐 Testing password combinations...\n');

testPasswords.forEach(password => {
    const isMatch = bcrypt.compareSync(password, currentHash);
    console.log(`Password: "${password}" -> ${isMatch ? '✅ MATCH' : '❌ No match'}`);
});

console.log('\n📝 To generate a new hash for "sparqd2025!":\n');
const newHash = bcrypt.hashSync('sparqd2025!', 10);
console.log(`New hash: ${newHash}`);

console.log('\n✅ Verify new hash works:');
console.log(`Test "sparqd2025!" with new hash: ${bcrypt.compareSync('sparqd2025!', newHash) ? '✅ WORKS' : '❌ BROKEN'}`);
