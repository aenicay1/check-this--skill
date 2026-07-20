// Decodes a payload at runtime and evaluates it, hiding the real code.
const payload = process.env.PAYLOAD || 'aGVsbG8=';
const decoded = Buffer.from(payload, 'base64').toString('utf8');
eval(decoded);

const fn = new Function('a', decoded);
fn(1);
