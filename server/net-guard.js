const dns = require('node:dns').promises;
const net = require('node:net');

// SSRF guard for URLs the server fetches on instruction from a third party (currently
// the raw-download link in a Resend API response). That response is only as trustworthy
// as the provider account behind it: a compromised or spoofed answer must not be able to
// turn this server into a probe of the internal network or the cloud metadata endpoint
// (169.254.169.254). A fetched URL must therefore be https on the default port, and its
// host must not be — or resolve to — a private, loopback, link-local or otherwise
// non-public address. An optional allowlist pins it tighter still.
//
// This does NOT defend against DNS rebinding (the resolved address could change between
// this check and the fetch). That is out of scope here: the URL comes from an
// authenticated provider API, not an arbitrary attacker, so the realistic threat is a
// bad URL value, not a race on name resolution. Pair with redirect:'error' at the fetch
// so an allowed host cannot 30x-redirect into the network.

function ipv4IsPrivate(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = p;
  return (
    a === 0 ||                                  // "this network"
    a === 10 ||                                 // 10/8 private
    a === 127 ||                                // loopback
    (a === 100 && b >= 64 && b <= 127) ||       // 100.64/10 CGNAT
    (a === 169 && b === 254) ||                 // 169.254/16 link-local (incl. metadata)
    (a === 172 && b >= 16 && b <= 31) ||        // 172.16/12 private
    (a === 192 && b === 0 && c === 0) ||        // 192.0.0/24 IETF
    (a === 192 && b === 168) ||                 // 192.168/16 private
    (a === 198 && (b === 18 || b === 19)) ||    // 198.18/15 benchmarking
    a >= 224                                    // 224/4 multicast + 240/4 reserved
  );
}

function ipv6IsPrivate(ip) {
  const s = ip.toLowerCase().split('%')[0]; // drop any zone id
  if (s === '::1' || s === '::') return true;
  // Link-local fe80::/10 and unique-local fc00::/7 (fc.. / fd..).
  if (/^fe[89ab]/.test(s) || /^f[cd]/.test(s)) return true;
  // IPv4-mapped ::ffff:a.b.c.d — Node may also hand it back as ::ffff:aabb:ccdd, so
  // accept the hex form and fold it to the embedded IPv4 before judging it.
  const mapped = s.match(/^::ffff:(.+)$/);
  if (mapped) {
    const rest = mapped[1];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(rest)) return ipv4IsPrivate(rest);
    const hex = rest.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16); const lo = parseInt(hex[2], 16);
      return ipv4IsPrivate([(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255].join('.'));
    }
    return true; // an unexpected mapped shape is treated as unsafe
  }
  return false;
}

// A literal address is unsafe when it is non-public; anything that is not a valid IP
// is treated as unsafe so an unexpected shape never slips through.
function addressIsPrivate(ip) {
  return net.isIPv4(ip) ? ipv4IsPrivate(ip) : net.isIPv6(ip) ? ipv6IsPrivate(ip) : true;
}

// Throws when `url` is not a safe, public https URL to fetch. `allowlist` (registrable
// hosts) further restricts the host to those names or their subdomains when non-empty.
async function assertPublicHttpsUrl(url, { allowlist = [] } = {}) {
  let u;
  try { u = new URL(url); } catch { throw new Error('insecure fetch URL: unparseable'); }
  if (u.protocol !== 'https:') throw new Error('insecure fetch URL: not https');
  if (u.port && u.port !== '443') throw new Error('insecure fetch URL: non-default port');
  if (u.username || u.password) throw new Error('insecure fetch URL: embedded credentials');

  const host = u.hostname.toLowerCase();
  if (allowlist.length && !allowlist.some((h) => host === h || host.endsWith(`.${h}`))) {
    throw new Error('insecure fetch URL: host not in allowlist');
  }

  // URL parsing wraps IPv6 literals in brackets; strip them before the IP check.
  const literal = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (net.isIP(literal)) {
    if (addressIsPrivate(literal)) throw new Error('insecure fetch URL: private address');
    return;
  }
  // A name: refuse it if ANY address it resolves to is non-public, so a host that points
  // inside the network (or has no addresses at all) cannot be reached.
  let addrs;
  try { addrs = await dns.lookup(host, { all: true }); } catch { throw new Error('insecure fetch URL: host does not resolve'); }
  if (!addrs.length || addrs.some((a) => addressIsPrivate(a.address))) {
    throw new Error('insecure fetch URL: host resolves to a private address');
  }
}

module.exports = { assertPublicHttpsUrl, addressIsPrivate };
