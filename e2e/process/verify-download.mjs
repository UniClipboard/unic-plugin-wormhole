import { createHash } from 'node:crypto';
import { createClient } from '@ziuchen/wormhole-client';

let link = '';
for await (const data of process.stdin) link += data;
try {
  const client = createClient({ retries: 1, timeout: 30_000 });
  const result = await client.download(link, {signal: AbortSignal.timeout(90_000)});
  const roomURL = new URL(link);
  const salt = await fetch(`https://wormhole.app/api/room/${roomURL.pathname.slice(1)}/salt`, {signal: AbortSignal.timeout(15_000)});
  if (!salt.ok) throw new Error('salt');
  const { Keychain } = await import('wormhole-crypto');
  const key = new Keychain(roomURL.hash.slice(1), (await salt.json()).salt);
  const room = await fetch(`https://wormhole.app/api/room/${roomURL.pathname.slice(1)}`, {
    headers: {Authorization: await key.authHeader()}, signal: AbortSignal.timeout(15_000)
  });
  if (!room.ok) throw new Error('room');
  console.log(JSON.stringify({
    lifetime: (await room.json()).lifetime,
    files: Object.fromEntries(result.files.map(({name, data}) => [
      name, {size: data.byteLength, sha256: createHash('sha256').update(data).digest('hex')}
    ]))
  }));
} catch (error) {
  console.error('Recipient check failed', error?.name, error?.status ?? '');
  process.exitCode = 1;
}
