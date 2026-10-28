import { SAMPLE_JWT } from '../toolbox/jwt'
import type { SerializedRecipe } from './engine/recipe'

export interface ExampleRecipe {
  id: string
  name: string
  description: string
  recipe: SerializedRecipe
  input: string
}

export const EXAMPLES: readonly ExampleRecipe[] = [
  {
    id: 'b64-gunzip',
    name: 'Decode Base64 then Gunzip',
    description: 'A classic dropper pattern: gzip-compressed data wrapped in Base64.',
    recipe: { v: 1, steps: [{ op: 'from-base64' }, { op: 'gunzip' }] },
    input:
      'H4sIAAAAAAAACh3KQQrCQAwF0H1P8d2rK/EAegFBL5A2oRPIJENmSrGnF3zr9wxfk8ZmNDS8n/GNDSxLsDAI66ENs8WMosziUMeDutxvp+lTtKPRGJIO7Vii1viPSrZTCjijNckOcsYrdsl3ETOEy8XUJft1+gGfKaF+gQAAAA==',
  },
  {
    id: 'defang',
    name: 'Defang IOCs',
    description: 'Make URLs, domains, IPs and emails safe to paste into a report or ticket.',
    recipe: { v: 1, steps: [{ op: 'defang' }] },
    input:
      'Beacon to https://evil.example.com/gate.php from 203.0.113.45.\nPhishing sender: billing@pay-pal.example.net\nSecond stage hosted on cdn.badstuff.example.org',
  },
  {
    id: 'extract-iocs',
    name: 'Refang and extract URLs',
    description: 'Turn defanged indicators back into real ones, then list the unique URLs.',
    recipe: { v: 1, steps: [{ op: 'refang' }, { op: 'extract-urls', args: { sort: true } }] },
    input: 'IOCs: hxxps://login-microsoft[.]example[.]com/oauth and hxxp://198[.]51[.]100[.]7/payload.bin — also hxxps://login-microsoft[.]example[.]com/oauth',
  },
  {
    id: 'jwt',
    name: 'JWT decode',
    description: 'Decode the header and payload of a JSON Web Token (signature not verified).',
    recipe: { v: 1, steps: [{ op: 'jwt-decode' }] },
    input: SAMPLE_JWT,
  },
  {
    id: 'xor-brute',
    name: 'XOR brute force',
    description: 'Hex-encoded data XORed with an unknown single-byte key. The best-scoring key is 0x5a.',
    recipe: { v: 1, steps: [{ op: 'from-hex' }, { op: 'xor-brute-force', args: { top: 5 } }] },
    input:
      '0e323f7a3b3e3733347a2a3b29292d35283e7a3c35287a2e323f7a292e3b3d33343d7a293f282c3f287a33297a322f342e3f2868747a08352e3b2e3f7a332e7a3b3c2e3f287a2e323f7a3b2f3e332e74',
  },
  {
    id: 'layered',
    name: 'Layered encoding (try Magic)',
    description: 'Hex of Base64 of JSON. The recipe is empty: open the Magic panel to find the chain.',
    recipe: { v: 1, steps: [] },
    input: '65794a3163325679496a6f6959577870593255694c434a796232786c496a6f69595752746157346966513d3d',
  },
  {
    id: 'aes-gcm',
    name: 'AES-GCM encrypt',
    description: 'Encrypt text with AES-256-GCM. Change the key and use a fresh random 12-byte IV for every message.',
    recipe: {
      v: 1,
      steps: [
        {
          op: 'aes-encrypt',
          args: {
            key: { value: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', encoding: 'hex' },
            iv: { value: 'cafebabefacedbaddecaf888', encoding: 'hex' },
            output: 'base64',
          },
        },
      ],
    },
    input: 'Attack at dawn',
  },
  {
    id: 'hexdump',
    name: 'Hexdump',
    description: 'Inspect raw bytes with offsets, hex and ASCII columns.',
    recipe: { v: 1, steps: [{ op: 'to-hexdump' }] },
    input: 'Hello, Data Lab!\u0000\u0001\u0002 Binary bytes and UTF-8: é ✓',
  },
]
