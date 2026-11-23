# Wormhole for UniClipboard

An official UniClipboard plugin that creates an encrypted temporary download
link using [Wormhole](https://wormhole.app/). It requires no account or
settings. Select a text, image, or file item in history and choose the
Wormhole Action. Desktop copies and presents the resulting link.

## Install

Choose **Settings > Plugins > Plugin Marketplace** and install **Wormhole**.
Restart the service after installation. To install from the CLI:

```sh
unic plugin install https://github.com/UniClipboard/unic-plugin-wormhole --ref v0.1.0 --enable
unic history action @1 unic.wormhole/share
```

The CLI stores the link as a new text item in history. Pass `--apply` when a
desktop clipboard adapter is running to copy the result. The source stays
in history.

## Sharing behavior

- Text uploads as UTF-8 in `clipboard.txt`. Images keep their stored encoding.
- A file selection produces one link, including any empty files. Directory
  selections are unsupported. The encrypted selection must fit within 5 GB
  and finish within the host's five-minute Action deadline.
- The plugin encrypts the content and names locally. It sends ciphertext to
  Wormhole and Backblaze only when you run the Action. The download link
  carries the decryption key in its fragment. Anyone with the full link can
  decrypt the contents. The link follows the host's usual history and sync
  settings.
- Wormhole uses its default 24-hour expiration. An upload that fails or is
  cancelled before confirmation creates no result in UniClipboard. Partial
  ciphertext may remain at the provider until expiration.
- The plugin speaks the website's upload protocol. A provider protocol change
  can require a plugin update. See [Wormhole security](https://wormhole.app/security)
  and the [Wormhole FAQ](https://wormhole.app/faq).

## Verification

Use Go 1.27.3. Run `sh scripts/verify.sh` for an isolated provider fixture and a
real Engine-to-plugin RPC process. To run live upload and independent download
with synthetic content, use Node.js 22.12 or later and run:

```sh
UNIC_WORMHOLE_LIVE=1 sh scripts/verify.sh
```

The redacted JSON receipt is saved under `.cache/acceptance/`. Run
`sh scripts/package.sh` to build the six release archives and print their
manifest entries. See [acceptance](ACCEPTANCE.md) for covered boundaries.
