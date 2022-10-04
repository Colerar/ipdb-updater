# ipdb-updater

A tool to download ipip.net `.ipdb` files.

## Usage

Help:

```plaintext
> ipdb-ipdater -h
Usage: ipdb-updater [OPTIONS] <--token-v4 <TOKEN>|--token-v6 <TOKEN>>

Options:
  -4, --token-v4 <TOKEN>        Token for downloading IPV4 db [env: IPIP_TOKEN_V4=]
  -6, --token-v6 <TOKEN>        Token for downloading IPV6 db [env: IPIP_TOKEN_V6=]
  -p, --proxy <PROXY>           Proxy string, schema://addr:port, SOCKS5 and HTTP(S) are supported [env: IPDB_PROXY=]
  -l, --language <LANG>         Language to download [default: EN]
  -o, --output-dir <DIR>        
  -t, --telegram-token <TOKEN>  Telegram token, get it from @BotFather [env: TG_TOKEN=]
  -c, --target-chat <CHAT_ID>   Where files upload to, chat id like '@this_is_a_id', [env: TG_CHAT_ID=]
  -v, --verbose...              More output per occurrence
  -q, --quiet...                Less output per occurrence
  -h, --help                    Print help information
```

- Basic Usage: `ipdb-updater -4 xxxxxxxxxxx -6 xxxxxxxxx`
- Upload to Telegram: `ipdb-updater -4 xxxxxxxxxxx -6 xxxxxxxxx -t 12312312:XXXXXXX -c @123123123`
- With environment variable:
  - Useful for run in container and hide secrets.
  - `IPIP_TOKEN_V4=xxxxx IP_TOKEN_V6=xxxxxxx TG_TOKEN=123123:123123123xxasdfAsad TG_CHAT_ID=-10023423423 ipdb-updater`
- With proxy:
  - Useful in areas where Telegram is blocked and for hiding your identity.
  - `IPDB_PROXY=socks5://127.0.0.1:7000 ipdb-updater -4 xxxxxxxxxxx -6 xxxxxxxxx`
- With crontab:
  - `crontab -e`
  - Append line: `0 12 * * * /path/to/ipdb-updater -4 xxxx -6 xxxx -t xxxx -c -1001233348238 -o /path/to/output`
  - This way `ipdb-updater` will run at 12:00 every day.

## Build

```bash
cargo build --release
```

The target binary is at `target/release/ipdb-updater`.

## License

Licensed under the terms of [the MIT License](/LICENSE)
