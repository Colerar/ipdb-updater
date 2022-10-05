use std::{
  borrow::Cow,
  fs::{self, File},
  io::{BufWriter, Write},
  path::PathBuf,
  sync::Arc,
};

use anyhow::{ensure, Context, Result};
use chrono::Local;
use clap::{ArgGroup, Parser, ValueHint};
use clap_verbosity_flag::{LogLevel, Verbosity};
use frankenstein::{AsyncApi, AsyncTelegramApi, SendDocumentParams};
use log::{debug, error, info, LevelFilter};
use log4rs::{
  append::console::ConsoleAppender,
  config::{Appender, Root},
  encode::pattern::PatternEncoder,
  Config,
};
use reqwest::{Client, Proxy};
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(group(
  ArgGroup::new("tokens")
    .required(true)
    .multiple(true)
    .args(&["token_v4", "token_v6"])
))]
struct Cli {
  /// Token for downloading IPV4 db
  #[arg(short = '4', long, env = "IPIP_TOKEN_V4", value_name = "TOKEN")]
  token_v4: Option<String>,
  /// Token for downloading IPV6 db
  #[arg(short = '6', long, env = "IPIP_TOKEN_V6", value_name = "TOKEN")]
  token_v6: Option<String>,
  /// Proxy string, schema://addr:port, SOCKS5 and HTTP(S) are supported
  #[arg(short, long, env = "IPDB_PROXY")]
  proxy: Option<String>,
  /// Language to download
  #[arg(short, long, value_name = "LANG", default_value_t = Cow::Borrowed("EN"))]
  language: Cow<'static, str>,
  #[arg(short = 'o', long, value_name = "DIR")]
  #[arg(value_hint = ValueHint::DirPath)]
  output_dir: Option<PathBuf>,
  /// Telegram token, get it from @BotFather
  #[arg(short = 't', long, value_name = "TOKEN", env = "TG_TOKEN")]
  telegram_token: Option<String>,
  /// Where files upload to, chat id like '@this_is_a_id',
  #[arg(short = 'c', long, value_name = "CHAT_ID", env = "TG_CHAT_ID")]
  #[arg(allow_hyphen_values = true)]
  target_chat: Option<String>,
  #[clap(flatten)]
  verbose: Verbosity<DefaultLevel>,
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Cli::parse();
  debug!("{args:?}");
  init_logger(args.verbose.log_level_filter());

  let output_dir = if let Some(dir) = args.output_dir {
    dir
  } else {
    std::env::current_dir().expect("Failed to get current dir")
  };

  info!("Output dir: {}", &output_dir.to_string_lossy());

  let mut cli = Client::builder();
  if let Some(proxy) = args.proxy {
    let proxy =
      Proxy::all(proxy.clone()).with_context(|| format!("Failed to set \"{proxy}\" as proxy"))?;
    cli = cli.proxy(proxy);
  }
  let cli = cli.build()?;

  let tg_api = if args.telegram_token.is_none() ^ args.target_chat.is_none() {
    error!("--telegram-token and --target-chat must be provided together.");
    std::process::exit(1);
  } else if args.telegram_token.is_some() {
    let tg_api = AsyncApi::builder()
      .api_url(format!(
        "{}{}",
        frankenstein::BASE_API_URL,
        &*args.telegram_token.unwrap()
      ))
      .client(cli.clone())
      .build();
    let me = tg_api
      .get_me()
      .await
      .context("Failed to get telegram bot self info")?;
    info!(
      "Current tg bot: {}",
      me.result
        .username
        .context("Failed to get username for bot, maybe token is invalid")?
    );
    Some(tg_api)
  } else {
    None
  };

  let today = format!("{}", Local::now().format("%Y%m%d"));
  let dir = {
    let mut path = output_dir.clone();
    path.push(format!("./ipip-{today}"));
    path
  };
  fs::create_dir_all(&dir)
    .with_context(|| format!("Failed to create directory of {}", &dir.to_string_lossy()))?;
  let tarxz_path = {
    let mut path = output_dir.clone();
    path.push(format!("./ipip-{today}.tar.xz"));
    path
  };
  let ipv4 = {
    let mut path = dir.clone();
    path.push("./v4.ipdb");
    path
  };
  let ipv6 = {
    let mut path = dir.clone();
    path.push("./v6.ipdb");
    path
  };

  let sha1sums = Arc::new(Mutex::new(Vec::new()));

  let download = |name: &'static str, path: PathBuf, token: String| {
    let sha1sums = Arc::clone(&sha1sums);
    async move {
      info!("Downloading {} IPDB", name);
      ensure!(
        !path.exists(),
        format!(
          "The file on path already exists: {}",
          path.to_string_lossy()
        )
      );
      let file = File::create(&path).with_context(|| {
        format!(
          "Failed to create {name} IPDB file at: {}",
          path.to_string_lossy()
        )
      })?;
      let mut buf_writer = BufWriter::new(file);
      let (data, sha1) = fetch_ipdb(&cli, args.language, token)
        .await
        .context("Failed to download {name} IPDB")?;
      info!("Writing to file: {}", path.to_string_lossy());
      buf_writer
        .write_all(&*data)
        .with_context(|| format!("Failed to write data to file {}", path.to_string_lossy()))?;
      if let Some(sha1) = sha1 {
        info!("Checksum: {}", sha1);
        let mut sha1sums = sha1sums.lock().await;
        sha1sums.push((
          path
            .file_name()
            .context("Failed to get file name")?
            .to_string_lossy()
            .into_owned(),
          sha1,
        ));
      }
      Ok(())
    }
  };
  if let Some(token) = args.token_v4 {
    download.clone()("IPV4", ipv4, token).await?;
  }
  if let Some(token) = args.token_v6 {
    download("IPV6", ipv6, token).await?;
  }

  let sha1sums = Arc::clone(&sha1sums);
  let sha1sums = &sha1sums.lock().await;
  let sha1sums = sha1sums.iter().fold(
    "SHA-1 Checksums:".to_string(),
    |acc, (filename, checksum)| format!("{acc}\n{filename}: {checksum}"),
  );

  let tg_api = if let Some(tg) = tg_api {
    tg
  } else {
    return Ok(());
  };

  {
    info!("Compressing files...");
    let tarxz = File::create(&tarxz_path).with_context(|| {
      format!(
        "Failed to create archive file: {}",
        tarxz_path.to_string_lossy()
      )
    })?;
    let enc = xz2::write::XzEncoder::new(tarxz, 6);
    let mut tar = tar::Builder::new(enc);
    tar
      .append_dir_all(".", &dir)
      .context("Failed to compress files...")?;
    // RAII: tar.finish() here
  }

  info!("Sending files to telegram...");
  let target_chat = args.target_chat.clone().unwrap();
  tg_api
    .send_document(
      &SendDocumentParams::builder()
        .chat_id(target_chat.clone())
        .document(tarxz_path)
        .caption(sha1sums)
        .build(),
    )
    .await
    .with_context(|| format!("Failed to send file to chat '{}'", &target_chat))?;

  info!("Removing the source directory of archive...");

  fs::remove_dir_all(&dir)
    .with_context(|| format!("Failed to remove directory: {}", dir.to_string_lossy()))?;

  Ok(())
}

async fn fetch_ipdb(
  cli: &Client,
  language: Cow<'static, str>,
  token: String,
) -> Result<(Vec<u8>, Option<String>)> {
  let resp = cli
    .get("https://user.ipip.net/download.php")
    .query(&[("type", "ipdb"), ("lang", &*language), ("token", &*token)])
    .send()
    .await
    .context("Failed to download IPDB")?;
  let checksum = resp.headers().get("ETag").map(|etag| {
    String::from_utf8_lossy(etag.as_bytes())
      .chars()
      .skip(5)
      .collect::<String>()
  });
  let vec = resp
    .bytes()
    .await
    .context("Failed to get IPDB resp body as Bytes")?
    .to_vec();
  Ok((vec, checksum))
}

#[cfg(debug_assertions)]
type DefaultLevel = DebugLevel;

#[cfg(not(debug_assertions))]
type DefaultLevel = clap_verbosity_flag::InfoLevel;

#[derive(Copy, Clone, Debug, Default)]
pub struct DebugLevel;

impl LogLevel for DebugLevel {
  fn default() -> Option<log::Level> {
    Some(log::Level::Debug)
  }
}

fn init_logger(verbosity: LevelFilter) {
  const PATTERN: &str = "{d(%m-%d %H:%M)} {h({l:.1})} - {h({m})}{n}";
  let stdout = ConsoleAppender::builder()
    .encoder(Box::new(PatternEncoder::new(PATTERN)))
    .build();
  let config = Config::builder()
    .appender(Appender::builder().build("stdout", Box::new(stdout)))
    .build(Root::builder().appender("stdout").build(verbosity))
    .unwrap();
  log4rs::init_config(config).unwrap();
}
