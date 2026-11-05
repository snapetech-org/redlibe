use crate::tls_connector::HttpsConnector;
use arc_swap::ArcSwap;
use cached::proc_macro::cached;
use futures_lite::future::block_on;
use futures_lite::{future::Boxed, FutureExt};
use hyper::header::HeaderValue;
use hyper::{body, body::Buf, header, Body, Client, Method, Request, Response, Uri};
use libflate::gzip;
use log::{error, trace, warn};
use percent_encoding::{percent_encode, CONTROLS};
use serde_json::Value;

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32};
use std::sync::LazyLock;
use std::{io, result::Result};
use tokio::sync::oneshot;

use crate::auth::{refresh_access_token, AuthContext, SessionData};
use crate::dbg_msg;
use crate::oauth::{force_refresh_token, token_daemon, Oauth, OauthBackendImpl};
use crate::server::RequestExt;
use crate::utils::{format_url, Post};

const REDDIT_URL_BASE: &str = "https://oauth.reddit.com";
const REDDIT_URL_BASE_HOST: &str = "oauth.reddit.com";

const REDDIT_SHORT_URL_BASE: &str = "https://redd.it";
const REDDIT_SHORT_URL_BASE_HOST: &str = "redd.it";

const ALTERNATIVE_REDDIT_URL_BASE: &str = "https://www.reddit.com";
const ALTERNATIVE_REDDIT_URL_BASE_HOST: &str = "www.reddit.com";

pub static HTTPS_CONNECTOR: LazyLock<HttpsConnector> = LazyLock::new(|| HttpsConnector::new().expect("load native trust roots for upstream HTTPS"));

pub static CLIENT: LazyLock<Client<HttpsConnector>> = LazyLock::new(|| Client::builder().build::<_, Body>(HTTPS_CONNECTOR.clone()));

pub static OAUTH_CLIENT: LazyLock<ArcSwap<Oauth>> = LazyLock::new(|| {
	let client = block_on(Oauth::new());
	tokio::spawn(token_daemon());
	ArcSwap::new(client.into())
});

pub static OAUTH_RATELIMIT_REMAINING: AtomicU16 = AtomicU16::new(99);

pub static OAUTH_IS_ROLLING_OVER: AtomicBool = AtomicBool::new(false);
static UPSTREAM_CIRCUIT_OPEN_UNTIL_EPOCH_SECS: AtomicI64 = AtomicI64::new(0);
static UPSTREAM_CONSECUTIVE_FAILURES: AtomicU32 = AtomicU32::new(0);
static UPSTREAM_FAILURE_403_HTML: AtomicU32 = AtomicU32::new(0);
static UPSTREAM_FAILURE_429: AtomicU32 = AtomicU32::new(0);
static UPSTREAM_FAILURE_PARSE: AtomicU32 = AtomicU32::new(0);
static UPSTREAM_FAILURE_TRANSPORT: AtomicU32 = AtomicU32::new(0);
static UPSTREAM_SUCCESS_COUNT: AtomicU32 = AtomicU32::new(0);
static JSON_COALESCE_LEADER_COUNT: AtomicU32 = AtomicU32::new(0);
static JSON_COALESCE_FOLLOWER_COUNT: AtomicU32 = AtomicU32::new(0);
static JSON_COALESCE_BROADCAST_COUNT: AtomicU32 = AtomicU32::new(0);
static INFLIGHT_JSON_REQUESTS: LazyLock<std::sync::Mutex<HashMap<String, Vec<oneshot::Sender<Result<Value, String>>>>>> =
	LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

const URL_PAIRS: [(&str, &str); 2] = [
	(ALTERNATIVE_REDDIT_URL_BASE, ALTERNATIVE_REDDIT_URL_BASE_HOST),
	(REDDIT_SHORT_URL_BASE, REDDIT_SHORT_URL_BASE_HOST),
];

const JSON_RETRY_ATTEMPTS: u8 = 3;
const JSON_BACKOFF_BASE_MS: u64 = 150;
const UPSTREAM_CIRCUIT_TRIP_FAILURES: u32 = 6;
const UPSTREAM_CIRCUIT_OPEN_SECS: i64 = 20;

fn now_epoch_secs() -> i64 {
	time::OffsetDateTime::now_utc().unix_timestamp()
}

fn log_upstream_event(path: &str, event: &str, status: Option<u16>, attempt: u8, detail: &str) {
	warn!(
		"upstream_event event={event} status={} attempt={} path={} detail={}",
		status.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string()),
		attempt,
		path,
		detail.replace('\n', " ")
	);
}

fn on_upstream_success() {
	UPSTREAM_CONSECUTIVE_FAILURES.store(0, Ordering::SeqCst);
	UPSTREAM_SUCCESS_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn on_upstream_failure(path: &str, category: &str, status: Option<u16>, attempt: u8, detail: &str) {
	match category {
		"html_403" => {
			UPSTREAM_FAILURE_403_HTML.fetch_add(1, Ordering::SeqCst);
		}
		"http_429" => {
			UPSTREAM_FAILURE_429.fetch_add(1, Ordering::SeqCst);
		}
		"parse" => {
			UPSTREAM_FAILURE_PARSE.fetch_add(1, Ordering::SeqCst);
		}
		"transport" => {
			UPSTREAM_FAILURE_TRANSPORT.fetch_add(1, Ordering::SeqCst);
		}
		_ => {}
	}
	let failures = UPSTREAM_CONSECUTIVE_FAILURES.fetch_add(1, Ordering::SeqCst) + 1;
	log_upstream_event(path, category, status, attempt, detail);
	if failures >= UPSTREAM_CIRCUIT_TRIP_FAILURES {
		UPSTREAM_CIRCUIT_OPEN_UNTIL_EPOCH_SECS.store(now_epoch_secs() + UPSTREAM_CIRCUIT_OPEN_SECS, Ordering::SeqCst);
	}
}

fn upstream_circuit_message(path: &str) -> Option<String> {
	let open_until = UPSTREAM_CIRCUIT_OPEN_UNTIL_EPOCH_SECS.load(Ordering::SeqCst);
	let now = now_epoch_secs();
	if open_until > now {
		let remaining = open_until - now;
		return Some(format!(
			"Reddit upstream is temporarily failing repeatedly (circuit breaker open for ~{remaining}s). \
			 Please retry shortly or log in so requests can use your account token. | {path}"
		));
	}
	None
}

fn should_retry_json_error(msg: &str) -> bool {
	msg.contains("Couldn't send request to Reddit")
		|| msg.contains("Failed receiving body from Reddit")
		|| msg.contains("Reddit rate limit exceeded")
		|| msg.contains("HTTP 429")
		|| msg.contains("HTTP 403")
		|| msg.contains("Reddit is having issues")
		|| msg.contains("anonymous OAuth flow may be failing")
}

async fn sleep_backoff_with_jitter(attempt: u8) {
	let factor = 1u64 << attempt.saturating_sub(1);
	let jitter = fastrand::u64(0..JSON_BACKOFF_BASE_MS);
	let delay = JSON_BACKOFF_BASE_MS.saturating_mul(factor).saturating_add(jitter);
	tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
}

pub fn upstream_metrics_snapshot_json() -> String {
	format!(
		r#"{{"success":{},"consecutive_failures":{},"html_403":{},"http_429":{},"parse":{},"transport":{},"circuit_open_until":{},"coalesce_leaders":{},"coalesce_followers":{},"coalesce_broadcasts":{},"coalesce_inflight":{},"oauth_backend":"{}","oauth_ratelimit_remaining":{},"oauth_is_rolling_over":{}}}"#,
		UPSTREAM_SUCCESS_COUNT.load(Ordering::Relaxed),
		UPSTREAM_CONSECUTIVE_FAILURES.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_403_HTML.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_429.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_PARSE.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_TRANSPORT.load(Ordering::Relaxed),
		UPSTREAM_CIRCUIT_OPEN_UNTIL_EPOCH_SECS.load(Ordering::Relaxed),
		JSON_COALESCE_LEADER_COUNT.load(Ordering::Relaxed),
		JSON_COALESCE_FOLLOWER_COUNT.load(Ordering::Relaxed),
		JSON_COALESCE_BROADCAST_COUNT.load(Ordering::Relaxed),
		inflight_json_count(),
		oauth_backend_label(),
		OAUTH_RATELIMIT_REMAINING.load(Ordering::Relaxed),
		if OAUTH_IS_ROLLING_OVER.load(Ordering::Relaxed) { "true" } else { "false" }
	)
}

fn oauth_backend_label() -> &'static str {
	match &OAUTH_CLIENT.load().backend {
		OauthBackendImpl::GenericWeb(_) => "generic_web",
		OauthBackendImpl::MobileSpoof(_) => "mobile_spoof",
	}
}

fn inflight_json_count() -> usize {
	INFLIGHT_JSON_REQUESTS.lock().map(|m| m.len()).unwrap_or_default()
}

pub fn upstream_prometheus_metrics() -> String {
	let circuit_open = if UPSTREAM_CIRCUIT_OPEN_UNTIL_EPOCH_SECS.load(Ordering::Relaxed) > now_epoch_secs() {
		1
	} else {
		0
	};
	let oauth_backend_is_generic = if oauth_backend_label() == "generic_web" { 1 } else { 0 };
	format!(
		concat!(
			"# TYPE redlib_upstream_success_total counter\n",
			"redlib_upstream_success_total {}\n",
			"# TYPE redlib_upstream_failures_total counter\n",
			"redlib_upstream_failures_total{{type=\"html_403\"}} {}\n",
			"redlib_upstream_failures_total{{type=\"http_429\"}} {}\n",
			"redlib_upstream_failures_total{{type=\"parse\"}} {}\n",
			"redlib_upstream_failures_total{{type=\"transport\"}} {}\n",
			"# TYPE redlib_upstream_consecutive_failures gauge\n",
			"redlib_upstream_consecutive_failures {}\n",
			"# TYPE redlib_upstream_circuit_open gauge\n",
			"redlib_upstream_circuit_open {}\n",
			"# TYPE redlib_upstream_circuit_open_until_epoch_seconds gauge\n",
			"redlib_upstream_circuit_open_until_epoch_seconds {}\n",
			"# TYPE redlib_json_coalesced_requests_total counter\n",
			"redlib_json_coalesced_requests_total{{role=\"leader\"}} {}\n",
			"redlib_json_coalesced_requests_total{{role=\"follower\"}} {}\n",
			"# TYPE redlib_json_coalesce_broadcasts_total counter\n",
			"redlib_json_coalesce_broadcasts_total {}\n",
			"# TYPE redlib_json_coalesce_inflight gauge\n",
			"redlib_json_coalesce_inflight {}\n",
			"# TYPE redlib_oauth_ratelimit_remaining gauge\n",
			"redlib_oauth_ratelimit_remaining {}\n",
			"# TYPE redlib_oauth_refresh_rolling gauge\n",
			"redlib_oauth_refresh_rolling {}\n",
			"# TYPE redlib_oauth_backend_generic_web gauge\n",
			"redlib_oauth_backend_generic_web {}\n"
		),
		UPSTREAM_SUCCESS_COUNT.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_403_HTML.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_429.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_PARSE.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_TRANSPORT.load(Ordering::Relaxed),
		UPSTREAM_CONSECUTIVE_FAILURES.load(Ordering::Relaxed),
		circuit_open,
		UPSTREAM_CIRCUIT_OPEN_UNTIL_EPOCH_SECS.load(Ordering::Relaxed),
		JSON_COALESCE_LEADER_COUNT.load(Ordering::Relaxed),
		JSON_COALESCE_FOLLOWER_COUNT.load(Ordering::Relaxed),
		JSON_COALESCE_BROADCAST_COUNT.load(Ordering::Relaxed),
		inflight_json_count(),
		OAUTH_RATELIMIT_REMAINING.load(Ordering::Relaxed),
		if OAUTH_IS_ROLLING_OVER.load(Ordering::Relaxed) { 1 } else { 0 },
		oauth_backend_is_generic
	)
}

pub fn upstream_diagnostics_snapshot() -> String {
	format!(
		"backend={}; ratelimit_remaining={}; rolling_refresh={}; consecutive_failures={}; circuit_open_until={}; success={}; html_403={}; http_429={}; parse={}; transport={}; coalesce_inflight={}; coalesce_followers={}",
		oauth_backend_label(),
		OAUTH_RATELIMIT_REMAINING.load(Ordering::Relaxed),
		OAUTH_IS_ROLLING_OVER.load(Ordering::Relaxed),
		UPSTREAM_CONSECUTIVE_FAILURES.load(Ordering::Relaxed),
		UPSTREAM_CIRCUIT_OPEN_UNTIL_EPOCH_SECS.load(Ordering::Relaxed),
		UPSTREAM_SUCCESS_COUNT.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_403_HTML.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_429.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_PARSE.load(Ordering::Relaxed),
		UPSTREAM_FAILURE_TRANSPORT.load(Ordering::Relaxed),
		inflight_json_count(),
		JSON_COALESCE_FOLLOWER_COUNT.load(Ordering::Relaxed)
	)
}

/// Gets the canonical path for a resource on Reddit. This is accomplished by
/// making a `HEAD` request to Reddit at the path given in `path`.
///
/// This function returns `Ok(Some(path))`, where `path`'s value is identical
/// to that of the value of the argument `path`, if Reddit responds to our
/// `HEAD` request with a 2xx-family HTTP code. It will also return an
/// `Ok(Some(String))` if Reddit responds to our `HEAD` request with a
/// `Location` header in the response, and the HTTP code is in the 3xx-family;
/// the `String` will contain the path as reported in `Location`. The return
/// value is `Ok(None)` if Reddit responded with a 3xx, but did not provide a
/// `Location` header. An `Err(String)` is returned if Reddit responds with a
/// 429, or if we were unable to decode the value in the `Location` header.
#[cached(size = 1024, time = 600, result = true)]
#[async_recursion::async_recursion]
pub async fn canonical_path(path: String, tries: i8) -> Result<Option<String>, String> {
	if tries == 0 {
		return Ok(None);
	}

	// for each URL pair, try the HEAD request
	let res = {
		// for url base and host in URL_PAIRS, try reddit_short_head(path.clone(), true, url_base, url_base_host) and if it succeeds, set res. else, res = None
		let mut res = None;
		for (url_base, url_base_host) in URL_PAIRS {
			res = reddit_short_head(path.clone(), true, url_base, url_base_host).await.ok();
			if let Some(res) = &res {
				if !res.status().is_client_error() {
					break;
				}
			}
		}
		res
	};

	let res = res.ok_or_else(|| "Unable to make HEAD request to Reddit.".to_string())?;
	let status = res.status().as_u16();
	let policy_error = res.headers().get(header::RETRY_AFTER).is_some();

	match status {
		// If Reddit responds with a 2xx, then the path is already canonical.
		200..=299 => Ok(Some(path)),

		// If Reddit responds with a 301, then the path is redirected.
		301 => match res.headers().get(header::LOCATION) {
			Some(val) => {
				let Ok(original) = val.to_str() else {
					return Err("Unable to decode Location header.".to_string());
				};

				// We need to strip the .json suffix from the original path.
				// In addition, we want to remove share parameters.
				// Cut it off here instead of letting it propagate all the way
				// to main.rs
				let stripped_uri = original.strip_suffix(".json").unwrap_or(original).split('?').next().unwrap_or_default();

				// The reason why we now have to format_url, is because the new OAuth
				// endpoints seem to return full paths, instead of relative paths.
				// So we need to strip the .json suffix from the original path, and
				// also remove all Reddit domain parts with format_url.
				// Otherwise, it will literally redirect to Reddit.com.
				let uri = format_url(stripped_uri);

				// Decrement tries and try again
				canonical_path(uri, tries - 1).await
			}
			None => Ok(None),
		},

		// If Reddit responds with anything other than 3xx (except for the 2xx and 301
		// as above), return a None.
		300..=399 => Ok(None),

		// Rate limiting
		429 => Err("Too many requests.".to_string()),

		// Special condition rate limiting - https://github.com/redlib-org/redlib/issues/229
		403 if policy_error => Err("Too many requests.".to_string()),

		_ => Ok(
			res
				.headers()
				.get(header::LOCATION)
				.map(|val| percent_encode(val.as_bytes(), CONTROLS).to_string().trim_start_matches(REDDIT_URL_BASE).to_string()),
		),
	}
}

pub async fn proxy(req: Request<Body>, format: &str) -> Result<Response<Body>, String> {
	let mut url = format!("{format}?{}", req.uri().query().unwrap_or_default());

	// For each parameter in request
	for (name, value) in &req.params() {
		// Fill the parameter value in the url
		url = url.replace(&format!("{{{name}}}"), value);
	}

	stream(&url, &req).await
}

async fn stream(url: &str, req: &Request<Body>) -> Result<Response<Body>, String> {
	// First parameter is target URL (mandatory).
	let parsed_uri = url.parse::<Uri>().map_err(|_| "Couldn't parse URL".to_string())?;

	// Build the hyper client from the HTTPS connector.
	let client: &LazyLock<Client<_, Body>> = &CLIENT;

	let mut builder = Request::get(parsed_uri);

	// Copy useful headers from original request
	for &key in &["Range", "If-Modified-Since", "If-None-Match", "Cache-Control"] {
		if let Some(value) = req.headers().get(key) {
			builder = builder.header(key, value);
		}
	}

	// Use the configured Firefox UA for all proxied media requests.
	builder = builder.header("User-Agent", crate::config::get_user_agent());

	let stream_request = builder.body(Body::empty()).map_err(|_| "Couldn't build empty body in stream".to_string())?;

	client
		.request(stream_request)
		.await
		.map(|mut res| {
			let mut rm = |key: &str| res.headers_mut().remove(key);

			rm("access-control-expose-headers");
			rm("server");
			rm("vary");
			rm("x-cdn");
			rm("x-cdn-client-region");
			rm("x-cdn-name");
			rm("x-cdn-server-region");
			rm("x-reddit-cdn");
			rm("x-reddit-video-features");
			rm("Nel");
			rm("Report-To");

			res
		})
		.map_err(|e| e.to_string())
}

/// Makes a GET request to Reddit at `path`. By default, this will honor HTTP
/// 3xx codes Reddit returns and will automatically redirect.
fn reddit_get(path: String, quarantine: bool) -> Boxed<Result<Response<Body>, String>> {
	request(&Method::GET, path, true, quarantine, REDDIT_URL_BASE, REDDIT_URL_BASE_HOST)
}

/// Makes a HEAD request to Reddit at `path, using the short URL base. This will not follow redirects.
fn reddit_short_head(path: String, quarantine: bool, base_path: &'static str, host: &'static str) -> Boxed<Result<Response<Body>, String>> {
	request(&Method::HEAD, path, false, quarantine, base_path, host)
}

// /// Makes a HEAD request to Reddit at `path`. This will not follow redirects.
// fn reddit_head(path: String, quarantine: bool) -> Boxed<Result<Response<Body>, String>> {
// 	request(&Method::HEAD, path, false, quarantine, false)
// }
// Unused - reddit_head is only ever called in the context of a short URL

/// Makes a request to Reddit. If `redirect` is `true`, `request_with_redirect`
/// will recurse on the URL that Reddit provides in the Location HTTP header
/// in its response.
fn request(method: &'static Method, path: String, redirect: bool, quarantine: bool, base_path: &'static str, host: &'static str) -> Boxed<Result<Response<Body>, String>> {
	// Build Reddit URL from path.
	let url = format!("{base_path}{path}");

	// Construct the hyper client from the HTTPS connector.
	let client: &LazyLock<Client<_, Body>> = &CLIENT;

	// Build request to Reddit. When making a GET, request gzip compression.
	// (Reddit doesn't do brotli yet.)
	let mut headers: Vec<(String, String)> = vec![
		("Host".into(), host.into()),
		("Accept-Encoding".into(), if method == Method::GET { "gzip".into() } else { "identity".into() }),
		(
			"Cookie".into(),
			if quarantine {
				"_options=%7B%22pref_quarantine_optin%22%3A%20true%2C%20%22pref_gated_sr_optin%22%3A%20true%7D".into()
			} else {
				"".into()
			},
		),
	];

	{
		let client = OAUTH_CLIENT.load_full();
		for (key, value) in client.headers_map.clone() {
			headers.push((key, value));
		}
	}

	// shuffle headers: https://github.com/redlib-org/redlib/issues/324
	fastrand::shuffle(&mut headers);

	// Always override User-Agent to the configured Firefox UA regardless of which
	// anonymous OAuth backend set it — this is a safety net for consistency.
	let configured_ua = crate::config::get_user_agent();
	for (key, value) in &mut headers {
		if key.eq_ignore_ascii_case("User-Agent") {
			*value = configured_ua.clone();
		}
	}

	let mut builder = Request::builder().method(method).uri(&url);

	for (key, value) in headers {
		builder = builder.header(key, value);
	}

	let builder = builder.body(Body::empty());

	async move {
		match builder {
			Ok(req) => match client.request(req).await {
				Ok(mut response) => {
					// Reddit may respond with a 3xx. Decide whether or not to
					// redirect based on caller params.
					if response.status().is_redirection() {
						if !redirect {
							return Ok(response);
						};
						let location_header = response.headers().get(header::LOCATION);
						if location_header == Some(&HeaderValue::from_static(ALTERNATIVE_REDDIT_URL_BASE)) {
							return Err("Reddit response was invalid".to_string());
						}
						return request(
							method,
							location_header
								.map(|val| {
									// We need to make adjustments to the URI
									// we get back from Reddit. Namely, we
									// must:
									//
									//     1. Remove the authority (e.g.
									//     https://www.reddit.com) that may be
									//     present, so that we recurse on the
									//     path (and query parameters) as
									//     required.
									//
									//     2. Percent-encode the path.
									let new_path = percent_encode(val.as_bytes(), CONTROLS)
										.to_string()
										.trim_start_matches(REDDIT_URL_BASE)
										.trim_start_matches(ALTERNATIVE_REDDIT_URL_BASE)
										.to_string();
									format!("{new_path}{}raw_json=1", if new_path.contains('?') { "&" } else { "?" })
								})
								.unwrap_or_default()
								.to_string(),
							true,
							quarantine,
							base_path,
							host,
						)
						.await;
					};

					match response.headers().get(header::CONTENT_ENCODING) {
						// Content not compressed.
						None => Ok(response),

						// Content encoded (hopefully with gzip).
						Some(hdr) => {
							match hdr.to_str() {
								Ok(val) => match val {
									"gzip" => {}
									"identity" => return Ok(response),
									_ => return Err("Reddit response was encoded with an unsupported compressor".to_string()),
								},
								Err(_) => return Err("Reddit response was invalid".to_string()),
							}

							// We get here if the body is gzip-compressed.

							// The body must be something that implements
							// std::io::Read, hence the conversion to
							// bytes::buf::Buf and then transformation into a
							// Reader.
							let mut decompressed: Vec<u8>;
							{
								let mut aggregated_body = match body::aggregate(response.body_mut()).await {
									Ok(b) => b.reader(),
									Err(e) => return Err(e.to_string()),
								};

								let mut decoder = match gzip::Decoder::new(&mut aggregated_body) {
									Ok(decoder) => decoder,
									Err(e) => return Err(e.to_string()),
								};

								decompressed = Vec::<u8>::new();
								if let Err(e) = io::copy(&mut decoder, &mut decompressed) {
									return Err(e.to_string());
								};
							}

							response.headers_mut().remove(header::CONTENT_ENCODING);
							response.headers_mut().insert(header::CONTENT_LENGTH, decompressed.len().into());
							*(response.body_mut()) = Body::from(decompressed);

							Ok(response)
						}
					}
				}
				Err(e) => {
					dbg_msg!("{method} {REDDIT_URL_BASE}{path}: {}", e);

					Err(e.to_string())
				}
			},
			Err(_) => Err("Post url contains non-ASCII characters".to_string()),
		}
	}
	.boxed()
}

/// Make a request to a Reddit API and parse the JSON response
#[cached(size = 100, time = 30, result = true)]
pub async fn json(path: String, quarantine: bool) -> Result<Value, String> {
	let coalesce_key = format!("{}|{}", if quarantine { "q" } else { "n" }, path);
	let follower_wait = {
		let mut inflight = INFLIGHT_JSON_REQUESTS.lock().map_err(|_| "JSON coalescing lock poisoned".to_string())?;
		if let Some(waiters) = inflight.get_mut(&coalesce_key) {
			let (tx, rx) = oneshot::channel();
			waiters.push(tx);
			JSON_COALESCE_FOLLOWER_COUNT.fetch_add(1, Ordering::Relaxed);
			Some(rx)
		} else {
			inflight.insert(coalesce_key.clone(), Vec::new());
			JSON_COALESCE_LEADER_COUNT.fetch_add(1, Ordering::Relaxed);
			None
		}
	};

	if let Some(rx) = follower_wait {
		return match rx.await {
			Ok(result) => result,
			Err(_) => json_uncached(path, quarantine).await,
		};
	}

	let result = json_uncached(path.clone(), quarantine).await;
	if let Ok(mut inflight) = INFLIGHT_JSON_REQUESTS.lock() {
		if let Some(waiters) = inflight.remove(&coalesce_key) {
			if !waiters.is_empty() {
				JSON_COALESCE_BROADCAST_COUNT.fetch_add(waiters.len() as u32, Ordering::Relaxed);
			}
			for tx in waiters {
				let _ = tx.send(result.clone());
			}
		}
	}
	result
}

async fn json_uncached(path: String, quarantine: bool) -> Result<Value, String> {
	// Fail fast during known upstream brownouts to avoid dogpiling Reddit.
	if let Some(msg) = upstream_circuit_message(&path) {
		return Err(msg);
	}

	let mut last_err: Option<String> = None;
	for attempt in 1..=JSON_RETRY_ATTEMPTS {
		match json_once(path.clone(), quarantine, attempt).await {
			Ok(v) => {
				on_upstream_success();
				return Ok(v);
			}
			Err(e) => {
				last_err = Some(e.clone());
				if attempt < JSON_RETRY_ATTEMPTS && should_retry_json_error(&e) {
					sleep_backoff_with_jitter(attempt).await;
					continue;
				}
				return Err(e);
			}
		}
	}
	Err(last_err.unwrap_or_else(|| format!("Unknown Reddit JSON fetch error | {path}")))
}

async fn json_once(path: String, quarantine: bool, attempt: u8) -> Result<Value, String> {
	// Closure to quickly build errors
	let err = |msg: &str, e: String, path: String| -> Result<Value, String> {
		// eprintln!("{} - {}: {}", url, msg, e);
		Err(format!("{msg}: {e} | {path}"))
	};

	// First, handle rolling over the OAUTH_CLIENT if need be.
	let current_rate_limit = OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst);
	let is_rolling_over = OAUTH_IS_ROLLING_OVER.load(Ordering::SeqCst);
	if current_rate_limit < 10 && !is_rolling_over {
		warn!("Rate limit {current_rate_limit} is low. Spawning force_refresh_token()");
		tokio::spawn(force_refresh_token());
	}
	OAUTH_RATELIMIT_REMAINING.fetch_sub(1, Ordering::SeqCst);

	// Fetch the url...
	match reddit_get(path.clone(), quarantine).await {
		Ok(response) => {
			let status = response.status();
			if status.as_u16() == 429 {
				on_upstream_failure(&path, "http_429", Some(429), attempt, "rate limited");
			}

			let reset: Option<String> = if let (Some(remaining), Some(reset), Some(used)) = (
				response.headers().get("x-ratelimit-remaining").and_then(|val| val.to_str().ok().map(|s| s.to_string())),
				response.headers().get("x-ratelimit-reset").and_then(|val| val.to_str().ok().map(|s| s.to_string())),
				response.headers().get("x-ratelimit-used").and_then(|val| val.to_str().ok().map(|s| s.to_string())),
			) {
				trace!(
					"Ratelimit remaining: Header says {remaining}, we have {current_rate_limit}. Resets in {reset}. Rollover: {}. Ratelimit used: {used}",
					if is_rolling_over { "yes" } else { "no" },
				);

				// If can parse remaining as a float, round to a u16 and save
				if let Ok(val) = remaining.parse::<f32>() {
					OAUTH_RATELIMIT_REMAINING.store(val.round() as u16, Ordering::SeqCst);
				}

				Some(reset)
			} else {
				None
			};

			// asynchronously aggregate the chunks of the body
			match hyper::body::aggregate(response).await {
				Ok(mut body) => {
					let has_remaining = body.has_remaining();

					if !has_remaining {
						// Rate limited, so spawn a force_refresh_token()
						tokio::spawn(force_refresh_token());
						return match reset {
							Some(val) => Err(format!(
								"Reddit rate limit exceeded. Try refreshing in a few seconds.\
									 Rate limit will reset in: {val}"
							)),
							None => Err("Reddit rate limit exceeded".to_string()),
						};
					}

					// Copy to bytes so we can inspect on parse failure
					let bytes = body.copy_to_bytes(body.remaining());

					// Parse the response from Reddit as JSON
					match serde_json::from_slice::<Value>(&bytes) {
						Ok(json) => {
							// If user is suspended
							if let Some(data) = json.get("data") {
								if let Some(is_suspended) = data.get("is_suspended").and_then(Value::as_bool) {
									if is_suspended {
										return Err("suspended".into());
									}
								}
							}

							// If Reddit returned an error
							if json["error"].is_i64() {
								// OAuth token has expired; http status 401
								if json["message"] == "Unauthorized" {
									error!("Forcing a token refresh");
									let () = force_refresh_token().await;
									return Err("OAuth token has expired. Please refresh the page!".to_string());
								}

								// Handle quarantined
								if json["reason"] == "quarantined" {
									return Err("quarantined".into());
								}
								// Handle gated
								if json["reason"] == "gated" {
									return Err("gated".into());
								}
								// Handle private subs
								if json["reason"] == "private" {
									return Err("private".into());
								}
								// Handle banned subs
								if json["reason"] == "banned" {
									return Err("banned".into());
								}

								Err(format!("Reddit error {} \"{}\": {} | {path}", json["error"], json["reason"], json["message"]))
							} else {
								Ok(json)
							}
						}
						Err(e) => {
							error!("Got an invalid response from reddit {e}. Status code: {status}");
							if status.is_server_error() {
								on_upstream_failure(&path, "parse", Some(status.as_u16()), attempt, "server error + invalid json");
								return Err("Reddit is having issues, check if there's an outage".to_string());
							}
							// Provide a clearer message when Reddit returns HTML or empty body
							let hint = if bytes.is_empty() {
								format!("Reddit returned an empty response (HTTP {status}).")
							} else if bytes.first().copied() == Some(b'<') {
								if status.as_u16() == 403 {
									on_upstream_failure(&path, "html_403", Some(403), attempt, "html instead of json");
								} else {
									on_upstream_failure(&path, "parse", Some(status.as_u16()), attempt, "html instead of json");
								}
								format!(
									"Reddit returned an HTML page instead of JSON (HTTP {status}). \
										The instance may be blocked, rate limited, or the anonymous OAuth flow may be failing. \
										See https://github.com/redlib-org/redlib/issues/446"
								)
							} else {
								on_upstream_failure(&path, "parse", Some(status.as_u16()), attempt, "json parse error");
								format!("{e} | {path}")
							};
							err("Failed to parse page JSON data", hint, path)
						}
					}
				}
				Err(e) => {
					on_upstream_failure(&path, "transport", Some(status.as_u16()), attempt, "body receive failed");
					err("Failed receiving body from Reddit", e.to_string(), path)
				}
			}
		}
		Err(e) => {
			on_upstream_failure(&path, "transport", None, attempt, &e);
			err("Couldn't send request to Reddit", e, path)
		}
	}
}

/// Make an authenticated GET request to a Reddit API path and parse the JSON response.
///
/// - `UserSession` / `RawBearer`: uses the caller's bearer token, bypassing the
///   shared anonymous `OAUTH_CLIENT`.
/// - `Anonymous`: delegates to the existing `json()` function unchanged.
///
/// Unlike `json()`, this function is **not cached** — authenticated responses
/// are user-specific and must not be shared across sessions.
///
/// On 401 Unauthorized with a `UserSession` that has a non-empty `refresh_token`,
/// automatically refreshes the access token, retries the request once, and returns
/// the new session in the second element so the caller can call `update_session_cookie`.
pub async fn authed_json(path: String, quarantine: bool, auth: &AuthContext) -> Result<(Value, Option<SessionData>), String> {
	let bearer = match auth.bearer_token() {
		Some(t) => t.to_string(),
		None => {
			let json = json(path, quarantine).await?;
			return Ok((json, None));
		}
	};

	let (json, _updated) = authed_json_with_bearer(path.clone(), quarantine, &bearer).await?;
	if json["error"].is_i64() && json["message"].as_str() == Some("Unauthorized") {
		// Try refresh for user sessions with a refresh token
		if let Some(s) = auth.session_data() {
			if !s.refresh_token.is_empty() {
				let (new_token, expires_at) = refresh_access_token(&s.refresh_token).await?;
				let new_session = SessionData {
					access_token: new_token,
					refresh_token: s.refresh_token.clone(),
					username: s.username.clone(),
					expires_at,
					csrf_token: s.csrf_token.clone(),
				};
				let (retry_json, _) = authed_json_with_bearer(path, quarantine, &new_session.access_token).await?;
				if retry_json["error"].is_i64() {
					return Err(format!("Reddit API error {}: {} | {}", retry_json["error"], retry_json["reason"], retry_json["message"]));
				}
				return Ok((retry_json, Some(new_session)));
			}
		}
		return Err("OAuth token is unauthorized — session may have expired".to_string());
	}
	if json["error"].is_i64() {
		return Err(format!("Reddit API error {}: {} | {}", json["error"], json["reason"], json["message"]));
	}
	Ok((json, None))
}

/// Inner helper: one GET with a given bearer token. Returns raw JSON (may contain error fields).
async fn authed_json_with_bearer(path: String, quarantine: bool, bearer: &str) -> Result<(Value, Option<SessionData>), String> {
	let url = format!("{REDDIT_URL_BASE}{path}");
	let request = Request::builder()
		.method(Method::GET)
		.uri(&url)
		.header("Host", REDDIT_URL_BASE_HOST)
		.header("Authorization", format!("Bearer {bearer}"))
		.header("User-Agent", crate::config::get_user_agent())
		.header("Accept-Encoding", "gzip")
		.header(
			"Cookie",
			if quarantine {
				"_options=%7B%22pref_quarantine_optin%22%3A%20true%2C%20%22pref_gated_sr_optin%22%3A%20true%7D"
			} else {
				""
			},
		)
		.body(Body::empty())
		.map_err(|e| e.to_string())?;

	let client: &LazyLock<Client<_, Body>> = &CLIENT;
	let response = client.request(request).await.map_err(|e| e.to_string())?;
	let status = response.status();

	let body_bytes: Vec<u8> = match response.headers().get(header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()) {
		Some("gzip") => {
			let aggregated = match body::aggregate(response).await {
				Ok(b) => b,
				Err(e) => return Err(e.to_string()),
			};
			let mut decoder = match libflate::gzip::Decoder::new(aggregated.reader()) {
				Ok(d) => d,
				Err(e) => return Err(e.to_string()),
			};
			let mut out = Vec::<u8>::new();
			if let Err(e) = io::copy(&mut decoder, &mut out) {
				return Err(e.to_string());
			}
			out
		}
		_ => {
			let bytes = body::to_bytes(response.into_body()).await.map_err(|e| e.to_string())?;
			bytes.to_vec()
		}
	};

	if body_bytes.is_empty() {
		return Err("Reddit returned an empty response (possible rate limit)".to_string());
	}

	let json: Value = serde_json::from_slice(&body_bytes).map_err(|e| format!("Failed to parse authed JSON: {e} | status={status}"))?;
	Ok((json, None))
}

/// Fetch the list of subreddit display names the user is subscribed to.
/// Uses the given bearer token (e.g. from OAuth callback). Used to populate Feeds nav when logged in.
pub async fn fetch_subscribed_subreddits_with_bearer(bearer: &str) -> Result<Vec<String>, String> {
	let path = "/subreddits/mine/subscriber.json?limit=100&raw_json=1".to_string();
	let (json, _) = authed_json_with_bearer(path, false, bearer).await?;
	if json["error"].is_i64() {
		return Err(format!("Reddit API error {}: {} | {}", json["error"], json["reason"], json["message"]));
	}
	let children = json["data"]["children"].as_array().ok_or("Invalid mine/subscriber response")?;
	let names: Vec<String> = children.iter().filter_map(|c| c["data"]["display_name"].as_str().map(String::from)).collect();
	Ok(names)
}

/// Fetch the current user's subscribed subreddits (using AuthContext). Use when logged in to refresh the list.
pub async fn fetch_subscribed_subreddits(auth: &AuthContext) -> Result<Vec<String>, String> {
	let path = "/subreddits/mine/subscriber.json?limit=100&raw_json=1".to_string();
	let (json, _) = authed_json(path, false, auth).await?;
	let children = json["data"]["children"].as_array().ok_or("Invalid mine/subscriber response")?;
	let names: Vec<String> = children.iter().filter_map(|c| c["data"]["display_name"].as_str().map(String::from)).collect();
	Ok(names)
}

/// Make an authenticated POST request to a Reddit API endpoint.
/// Used for actions like voting, subscribing, saving.
///
/// On 401 Unauthorized with a `UserSession` that has a non-empty `refresh_token`,
/// refreshes the access token, retries once, and returns the new session so the
/// caller can call `update_session_cookie`.
pub async fn authed_post(path: String, body_str: String, auth: &AuthContext) -> Result<(Value, Option<SessionData>), String> {
	let bearer = auth.bearer_token().ok_or("Authenticated POST requires a logged-in session")?;

	let (value, updated) = authed_post_with_bearer(path.clone(), body_str.clone(), bearer).await?;
	if value.get("error").and_then(|e| e.as_i64()).is_some() && value.get("message").and_then(|m| m.as_str()) == Some("Unauthorized") {
		if let Some(s) = auth.session_data() {
			if !s.refresh_token.is_empty() {
				let (new_token, expires_at) = refresh_access_token(&s.refresh_token).await?;
				let new_session = SessionData {
					access_token: new_token,
					refresh_token: s.refresh_token.clone(),
					username: s.username.clone(),
					expires_at,
					csrf_token: s.csrf_token.clone(),
				};
				let (retry_value, _) = authed_post_with_bearer(path, body_str, &new_session.access_token).await?;
				if retry_value.get("error").and_then(|e| e.as_i64()).is_some() {
					return Err(format!("Reddit API error {}: {} | {}", retry_value["error"], retry_value["reason"], retry_value["message"]));
				}
				return Ok((retry_value, Some(new_session)));
			}
		}
		return Err("OAuth token is unauthorized — session may have expired".to_string());
	}
	if value.get("error").and_then(|e| e.as_i64()).is_some() {
		return Err(format!("Reddit API error {}: {} | {}", value["error"], value["reason"], value["message"]));
	}
	Ok((value, updated))
}

async fn authed_post_with_bearer(path: String, body_str: String, bearer: &str) -> Result<(Value, Option<SessionData>), String> {
	let url = format!("{REDDIT_URL_BASE}{path}");
	let request = Request::builder()
		.method(Method::POST)
		.uri(&url)
		.header("Host", REDDIT_URL_BASE_HOST)
		.header("Authorization", format!("Bearer {bearer}"))
		.header("User-Agent", crate::config::get_user_agent())
		.header("Content-Type", "application/x-www-form-urlencoded")
		.body(Body::from(body_str))
		.map_err(|e| e.to_string())?;

	let client: &LazyLock<Client<_, Body>> = &CLIENT;
	let response = client.request(request).await.map_err(|e| e.to_string())?;
	let status = response.status();
	let bytes = body::to_bytes(response.into_body()).await.map_err(|e| e.to_string())?;

	if bytes.is_empty() || &bytes[..] == b"{}" {
		return Ok((Value::Object(Default::default()), None));
	}

	let json: Value = serde_json::from_slice(&bytes).map_err(|e| format!("Failed to parse POST response: {e} | status={status}"))?;
	Ok((json, None))
}

async fn self_check(sub: &str) -> Result<(), String> {
	let query = format!("/r/{sub}/hot.json?&raw_json=1");

	match Post::fetch(&query, true).await {
		Ok(_) => Ok(()),
		Err(e) => Err(e),
	}
}

pub async fn rate_limit_check() -> Result<(), String> {
	// First, test the Oauth client: we can perform a rate limit check if the OAuth backend is MobileSpoof; if GenericWeb, we skip the check.
	if matches!(OAUTH_CLIENT.load().backend, OauthBackendImpl::GenericWeb(_)) {
		warn!("[⚠️] Cannot perform rate limit check, running as GenericWeb. Skipping check.");
		return Ok(());
	}

	// First, check a subreddit.
	self_check("reddit").await?;
	// This will reduce the rate limit to 99. Assert this check.
	if OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst) != 99 {
		return Err(format!("Rate limit check 1 failed: expected 99, got {}", OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst)));
	}
	// Now, we switch out the OAuth client.
	// This checks for the IP rate limit association.
	force_refresh_token().await;
	// Now, check a new sub to break cache.
	self_check("rust").await?;
	// Again, assert the rate limit check.
	if OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst) != 99 {
		return Err(format!("Rate limit check 2 failed: expected 99, got {}", OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst)));
	}

	Ok(())
}

#[cfg(test)]
use {crate::config::get_setting, sealed_test::prelude::*};

#[tokio::test(flavor = "multi_thread")]
async fn test_rate_limit_check() {
	rate_limit_check().await.unwrap();
}

#[test]
#[sealed_test(env = [("REDLIB_DEFAULT_SUBSCRIPTIONS", "rust")])]
fn test_default_subscriptions() {
	tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
		let subscriptions = get_setting("REDLIB_DEFAULT_SUBSCRIPTIONS");
		assert!(subscriptions.is_some());

		// check rate limit
		rate_limit_check().await.unwrap();
	});
}

#[cfg(test)]
const POPULAR_URL: &str = "/r/popular/hot.json?&raw_json=1&geo_filter=GLOBAL";

#[tokio::test(flavor = "multi_thread")]
async fn test_localization_popular() {
	let val = json(POPULAR_URL.to_string(), false).await.unwrap();
	assert_eq!("GLOBAL", val["data"]["geo_filter"].as_str().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_obfuscated_share_link() {
	let share_link = "/r/rust/s/kPgq8WNHRK".into();
	// Correct link without share parameters
	let canonical_link = "/r/rust/comments/18t5968/why_use_tuple_struct_over_standard_struct/kfbqlbc/".into();
	assert_eq!(canonical_path(share_link, 3).await, Ok(Some(canonical_link)));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_private_sub() {
	let link = json("/r/suicide/about.json?raw_json=1".into(), true).await;
	assert!(link.is_err());
	assert_eq!(link, Err("private".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_banned_sub() {
	let link = json("/r/aaa/about.json?raw_json=1".into(), true).await;
	assert!(link.is_err());
	assert_eq!(link, Err("banned".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gated_sub() {
	// quarantine to false to specifically catch when we _don't_ catch it
	let link = json("/r/drugs/about.json?raw_json=1".into(), false).await;
	assert!(link.is_err());
	assert_eq!(link, Err("gated".into()));
}
