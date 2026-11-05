//! HTTPS-only Hyper 0.14 transport using the maintained Rustls certificate verifier.
use hyper::client::connect::{Connected, Connection, HttpConnector};
use hyper::service::Service;
use hyper::Uri;
use rustls::{ClientConfig, RootCertStore};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct HttpsConnector {
	http: HttpConnector,
	tls: TlsConnector,
}

fn tls_config(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
	// Retain the existing Firefox-style order and forward-secret suites.
	use rustls::crypto::ring::cipher_suite::*;
	let mut provider = rustls::crypto::ring::default_provider();
	provider.cipher_suites = vec![
		TLS13_AES_256_GCM_SHA384,
		TLS13_AES_128_GCM_SHA256,
		TLS13_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	];
	let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
		.with_safe_default_protocol_versions()?
		.with_root_certificates(roots)
		.with_no_client_auth();
	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	Ok(config)
}

impl HttpsConnector {
	pub fn new() -> Result<Self, Error> {
		let native = rustls_native_certs::load_native_certs();
		let mut roots = RootCertStore::empty();
		let (accepted, _) = roots.add_parsable_certificates(native.certs);
		if accepted == 0 {
			return Err(io::Error::other("native TLS trust store contains no usable certificates").into());
		}
		Ok(Self::with_config(tls_config(roots)?))
	}

	fn with_config(config: ClientConfig) -> Self {
		let mut http = HttpConnector::new();
		http.enforce_http(false);
		Self {
			http,
			tls: TlsConnector::from(Arc::new(config)),
		}
	}
}

impl Service<Uri> for HttpsConnector {
	type Response = HttpsStream;
	type Error = Error;
	type Future = Pin<Box<dyn Future<Output = Result<HttpsStream, Error>> + Send>>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
		self.http.poll_ready(cx).map_err(Into::into)
	}

	fn call(&mut self, uri: Uri) -> Self::Future {
		let mut http = self.http.clone();
		let tls = self.tls.clone();
		Box::pin(async move {
			if uri.scheme_str() != Some("https") {
				return Err(io::Error::new(io::ErrorKind::InvalidInput, "upstream transport requires HTTPS").into());
			}
			let host = uri.host().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "HTTPS URI requires a host"))?;
			let host = host.strip_prefix('[').and_then(|value| value.strip_suffix(']')).unwrap_or(host);
			let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
			let stream = http.call(uri).await?;
			Ok(HttpsStream(tls.connect(name, stream).await?))
		})
	}
}

pub struct HttpsStream(TlsStream<TcpStream>);

impl Connection for HttpsStream {
	fn connected(&self) -> Connected {
		let connected = self.0.get_ref().0.connected();
		if self.0.get_ref().1.alpn_protocol() == Some(b"h2") {
			connected.negotiated_h2()
		} else {
			connected
		}
	}
}

impl AsyncRead for HttpsStream {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.0).poll_read(cx, buf)
	}
}

impl AsyncWrite for HttpsStream {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.0).poll_write(cx, buf)
	}
	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.0).poll_flush(cx)
	}
	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.0).poll_shutdown(cx)
	}
	fn is_write_vectored(&self) -> bool {
		self.0.is_write_vectored()
	}
	fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rcgen::{generate_simple_self_signed, CertifiedKey};
	use rustls::pki_types::PrivatePkcs8KeyDer;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;
	use tokio_rustls::TlsAcceptor;

	async fn fixture(alpn: &[u8], serve_http: bool) -> (u16, RootCertStore, tokio::task::JoinHandle<io::Result<()>>) {
		let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
		let mut roots = RootCertStore::empty();
		roots.add(cert.der().clone()).unwrap();
		let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_no_client_auth()
			.with_single_cert(vec![cert.der().clone()], PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into())
			.unwrap();
		server.alpn_protocols = vec![alpn.to_vec()];
		let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
		let port = listener.local_addr().unwrap().port();
		let h2 = alpn == b"h2";
		let task = tokio::spawn(async move {
			let (socket, _) = listener.accept().await?;
			let mut stream = TlsAcceptor::from(Arc::new(server)).accept(socket).await?;
			if serve_http {
				let service = hyper::service::service_fn(|_| async { Ok::<_, std::convert::Infallible>(hyper::Response::new(hyper::Body::from("fixture"))) });
				hyper::server::conn::Http::new()
					.http2_only(h2)
					.serve_connection(stream, service)
					.await
					.map_err(io::Error::other)
			} else {
				stream.write_all(b"fixture").await
			}
		});
		(port, roots, task)
	}

	async fn trusted_protocol(alpn: &[u8], h2: bool) {
		let (port, roots, server) = fixture(alpn, false).await;
		let mut connector = HttpsConnector::with_config(tls_config(roots).unwrap());
		let mut stream = tokio::time::timeout(std::time::Duration::from_secs(5), connector.call(format!("https://localhost:{port}/").parse().unwrap()))
			.await
			.unwrap()
			.unwrap();
		assert_eq!(stream.connected().is_negotiated_h2(), h2);
		let mut content = [0; 7];
		stream.read_exact(&mut content).await.unwrap();
		assert_eq!(&content, b"fixture");
		server.await.unwrap().unwrap();
	}

	#[tokio::test]
	async fn trusted_certificate_and_h2_alpn() {
		trusted_protocol(b"h2", true).await;
	}

	#[tokio::test]
	async fn trusted_certificate_and_http1_alpn() {
		trusted_protocol(b"http/1.1", false).await;
	}

	#[tokio::test]
	async fn rejects_untrusted_certificate() {
		let (port, _, server) = fixture(b"http/1.1", false).await;
		let mut connector = HttpsConnector::with_config(tls_config(RootCertStore::empty()).unwrap());
		assert!(connector.call(format!("https://localhost:{port}/").parse().unwrap()).await.is_err());
		assert!(server.await.unwrap().is_err());
	}

	#[tokio::test]
	async fn rejects_certificate_for_wrong_hostname() {
		let (port, roots, server) = fixture(b"http/1.1", false).await;
		let mut connector = HttpsConnector::with_config(tls_config(roots).unwrap());
		assert!(connector.call(format!("https://127.0.0.1:{port}/").parse().unwrap()).await.is_err());
		assert!(server.await.unwrap().is_err());
	}

	#[tokio::test]
	async fn rejects_plain_http_before_connecting() {
		let mut connector = HttpsConnector::with_config(tls_config(RootCertStore::empty()).unwrap());
		let error = match connector.call("http://127.0.0.1:1/".parse().unwrap()).await {
			Ok(_) => panic!("plaintext transport was accepted"),
			Err(error) => error,
		};
		assert!(error.to_string().contains("requires HTTPS"));
	}

	#[test]
	fn native_trust_store_loads() {
		HttpsConnector::new().unwrap();
	}
	#[tokio::test]
	async fn hyper_client_exchanges_real_http2_request() {
		let (port, roots, server) = fixture(b"h2", true).await;
		let connector = HttpsConnector::with_config(tls_config(roots).unwrap());
		let client = hyper::Client::builder().build::<_, hyper::Body>(connector);
		let response = client.get(format!("https://localhost:{port}/").parse().unwrap()).await.unwrap();
		assert_eq!(response.version(), hyper::Version::HTTP_2);
		assert_eq!(hyper::body::to_bytes(response.into_body()).await.unwrap(), "fixture");
		drop(client);
		server.abort();
	}
}
