//! Disposable Electrum JSON-RPC transport; never opens outbound connections.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub struct Fixture {
    pub url: String,
    pub requests: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    pub async fn new(handler: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let recorded = Arc::clone(&recorded);
                let handler = Arc::clone(&handler);
                connections.spawn(async move {
                    let (read, mut write) = socket.into_split();
                    let mut lines = BufReader::new(read).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let request: Value = serde_json::from_str(&line).unwrap();
                        recorded.lock().unwrap().push(request.clone());
                        let mut response = handler(&request);
                        response["jsonrpc"] = json!("2.0");
                        response["id"] = request["id"].clone();
                        let line = format!("{response}\n");
                        if write.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
                while connections.try_join_next().is_some() {}
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
