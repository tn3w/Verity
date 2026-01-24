use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use parking_lot::RwLock;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const LISTS_URL: &str = "https://raw.githubusercontent.com/tn3w/Verity/master/lists.json";

#[derive(Deserialize, Clone)]
struct ListData {
    addresses: Vec<u128>,
    networks: Vec<[u128; 2]>,
}

#[derive(Deserialize)]
struct ListsFile {
    timestamp: i64,
    lists: HashMap<String, ListData>,
}

type Lists = Arc<RwLock<HashMap<String, ListData>>>;

fn parse_ip(input: &str) -> Option<u128> {
    if let Ok(v4) = Ipv4Addr::from_str(input) {
        return Some(u32::from(v4) as u128);
    }
    if let Ok(v6) = Ipv6Addr::from_str(input) {
        return Some(u128::from(v6));
    }
    None
}

fn check_ip(target: u128, lists: &HashMap<String, ListData>) -> Vec<String> {
    lists
        .iter()
        .filter_map(|(name, data)| {
            if data.addresses.binary_search(&target).is_ok() {
                return Some(name.clone());
            }
            for [start, end] in &data.networks {
                if target >= *start && target <= *end {
                    return Some(name.clone());
                }
            }
            None
        })
        .collect()
}

fn load_lists_from_file() -> Option<(i64, HashMap<String, ListData>)> {
    let data = std::fs::read("lists.json").ok()?;
    let file: ListsFile = serde_json::from_slice(&data).ok()?;
    Some((file.timestamp, file.lists))
}

async fn download_lists() -> Option<HashMap<String, ListData>> {
    let response = reqwest::get(LISTS_URL).await.ok()?;
    let bytes = response.bytes().await.ok()?;
    std::fs::write("lists.json", &bytes).ok()?;
    let file: ListsFile = serde_json::from_slice(&bytes).ok()?;
    Some(file.lists)
}

fn should_update(timestamp: i64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    now >= timestamp + 87300
}

async fn update_lists(lists: Lists, initial_timestamp: i64) {
    let mut last_timestamp = initial_timestamp;
    loop {
        let wait_time = (last_timestamp + 87300)
            - std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
        if wait_time > 0 {
            tokio::time::sleep(Duration::from_secs(wait_time as u64)).await;
        }
        println!("Updating lists...");
        if let Some(new_lists) = download_lists().await {
            let mut write = lists.write();
            *write = new_lists;
            last_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            println!("Lists updated: {} entries", write.len());
        } else {
            eprintln!("Failed to update lists");
            tokio::time::sleep(Duration::from_secs(300)).await;
        }
    }
}

async fn root() -> Redirect {
    Redirect::permanent("https://github.com/tn3w/Verity")
}

async fn lookup(
    Path(ip): Path<String>,
    axum::extract::State(lists): axum::extract::State<Lists>,
) -> Response {
    let target = match parse_ip(&ip) {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, "Invalid IP").into_response(),
    };
    let read = lists.read();
    let matches = check_ip(target, &read);
    (StatusCode::OK, Json(matches)).into_response()
}

#[tokio::main]
async fn main() {
    let (timestamp, initial_lists) = load_lists_from_file()
        .or_else(|| {
            println!("Downloading initial lists...");
            tokio::runtime::Handle::current().block_on(async {
                download_lists().await.map(|lists| {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    (ts, lists)
                })
            })
        })
        .expect("Failed to load lists");

    println!("Loaded {} lists", initial_lists.len());
    let lists = Arc::new(RwLock::new(initial_lists));

    tokio::spawn(update_lists(lists.clone(), timestamp));

    let app = Router::new()
        .route("/", get(root))
        .route("/{ip}", get(lookup))
        .with_state(lists);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
