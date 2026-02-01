use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

const LISTS_URL: &str = "https://raw.githubusercontent.com/tn3w/Verity/master/lists.json";
const CACHE_TTL: Duration = Duration::from_secs(3600);
const LISTS_FILE: &str = "lists.json";
const SOURCES_FILE: &str = "sources.json";
const UPDATE_INTERVAL: Duration = Duration::from_secs(87300);
const DNS_TIMEOUT: Duration = Duration::from_millis(500);
const SCORE_CATEGORIES: [&str; 7] = [
    "malware",
    "botnet",
    "attacks",
    "spam",
    "compromised",
    "anonymizer",
    "infrastructure",
];

#[derive(Deserialize, Clone)]
struct ListData {
    addresses: Vec<u128>,
    networks: Vec<[u128; 2]>,
}

#[derive(Deserialize, Clone)]
struct SourceData {
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default = "default_base_score")]
    base_score: f64,
    #[serde(default)]
    score_categories: Vec<String>,
    #[serde(default)]
    special_handling: Option<String>,
    #[serde(default)]
    provider_name: Option<String>,
}

fn default_base_score() -> f64 {
    0.5
}

#[derive(Serialize, Default)]
struct ReputationResponse {
    score: f64,
    lists: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(flatten)]
    flags: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ListsFile {
    timestamp: i64,
    lists: HashMap<String, ListData>,
}

type Lists = Arc<RwLock<HashMap<String, ListData>>>;
type Sources = Arc<HashMap<String, SourceData>>;
type Cache = Arc<RwLock<HashMap<String, (Vec<u128>, SystemTime)>>>;
type Resolver = Arc<TokioAsyncResolver>;

fn parse_ip(input: &str) -> Option<u128> {
    if let Ok(v4) = input.parse::<Ipv4Addr>() {
        return Some(u32::from(v4) as u128);
    }
    input.parse::<Ipv6Addr>().ok().map(u128::from)
}

fn is_ipv6(value: u128) -> bool {
    value > u32::MAX as u128
}

fn extract_ipv4_from_parts(ipv6_str: &str) -> Option<u128> {
    let parts: Vec<&str> = ipv6_str.split(':').collect();

    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || part.parse::<u8>().is_err() {
            continue;
        }

        if index + 3 >= parts.len() {
            continue;
        }

        let octets: Result<Vec<u8>, _> = parts[index..index + 4]
            .iter()
            .map(|p| p.parse::<u8>())
            .collect();

        if let Ok(octets) = octets {
            if octets.len() == 4 {
                let ipv4 = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                return Some(u32::from(ipv4) as u128);
            }
        }
    }
    None
}

fn extract_ipv4_from_ipv6(ipv6: &Ipv6Addr) -> Vec<u128> {
    let mut results = Vec::new();
    let segments = ipv6.segments();

    if segments[0..6] == [0, 0, 0, 0, 0, 0xffff] {
        let ipv4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        results.push(u32::from(ipv4) as u128);
    }

    if segments[0] == 0x2002 {
        let ipv4 = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        results.push(u32::from(ipv4) as u128);
    }

    if let Some(embedded) = extract_ipv4_from_parts(&ipv6.to_string()) {
        results.push(embedded);
    }

    results
}

async fn reverse_lookup_ipv4(ipv6_str: &str, resolver: &Resolver) -> Option<Vec<u128>> {
    let addr = ipv6_str.parse().ok()?;

    let response = tokio::time::timeout(DNS_TIMEOUT, resolver.reverse_lookup(addr))
        .await
        .ok()?
        .ok()?;

    let hostname = response.iter().next()?.to_string();
    let hostname = hostname.trim_end_matches('.');

    let lookup = tokio::time::timeout(DNS_TIMEOUT, resolver.ipv4_lookup(hostname))
        .await
        .ok()?
        .ok()?;

    Some(lookup.iter().map(|ip| u32::from(ip.0) as u128).collect())
}

async fn resolve_ipv4_from_ipv6(ipv6_str: &str, resolver: &Resolver, cache: &Cache) -> Vec<u128> {
    let now = SystemTime::now();

    if let Some((addresses, expires)) = cache.read().await.get(ipv6_str) {
        if *expires > now {
            return addresses.clone();
        }
    }

    let mut addresses = Vec::new();

    if let Ok(ipv6) = ipv6_str.parse::<Ipv6Addr>() {
        addresses.extend(extract_ipv4_from_ipv6(&ipv6));
    }

    if addresses.is_empty() {
        if let Some(resolved) = reverse_lookup_ipv4(ipv6_str, resolver).await {
            addresses.extend(resolved);
        }
    }

    cache
        .write()
        .await
        .insert(ipv6_str.to_string(), (addresses.clone(), now + CACHE_TTL));

    addresses
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

fn load_lists() -> Option<(i64, HashMap<String, ListData>)> {
    let content = std::fs::read_to_string(LISTS_FILE).ok()?;
    let parsed: ListsFile = serde_json::from_str(&content).ok()?;
    Some((parsed.timestamp, parsed.lists))
}

fn load_sources() -> Option<HashMap<String, SourceData>> {
    let content = std::fs::read_to_string(SOURCES_FILE).ok()?;
    let sources: Vec<serde_json::Value> = serde_json::from_str(&content).ok()?;

    let mut map = HashMap::new();
    for source in sources {
        let name = source.get("name").and_then(|n| n.as_str())?.to_string();
        let data: SourceData = serde_json::from_value(source).ok()?;
        map.insert(name, data);
    }
    Some(map)
}

async fn download_lists() -> Option<HashMap<String, ListData>> {
    let response = reqwest::get(LISTS_URL).await.ok()?;
    let bytes = response.bytes().await.ok()?;
    let parsed: ListsFile = serde_json::from_slice(&bytes).ok()?;
    std::fs::write(LISTS_FILE, &bytes).ok()?;
    Some(parsed.lists)
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

async fn update_lists_loop(lists: Lists, initial_timestamp: i64) {
    let mut last_timestamp = initial_timestamp;

    loop {
        let next_update = last_timestamp + UPDATE_INTERVAL.as_secs() as i64;
        let wait = next_update - unix_timestamp();

        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(wait as u64)).await;
        }

        println!("Updating lists...");

        match download_lists().await {
            Some(new_lists) => {
                let count = new_lists.len();
                *lists.write().await = new_lists;
                last_timestamp = unix_timestamp();
                println!("Lists updated: {} entries", count);
            }
            None => {
                eprintln!("Failed to update lists");
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
        }
    }
}

async fn root() -> Redirect {
    Redirect::permanent("https://github.com/tn3w/Verity")
}

fn process_reputation(
    matches: &[String],
    sources: &HashMap<String, SourceData>,
    ip: Option<String>,
) -> ReputationResponse {
    if matches.is_empty() {
        return ReputationResponse {
            ip,
            ..Default::default()
        };
    }

    let mut flags = HashMap::new();
    let mut scores: HashMap<&str, Vec<f64>> =
        SCORE_CATEGORIES.iter().map(|c| (*c, Vec::new())).collect();

    for list_name in matches {
        let Some(source) = sources.get(list_name) else {
            continue;
        };

        for flag in &source.flags {
            flags.insert(flag.clone(), serde_json::Value::Bool(true));
        }

        for category in &source.score_categories {
            if let Some(category_scores) = scores.get_mut(category.as_str()) {
                category_scores.push(source.base_score);
            }
        }

        if let Some(handling) = &source.special_handling {
            if handling == "tor_node_detection" {
                let key = if list_name.to_lowercase().contains("exit") {
                    "is_tor_exit"
                } else {
                    "is_tor_relay"
                };
                flags.insert(key.to_string(), serde_json::Value::Bool(true));
            }
        }

        if let Some(provider) = &source.provider_name {
            flags.insert(
                "vpn_provider".to_string(),
                serde_json::Value::String(provider.clone()),
            );
        }
    }

    ReputationResponse {
        score: calculate_score(&scores),
        lists: matches.to_vec(),
        ip,
        flags,
    }
}

fn calculate_score(scores: &HashMap<&str, Vec<f64>>) -> f64 {
    let mut total = 0.0;

    for category_scores in scores.values() {
        if category_scores.is_empty() {
            continue;
        }

        let mut sorted = category_scores.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        let combined = sorted.iter().fold(1.0, |acc, &score| acc * (1.0 - score));

        total += 1.0 - combined;
    }

    (total / 1.5).min(1.0)
}

async fn evaluate_ip(
    ip: String,
    lists: &HashMap<String, ListData>,
    sources: &HashMap<String, SourceData>,
    cache: &Cache,
    resolver: &Resolver,
    include_ip: bool,
) -> Response {
    let Some(target) = parse_ip(&ip) else {
        return (StatusCode::BAD_REQUEST, "Invalid IP").into_response();
    };

    let mut matches = check_ip(target, lists);

    if is_ipv6(target) {
        let ipv4_addresses = resolve_ipv4_from_ipv6(&ip, resolver, cache).await;

        for ipv4 in ipv4_addresses {
            for name in check_ip(ipv4, lists) {
                if !matches.contains(&name) {
                    matches.push(name);
                }
            }
        }
    }

    let ip_field = if include_ip { Some(ip) } else { None };
    let reputation = process_reputation(&matches, sources, ip_field);

    Json(reputation).into_response()
}

async fn lookup(
    Path(ip): Path<String>,
    State((lists, sources, cache, resolver)): State<(Lists, Sources, Cache, Resolver)>,
) -> Response {
    let lists_data = lists.read().await;
    evaluate_ip(ip, &lists_data, &sources, &cache, &resolver, false).await
}

async fn lookup_self(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State((lists, sources, cache, resolver)): State<(Lists, Sources, Cache, Resolver)>,
) -> Response {
    let ip = addr.ip().to_string();
    let lists_data = lists.read().await;
    evaluate_ip(ip, &lists_data, &sources, &cache, &resolver, true).await
}

#[tokio::main]
async fn main() {
    let (timestamp, initial_lists) = load_lists()
        .or_else(|| {
            println!("Downloading initial lists...");
            tokio::runtime::Handle::current().block_on(async {
                download_lists()
                    .await
                    .map(|lists| (unix_timestamp(), lists))
            })
        })
        .expect("Failed to load lists");

    let sources = Arc::new(load_sources().expect("Failed to load sources"));

    println!("Loaded {} lists", initial_lists.len());

    let lists = Arc::new(RwLock::new(initial_lists));
    let cache = Arc::new(RwLock::new(HashMap::new()));
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));

    tokio::spawn(update_lists_loop(lists.clone(), timestamp));

    let app = Router::new()
        .route("/", get(root))
        .route("/me", get(lookup_self))
        .route("/{ip}", get(lookup))
        .with_state((lists, sources, cache, resolver))
        .into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
