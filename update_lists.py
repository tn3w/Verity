import json
import time
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import re


def parse_ip(ip_str):
    try:
        if "/" in ip_str:
            return ipaddress.ip_network(ip_str, strict=False)
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def parse_line(line, regex):
    matches = re.findall(regex, line)
    results = []
    for match in matches:
        if isinstance(match, str):
            results.append(match)
        elif isinstance(match, tuple):
            results.append(next((group for group in match if group), None))
    return results


def download_source(url, timeout=10):
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read().decode("utf-8", errors="ignore")
            return content.splitlines()
    except Exception:
        return []


def download_single_list(source):
    ips = []
    for line in download_source(source["url"]):
        ips.extend(parse_line(line, source["regex"]))
    return source["name"], ips


def download_all_lists(sources):
    lists = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(download_single_list, source): source for source in sources
        }
        for future in as_completed(futures):
            name, ips = future.result()
            lists[name] = ips
            print(f"Downloaded {name}: {len(ips)} entries")
    return lists


def process_lists(lists):
    processed = {}
    for list_name, ip_strings in lists.items():
        addresses = []
        networks = []
        for ip_str in ip_strings:
            parsed = parse_ip(ip_str)
            if parsed is None:
                continue
            if isinstance(parsed, ipaddress.IPv4Network) or isinstance(
                parsed, ipaddress.IPv6Network
            ):
                start = int(parsed.network_address)
                end = int(parsed.broadcast_address)
                networks.append([start, end])
            else:
                addresses.append(int(parsed))
        addresses = sorted(set(addresses))
        networks = sorted(set(tuple(n) for n in networks))
        networks = [list(n) for n in networks]
        processed[list_name] = {"addresses": addresses, "networks": networks}
    return processed


def main():
    with open("sources.json") as f:
        sources = json.load(f)

    print("Downloading lists...")
    lists = download_all_lists(sources)

    print("Processing lists...")
    processed = process_lists(lists)

    output = {"timestamp": int(time.time()), "lists": processed}

    with open("lists.json", "w") as f:
        json.dump(output, f, separators=(",", ":"))

    print(f"Saved lists.json with {len(processed)} lists")


if __name__ == "__main__":
    main()
