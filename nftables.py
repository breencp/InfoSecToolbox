import argparse

# Path to the include file
whitelist_file = "/etc/nftables.d/mac_whitelist.conf"

# List of MAC addresses to whitelist
mac_addresses = [
    "06:7a:42:8a:20:69",
    "5e:a5:41:83:e6:4a",
    "58:55:95:32:80:28",
    "6a:5c:d3:8e:58:b9",
    "84:38:35:50:5b:04",
    "0a:84:71:32:93:0a",
    "fa:52:79:fc:2b:c4",
    "40:2f:86:04:b6:a4",
    "3c:06:30:ec:79:70",
    "04:99:b9:b4:f8:df",
    "f4:34:f0:09:7e:e2"
]

def generate_whitelist_file(mac_list):
    # Generate the contents of the whitelist file
    content = f"""set mac_whitelist {{
    type ether_addr;
    elements = {{ {', '.join(mac_list)} }}
    }}
    """

    # Write to the whitelist file
    with open(whitelist_file, "w") as f:
        f.write(content)
    print(f"Whitelist file updated with {len(mac_list)} MAC address(es).")


def parse_args():
    parser = argparse.ArgumentParser(description="Manage MAC whitelist for nftables.")
    parser.add_argument("--add", nargs="+", help="Add MAC address(es) to the whitelist.")
    parser.add_argument("--remove", nargs="+", help="Remove MAC address(es) from the whitelist.")
    parser.add_argument("--list", action="store_true", help="List all MAC addresses in the whitelist.")
    return parser.parse_args()


if __name__ == '__main__':
    generate_whitelist_file(mac_addresses)

