
# DDNS Updater

DDNS Updater is a simple tool designed to update your dynamic DNS records automatically. It is built using Go, ensuring ease of deployment on multiple platforms. There is also an AI translation to zig, which is unverified.

## Features

- Supports name.com
- Easy to configure
- Lightweight and fast
- Uses UPnP to determine the public IP
- Can also determine the public IP by using Netgear R7900P's web admin interface
- IPv4 only

## Requirements

- Go 1.16 or higher

## Installation

1. Clone the repository:
      git clone https://github.com/aathan/your-repo-name.git
      cd your-repo-name

2. Build the deb:
      ./createDeb.sh

3. Install the deb:

      sudo dpkg -i build/...

## Configuration

Edit the `/etc/my-dns-updater/config.json` file to add your DDNS provider details and credentials, and Netgear R7900P login info.

## Usage

See source code for command line parameters accepted by the updater

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request. Happy to integrate what's here with other DDNS updaters that are out there. I just needed something low fuss that I completely understood with zero effort to "plug in" to another project.

## License

This project is licensed under the MIT License.

