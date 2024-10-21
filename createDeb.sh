#!/bin/bash

set -e

# Define variables
PACKAGE_NAME="my-ddns-updater"
VERSION="2.0.1"
ARCHITECTURE="amd64"
MAINTAINER="Your Name <your.email@example.com>"
DESCRIPTION="IP Updater Service"
CONFIG_FILE="/etc/my-ddns-updater/config.json"
LOG_FILE="/var/log/${PACKAGE_NAME}.log"
BUILD_DIR="build"

# Create directory structure
mkdir -p ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN
mkdir -p ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/usr/local/bin
mkdir -p ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/etc/systemd/system
mkdir -p ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/etc/logrotate.d

# Create directory for config file
mkdir -p ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/$(dirname $CONFIG_FILE)

# Create the config file with all entries from main.go
cat << EOF > ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}${CONFIG_FILE}
{
  "nameComToken": "dummy_name_com_token",
  "getIPPassword": "dummy_get_ip_password",
  "getIPUsername": "dummy_get_ip_username",
  "disableUPnP": false,
  "host": "example",
  "domain": "example.com",
  "checkInterval": "30s",
  "updateInterval": "60s",
  "ignoreDNSInterval": "120s"
}
EOF

# Create directory for log file
mkdir -p ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/var/log
touch ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}${LOG_FILE}

# Compile the Go executable
go build -o ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/usr/local/bin/${PACKAGE_NAME} main.go

# Create control file
cat << EOF > ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN/control
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Architecture: ${ARCHITECTURE}
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
Pre-Depends: dpkg (>= 1.16.1), sudo
EOF

# Create systemd service file
cat << EOF > ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/etc/systemd/system/${PACKAGE_NAME}.service
[Unit]
Description=IP Updater Service
After=network.target

[Service]
ExecStart=/usr/local/bin/${PACKAGE_NAME} -config ${CONFIG_FILE}
Restart=always
RestartSec=60s
User=root
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
EOF

# Create logrotate configuration
cat << EOF > ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/etc/logrotate.d/${PACKAGE_NAME}
${LOG_FILE} {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 0644 root root
}
EOF

# Create postinst script
cat << EOF > ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN/postinst
#!/bin/bash
set -e

# Ensure all files and directories are owned by root
chown -R root:root /usr/local/bin/${PACKAGE_NAME}
chown -R root:root /etc/my-ddns-updater
chown -R root:root /etc/systemd/system/${PACKAGE_NAME}.service
chown -R root:root /etc/logrotate.d/${PACKAGE_NAME}
chown root:root ${LOG_FILE}

# Set appropriate permissions
chmod 755 /usr/local/bin/${PACKAGE_NAME}
chmod 644 /etc/systemd/system/${PACKAGE_NAME}.service
chmod 644 /etc/logrotate.d/${PACKAGE_NAME}
chmod 644 ${LOG_FILE}

# Handle config file
if [ -f ${CONFIG_FILE} ]; then
    # Config file exists, ask user what to do
    echo "Configuration file '${CONFIG_FILE}' already exists."
    echo "What would you like to do?"
    echo "  [I]nstall the package maintainer's version"
    echo "  [K]eep your currently-installed version"
    echo "  [D]iff between the versions"
    echo "  [S]ide-by-side diff between the versions"
    echo "  [E]xamine the situation in a new shell"
    
    # Read user's choice
    read -p "Please select an option [I/K/D/S/E] (default: K): " choice
    
    case "$choice" in
        [Ii]) mv ${CONFIG_FILE}.dpkg-new ${CONFIG_FILE}; chmod 600 ${CONFIG_FILE} ;;
        [Dd]) diff -u ${CONFIG_FILE} ${CONFIG_FILE}.dpkg-new; rm ${CONFIG_FILE}.dpkg-new ;;
        [Ss]) diff -y ${CONFIG_FILE} ${CONFIG_FILE}.dpkg-new; rm ${CONFIG_FILE}.dpkg-new ;;
        [Ee]) echo "Type 'exit' when done examining."; bash; rm ${CONFIG_FILE}.dpkg-new ;;
        *) rm ${CONFIG_FILE}.dpkg-new ;;
    esac
else
    # No existing config, install the new one
    mv ${CONFIG_FILE}.dpkg-new ${CONFIG_FILE}
    chmod 600 ${CONFIG_FILE}
fi

systemctl daemon-reload
systemctl enable ${PACKAGE_NAME}.service
systemctl restart ${PACKAGE_NAME}.service
EOF

# Make postinst script executable
chmod 755 ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN/postinst

# Create preinst script to check for root installation
cat << EOF > ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN/preinst
#!/bin/bash
set -e

if [ "\$(id -u)" != "0" ]; then
   echo "This package must be installed with root privileges" >&2
   exit 1
fi
EOF

# Make preinst script executable
chmod 755 ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN/preinst

# Set permissions for all files in the package
find ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE} -type d -exec chmod 755 {} \;
find ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE} -type f -exec chmod 644 {} \;
chmod 755 ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/usr/local/bin/${PACKAGE_NAME}
chmod 755 ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN/preinst
chmod 755 ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}/DEBIAN/postinst

# Rename config file to .dpkg-new
mv ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}${CONFIG_FILE} ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}${CONFIG_FILE}.dpkg-new

# Build the .deb package
fakeroot dpkg-deb --build ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}

echo "Debian package created: ${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb"
