# DevOpsFetch

DevOpsFetch is a Python-based monitoring tool for various system activities, including network ports, Docker events, Nginx configuration changes, and user activities. The tool is designed to be easy to install and configure on Linux systems, particularly Ubuntu.

## Table of Contents

- [DevOpsFetch](#devopsfetch)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Services](#services)
  - [Logging](#logging)
  - [Cron Jobs](#cron-jobs)

## Features

- Monitor active network ports and detailed information.
- Monitor Docker events such as container start, stop, die, and restart.
- Monitor Nginx configuration changes.
- Monitor user activities and logins.
- Retrieve and display detailed information about specific network ports, Docker containers, Nginx domains, and users.

## Installation

Follow these steps to install and configure DevOpsFetch:

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/devopsfetch.git
   cd devopsfetch
   ```

2. Run the installation script:

   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```

## Usage

DevOpsFetch provides various functionalities through a Python script (`devopsfetch.py`). You can run the script with different options to perform specific tasks:

- List active network ports:

  ```bash
  ./devopsfetch.py --port
  ```

- List Docker images and containers:

  ```bash
  ./devopsfetch.py --docker
  ```

- List Nginx domains and proxies:

  ```bash
  ./devopsfetch.py --nginx
  ```

- List users and their last login times:

  ```bash
  ./devopsfetch.py --users
  ```

- Retrieve detailed information about a specific port:

  ```bash
  ./devopsfetch.py --port <port_number>
  ```

- Retrieve detailed information about a specific Docker container:

  ```bash
  ./devopsfetch.py --container <container_name>
  ```

- Retrieve detailed information about a specific Nginx domain:

  ```bash
  ./devopsfetch.py --domain <domain_name>
  ```

- Retrieve detailed information about a specific user:

  ```bash
  ./devopsfetch.py --user <username>
  ```

## Services

DevOpsFetch sets up two systemd services:

1. **DevOpsFetch Service**: Monitors network ports, Docker events, and user activities.
2. **Nginx Monitor Service**: Monitors changes in the Nginx configuration.

These services are automatically enabled and started during the installation.

```sh
sudo systemctl status devopsfetch.service
sudo systemctl status nginx_monitor.service

```

## Logging

Log files are created in the `/var/log/devopsfetch` directory. The following log files are generated:

- `devopsfetch.log`: General log for DevOpsFetch activities.
- `port_activity.log`: Log for port monitoring activities.
- `nginx_changes.log`: Log for Nginx configuration changes.
- `docker_activity.log`: Log for Docker events.

## Cron Jobs

A cron job is created to monitor port activities every minute:

```cron
* * * * * /usr/sbin/ss -tuln >> /var/log/devopsfetch/port_activity.log
```
