#!/usr/bin/env python3

import argparse
import os
import re
import psutil
import docker
import subprocess
import logging
from tabulate import tabulate
from datetime import datetime, timedelta


log_dir = '/var/log/devopsfetch'
os.makedirs(log_dir, exist_ok=True)


logging.basicConfig(filename=os.path.join(log_dir, 'devopsfetch.log'),
                    level=logging.DEBUG,
                    format='%(asctime)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S,%f')

def list_active_ports():
    connections = psutil.net_connections(kind='inet')
    ports = []
    for conn in connections:
        user = get_user_by_pid(conn.pid)
        service = get_service_by_pid(conn.pid)
        ports.append([user, conn.laddr.port, service, conn.status])
    return ports

def get_user_by_pid(pid):
    try:
        proc = psutil.Process(pid)
        return proc.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A"

def get_service_by_pid(pid):
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A"

def detailed_port_info(port_number):
    connections = psutil.net_connections(kind='inet')
    details = []
    for conn in connections:
        if conn.laddr.port == int(port_number):
            user = get_user_by_pid(conn.pid)
            service = get_service_by_pid(conn.pid)
            details.append({
                'User': user,
                'Port': conn.laddr.port,
                'Remote Address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                'Service': service,
                'Status': conn.status,
                'PID': conn.pid
            })
    return details

def list_docker_info():
    client = docker.from_env()
    images = client.images.list()
    containers = client.containers.list(all=True)
    
    image_list = [{'Repository': img.tags[0] if img.tags else '<none>',
                   'Image ID': img.short_id,
                   'Created': datetime.strptime(img.attrs['Created'][:19], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                   'Size': img.attrs['Size']} for img in images]
    
    container_list = [{'Container ID': container.short_id,
                       'Image': container.image.tags[0] if container.image.tags else '<none>',
                       'Command': ' '.join(container.attrs['Config']['Cmd']) if container.attrs['Config']['Cmd'] else '<none>',
                       'Created': datetime.strptime(container.attrs['Created'][:19], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S'),
                       'Status': container.status,
                       'Ports': container.attrs['NetworkSettings']['Ports'],
                       'Names': container.name} for container in containers]
    
    return image_list, container_list


def detailed_container_info(container_name):
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        return container.attrs
    except docker.errors.NotFound:
        return None

def list_nginx_domains():
    try:
        result = subprocess.run(['sudo', 'nginx', '-T'], capture_output=True, text=True)
        config = result.stdout
        logging.debug(f"Raw Nginx config output: {config}")  # Log the raw output

        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, result.args)

        domains = []
        current_server = None
        current_config_file = None
        for line in config.split('\n'):
            line = line.strip()
            logging.debug(f"Processing line: {line}")  # Log each line being processed
            
            if line.startswith("# configuration file"):
                current_config_file = line.split()[3]
            elif line.startswith("server {"):
                current_server = {'server_name': [], 'proxy': [], 'config_file': current_config_file}
            elif line.startswith("server_name"):
                server_names = line.split()[1:]
                current_server['server_name'].extend(name.strip().strip(';') for name in server_names)
                logging.debug(f"Found server names: {current_server['server_name']}")  # Log server names
            elif line.startswith("proxy_pass"):
                proxy_pass = line.split()[1].strip(';')
                current_server['proxy'].append(proxy_pass)
                logging.debug(f"Found proxy_pass: {proxy_pass}")  # Log proxy_pass
            elif line.startswith("listen"):
                port = line.split()[1].strip(';')
                if port not in current_server['proxy']:
                    current_server['proxy'].append(port)
                logging.debug(f"Found listen port: {port}")  # Log listen port
            if current_server is not None:
                current_server.setdefault('config', []).append(line)
            if line.startswith("}"):
                if current_server:
                    domains.append(current_server)
                current_server = None

        logging.debug(f"Parsed domains: {domains}")  # Log parsed domains

        table = []
        for domain in domains:
            server_name = ', '.join(domain['server_name']) if domain['server_name'] else '_'
            table.append([
                server_name,
                ', '.join(domain['proxy']),
                domain['config_file']
            ])

        return tabulate(table, headers=["Server Name", "Proxy", "Configuration File"], tablefmt="pretty")

    except FileNotFoundError:
        return "Nginx not installed."
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running nginx -T: {e}")
        return f"Error running nginx -T: {e}"

def detailed_nginx_domain_info(domain):
    try:
        result = subprocess.run(['sudo', 'nginx', '-T'], capture_output=True, text=True)
        config = result.stdout
        domain_info = []
        current_server = None
        current_config_file = None
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith("# configuration file"):
                current_config_file = line.split()[3]
            elif line.startswith("server {"):
                if current_server:  # Save the previous server block if it's being processed
                    if domain in current_server['server_name']:
                        domain_info.append(current_server)
                current_server = {'server_name': [], 'proxy': [], 'config_file': current_config_file, 'details': []}
            elif line.startswith("server_name"):
                server_names = line.split()[1:]
                if current_server:
                    current_server['server_name'].extend(name.strip().strip(';') for name in server_names)
            elif line.startswith("proxy_pass"):
                proxy_pass = line.split()[1].strip(';')
                if current_server:
                    current_server['proxy'].append(proxy_pass)
            elif line.startswith("listen"):
                port = line.split()[1].strip(';')
                if current_server:
                    current_server['proxy'].append(port)
            if current_server is not None:
                current_server['details'].append(line)
            if line.startswith("}"):
                if current_server and domain in current_server['server_name']:
                    domain_info.append(current_server)
                current_server = None

        if not domain_info:
            return f"No information found for domain {domain}"

        domain_details = domain_info[0]
        details_table = "\n".join(domain_details['details'])
        
        table = [
            [
                "Server Name", ", ".join(domain_details['server_name']),
                "Proxy", ", ".join(domain_details['proxy']),
                "Configuration File", domain_details['config_file']
            ],
            ["Details", details_table]
        ]

        return tabulate(table, headers=["Type", "Information"], tablefmt="grid")

    except FileNotFoundError:
        return "Nginx not installed."
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running nginx -T: {e}")
        return f"Error running nginx -T: {e}"

def list_users():
    try:
        result = subprocess.run(['last'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        user_list = []

        # Define regex to capture the date and time, excluding the terminal
        last_login_pattern = re.compile(r'(?:tty\d+\s+)?(\w+\s+\w+\s+\d+\s+\d+:\d+)')

        for line in lines:
            if 'reboot' not in line and line.strip():
                parts = line.split()
                name = parts[0]

                # Use regex to extract date and time from the 'Last Login' field
                last_login_match = last_login_pattern.search(' '.join(parts[1:]))
                last_login = last_login_match.group(1) if last_login_match else 'N/A'

                # Combine parts starting from the 7th index onwards for the 'Started' field
                started = ' '.join(parts[7:])

                user_list.append([name, last_login, started])

        return user_list
    except Exception as e:
        logging.error(f"Failed to fetch user list: {e}")
        return []



def detailed_user_info(username):
    try:
        result = subprocess.run(['last', username], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        user_info = []
        
        # Define regex to capture IP/hostname and session duration
        ip_hostname_pattern = re.compile(r'\(([^)]+)\)')
        session_duration_pattern = re.compile(r'(\d+\+\d+:\d+|\d+:\d+)')

        for line in lines:
            if username in line and line.strip():
                parts = line.split()
                name = parts[0]
                terminal = parts[1]

                # Use regex to capture IP/hostname if present
                ip_hostname_match = ip_hostname_pattern.search(line)
                ip_or_hostname = ip_hostname_match.group(1) if ip_hostname_match else 'N/A'

                # Use regex to capture session duration if present
                session_duration_match = session_duration_pattern.search(line)
                session_duration = session_duration_match.group(0) if session_duration_match else 'N/A'

                # Extract last login and started time
                last_login = ' '.join(parts[2:7])
                started = ' '.join(parts[7:])

                user_info.append([name, terminal, last_login, started, ip_or_hostname, session_duration])
        return user_info
    except Exception as e:
        logging.error(f"Failed to fetch detailed user info for {username}: {e}")
        return []


def retrieve_logs(start_time, end_time):
    log_entries = []

    def parse_log_file(file_path, date_format):
        if not os.path.exists(file_path):
            open(file_path, 'a').close()
            logging.info(f"Log file {file_path} was missing and has been created.")
        
        with open(file_path, 'r') as log_file:
            for line in log_file:
                try:
                    log_time_str = line.split(' - ')[0]
                    log_time = datetime.strptime(log_time_str, date_format)
                    if start_time <= log_time <= end_time:
                        log_entries.append(line.strip())
                except ValueError:
                    continue

    parse_log_file('/var/log/devopsfetch/devopsfetch.log', '%Y-%m-%d %H:%M:%S,%f')
    parse_log_file('/var/log/devopsfetch/port_activity.log', '%Y-%m-%d %H:%M:%S')
    parse_log_file('/var/log/devopsfetch/nginx_changes.log', '%Y-%m-%d %H:%M:%S,%f')
    parse_log_file('/var/log/devopsfetch/docker_activity.log', '%Y-%m-%dT%H:%M:%S.%f')

    return sorted(log_entries, key=lambda x: datetime.strptime(x.split(' - ')[0], '%Y-%m-%d %H:%M:%S,%f'))

def main():
    parser = argparse.ArgumentParser(description="Devopsfetch: A tool for system information retrieval and monitoring")
    parser.add_argument('-p', '--port', nargs='?', const=True, help='Display all active ports and services, or details of a specific port')
    parser.add_argument('-d', '--docker', nargs='?', const=True, help='List all Docker images and containers, or details of a specific container')
    parser.add_argument('-n', '--nginx', nargs='?', const=True, help='Display all Nginx domains and ports, or details of a specific domain')
    parser.add_argument('-u', '--users', nargs='?', const=True, help='List all users and their last login times, or details of a specific user')
    parser.add_argument('-t', '--time', nargs='+', help='Display activities within a specified time range or on a specific date, optionally including time (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    args = parser.parse_args()

    if args.port:
        if args.port is True:
            ports = list_active_ports()
            print(tabulate(ports, headers=['User', 'Port', 'Service', 'Status']))
            logging.info('Ports information retrieved')
        else:
            port_info = detailed_port_info(args.port)
            if port_info:
                print(tabulate(port_info, headers='keys')) # print all keys
                logging.info(f'Detailed information for port {args.port} retrieved')
            else:
                print(f"No information found for port {args.port}")
                logging.info(f'No information found for port {args.port}')
    elif args.docker:
        if args.docker is True:
            images, containers = list_docker_info()
            print("Docker Images:")
            print(tabulate(images, headers="keys", tablefmt="grid"))
            print("\nDocker Containers:")
            print(tabulate(containers, headers="keys", tablefmt="grid"))
            logging.info('Docker information retrieved')
        else:
            container_info = detailed_container_info(args.docker)
            if container_info:
                print(container_info)
                logging.info(f'Detailed information for container {args.docker} retrieved')
            else:
                print(f"No information found for container {args.docker}")
                logging.info(f'No information found for container {args.docker}')
    elif args.nginx:
        if args.nginx is True:
            config = list_nginx_domains()
            print(config)
            logging.info('Nginx configuration retrieved')
        else:
            domain_info = detailed_nginx_domain_info(args.nginx)
            if domain_info:
                print(domain_info)
                logging.info(f'Detailed configuration for domain {args.nginx} retrieved')
            else:
                print(f"No information found for domain {args.nginx}")
                logging.info(f'No information found for domain {args.nginx}')
    elif args.users:
        if args.users is True:
            users = list_users()
            print(tabulate(users, headers=['User', 'Last Login', 'Started'], tablefmt="grid"))
            logging.info('Users information retrieved')
            
        else:
            user_info = detailed_user_info(args.users)
            if user_info:
                # print(tabulate(user_info, headers=['Name', 'Terminal', 'Last Login', 'Started']))
                print(tabulate(user_info, headers=['User', 'Terminal', 'Last Login', 'Started', 'IP/Hostname', 'Session Duration'], tablefmt="grid"))
                logging.info(f'Detailed information for user {args.users} retrieved')
            else:
                print(f"No information found for user {args.users}")
                logging.info(f'No information found for user {args.users}')
    elif args.time:
        try:
            if len(args.time) == 1:
                start_time = datetime.strptime(args.time[0], '%Y-%m-%d')
                end_time = start_time.replace(hour=23, minute=59, second=59)
            elif len(args.time) == 2 and ' ' not in args.time[1]:
                start_time = datetime.strptime(args.time[0], '%Y-%m-%d')
                end_time = datetime.strptime(args.time[1], '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            elif len(args.time) == 2:
                start_time = datetime.strptime(args.time[0], '%Y-%m-%d %H:%M:%S')
                end_time = datetime.strptime(args.time[1], '%Y-%m-%d %H:%M:%S')
            elif len(args.time) == 3:
                start_time = datetime.strptime(args.time[0] + ' ' + args.time[1], '%Y-%m-%d %H:%M:%S')
                end_time = datetime.strptime(args.time[2], '%Y-%m-%d %H:%M:%S')
            else:
                print("Invalid time range specified")
                return

            log_entries = retrieve_logs(start_time, end_time)
            if log_entries:
                print("\n".join(log_entries))
                logging.info(f'Activities between {start_time} and {end_time} retrieved')
            else:
                print(f"No activities found between {start_time} and {end_time}")
                logging.info(f'No activities found between {start_time} and {end_time}')
        except ValueError:
            print("Invalid date or date-time format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS.")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
