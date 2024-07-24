#!/bin/bash

# Define variables
LOG_DIR="/var/log/devopsfetch"
SERVICE_FILE="/etc/systemd/system/devopsfetch.service"
NGINX_SERVICE_FILE="/etc/systemd/system/nginx_monitor.service"
LOGROTATE_FILE="/etc/logrotate.d/devopsfetch"
PYTHON_SCRIPT="/usr/local/bin/devopsfetch.py"

# Function to install and configure auditd
setup_auditd() {
    echo "Setting up auditd..."
    sudo apt-get update
    sudo apt-get install -y auditd

    # Enable and start auditd service
    sudo systemctl enable auditd
    sudo systemctl start auditd

    # Add rules to monitor user activities and file access
    echo "-w /var/log/auth.log -p wa -k auth_logs" | sudo tee -a /etc/audit/rules.d/audit.rules
    echo "-w /etc/passwd -p wa -k passwd_changes" | sudo tee -a /etc/audit/rules.d/audit.rules

    # Reload auditd configuration to apply the new rules
    sudo systemctl restart auditd
}

# Step 1: Install dependencies
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y python3 python3-venv nginx docker.io logrotate inotify-tools auditd

# Set up Python virtual environment and install Python packages
echo "Setting up virtual environment and installing Python packages..."
python3 -m venv venv
source venv/bin/activate
pip install psutil docker tabulate

# Step 2: Create log directory and initial log files
echo "Creating log directory and initial log files..."
sudo mkdir -p "$LOG_DIR"
sudo touch "$LOG_DIR/devopsfetch.log" "$LOG_DIR/port_activity.log" "$LOG_DIR/nginx_changes.log" "$LOG_DIR/docker_activity.log"
sudo chmod 666 "$LOG_DIR"/*.log

# Step 3: Create logrotate configuration file
echo "Creating logrotate configuration file..."
sudo tee "$LOGROTATE_FILE" <<EOL
$LOG_DIR/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        systemctl restart devopsfetch.service
    endscript
}
EOL

# Step 4: Create and enable systemd services
echo "Creating and enabling systemd services..."

# DevOps Fetch Service
sudo tee "$SERVICE_FILE" <<EOL
[Unit]
Description=DevOps Fetch Service
After=network.target

[Service]
ExecStart=$(pwd)/venv/bin/python $(pwd)/devopsfetch.py
WorkingDirectory=$(pwd)
Restart=always
Environment="PATH=$(pwd)/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
User=root

[Install]
WantedBy=multi-user.target
EOL

# Nginx Monitor Service
sudo tee "$NGINX_SERVICE_FILE" <<EOL
[Unit]
Description=Monitor Nginx configuration changes
After=network.target

[Service]
ExecStart=/usr/bin/python3 $(pwd)/devopsfetch.py -n
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd to recognize new service files
sudo systemctl daemon-reload

# Enable and start the services
sudo systemctl enable devopsfetch.service
sudo systemctl start devopsfetch.service

sudo systemctl enable nginx_monitor.service
sudo systemctl start nginx_monitor.service

# Step 5: Set up auditd for monitoring user activities and file access
setup_auditd

# Step 6: Create a cron job for monitoring port activities
echo "Creating cron job for monitoring port activities..."
(crontab -l 2>/dev/null; echo "* * * * * /usr/sbin/ss -tuln >> $LOG_DIR/port_activity.log") | crontab -

# Step 7: Create a script for monitoring Nginx configuration changes
echo "Creating script for monitoring Nginx configuration changes..."
sudo tee /usr/local/bin/monitor_nginx.sh <<EOL
#!/bin/bash
inotifywait -m /etc/nginx/nginx.conf -e modify |
    while read path action file; do
        echo "\$(date '+%Y-%m-%d %H:%M:%S,%f') - \$file was modified" >> $LOG_DIR/nginx_changes.log
    done
EOL
sudo chmod +x /usr/local/bin/monitor_nginx.sh

# Step 8: Set up Docker event logging
echo "Setting up Docker event logging..."
nohup docker events --filter 'event=start' --filter 'event=stop' --filter 'event=die' --filter 'event=restart' >> $LOG_DIR/docker_activity.log &

# Ensure the Python script is executable
echo "Making the Python script executable..."
sudo chmod +x $(pwd)/devopsfetch.py

echo "Installation and setup complete."
