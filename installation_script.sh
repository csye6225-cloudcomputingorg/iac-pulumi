#!/bin/bash

echo_info () {
    echo $1
}

echo_info "---------UPDATES-BEING-INSTALLED---------"

# Update the system
sudo apt update && sudo apt upgrade -y

# # Install necessary packages
# sudo apt install -y python3 python3-pip mariadb-server mariadb-devel unzip

# Installing python server
echo_info "---------INSTALLING-PYTHON---------"
sudo apt install -y python3 python3-pip

# Create a Python virtual environment
sudo apt install python3.11-venv -y
python3.11 -m venv myenv
source myenv/bin/activate

# Install Python dependencies (update libraries for postgreSQL)
pip3 install bcrypt==4.0.1 blinker==1.6.3 certifi==2023.7.22 charset-normalizer==3.3.0 click==8.1.7 Flask==2.2.5 Flask-Cors==4.0.0 Flask-MySQL==1.5.2 Flask-SQLAlchemy==2.5.1 greenlet==3.0.0 idna==3.4 iniconfig==2.0.0 itsdangerous==2.1.2 Jinja2==3.1.2 MarkupSafe==2.1.3 mysql-connector-python==8.1.0 packaging==23.2 pip==23.0.1 pluggy==1.3.0 protobuf==4.21.12 PyMySQL==1.1.0 pytest==7.4.2 python-dotenv==1.0.0 requests==2.31.0 setuptools==66.1.1 SQLAlchemy==2.0.21 typing_extensions==4.8.0 urllib3==2.0.6 Werkzeug==3.0.0

# Start and enable MariaDB service
echo_info "---------INSTALLING-MARIADB---------"
sudo apt install mariadb-server -y
sudo systemctl start mariadb
sudo systemctl enable mariadb
sudo systemctl status mariadb

# Secure MariaDB installation (optional but recommended)
# Make sure to set a strong password for the root user
# sudo mysql_secure_installation

# Installing UNZIP
echo_info "---------INSTALLING-UNZIP---------"
sudo apt install -y unzip

# Download and unzip your web application code
mkdir webapp
unzip webapp.zip -d webapp
rm webapp.zip
cd webapp || exit

# python app.py  # Or whatever command starts your web app

# Your web application should now be running

# Optionally, create a systemd service to keep your app running on system restart
# Write a systemd service file and enable it
# For example:
# sudo nano /etc/systemd/system/my-webapp.service
# [Unit]
# Description=My Web Application
#
# [Service]
# ExecStart=/path/to/your/start_script.sh
# WorkingDirectory=/path/to/your/web_app_directory
# User=your_username
# Restart=always
#
# [Install]
# WantedBy=multi-user.target
#
# Then, enable and start the service:
# sudo systemctl enable my-webapp
# sudo systemctl start my-webapp

# Don't forget to open necessary ports in your security group for your web app
# (e.g., HTTP port 80, HTTPS port 443, etc.)

# When you're done, deactivate the virtual environment
deactivate
