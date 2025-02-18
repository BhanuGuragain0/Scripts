#!/bin/bash
#
# Professional Python Server Launcher for Pentesting
# Shadow@Bhanu Python Server Starting
#
# This script starts a Python HTTP server accessible over the internet.
# It supports command-line options for port (-p), background mode (-b),
# and bind address (-i). Logging, robust error handling, and graceful shutdown
# are provided for real-world pentesting scenarios.
#

# Exit immediately if a command exits with a non-zero status,
# Treat unset variables as an error, and ensure pipelines fail on first error.
set -euo pipefail

# Trap any error and display the line number and error message
trap 'echo -e "${COLOR_RED}[ ERROR ] An unexpected error occurred on line ${LINENO}. Exiting...${COLOR_RESET}"' ERR

# ANSI Color Codes for formatted output
COLOR_BLUE="\e[1;34m"
COLOR_RED="\e[1;31m"
COLOR_GREEN="\e[1;32m"
COLOR_YELLOW="\e[1;33m"
COLOR_RESET="\e[0m"

# Usage information function
usage() {
  echo -e "${COLOR_YELLOW}Usage: $0 -p <port> [-b] [-i <bind_address>] [-h]${COLOR_RESET}"
  echo -e "${COLOR_YELLOW}  -p <port>          : Specify the port number (1-65535)${COLOR_RESET}"
  echo -e "${COLOR_YELLOW}  -b                 : Run the server in background mode${COLOR_RESET}"
  echo -e "${COLOR_YELLOW}  -i <bind_address>  : Specify the bind address (default: 0.0.0.0 for public/internet access)${COLOR_RESET}"
  echo -e "${COLOR_YELLOW}  -h                 : Display this help message${COLOR_RESET}"
  exit 1
}

# Function to get the current timestamp for logging purposes
get_timestamp() {
  date +"%Y-%m-%d %H:%M:%S"
}

# Function to check if Python3 is installed
check_dependency() {
  if ! command -v python3 &>/dev/null; then
    echo -e "${COLOR_RED}[ $(get_timestamp) ] Error: Python3 is not installed.${COLOR_RESET}"
    exit 1
  fi
}

# Function to validate the port number
validate_port() {
  local port="$1"
  if ! [[ $port =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo -e "${COLOR_RED}[ $(get_timestamp) ] Invalid port number: $port. Please specify a number between 1 and 65535.${COLOR_RESET}"
    exit 1
  fi
}

# Function to check if the chosen port is already in use
check_port_usage() {
  local port="$1"
  if ss -tuln | grep -q ":$port[[:space:]]"; then
    echo -e "${COLOR_RED}[ $(get_timestamp) ] Error: Port $port is already in use. Choose a different port.${COLOR_RESET}"
    exit 1
  fi
}

# Function to gracefully stop the server
stop_server() {
  echo -e "\n${COLOR_RED}[ $(get_timestamp) ] Stopping the server...${COLOR_RESET}"
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  echo -e "${COLOR_RED}[ $(get_timestamp) ] Server stopped successfully.${COLOR_RESET}"
  exit 0
}

# --- Command-Line Option Parsing ---
BACKGROUND_MODE="no"
BIND_ADDRESS=""
while getopts ":p:bi:h" opt; do
  case $opt in
    p)
      PORT="$OPTARG"
      ;;
    b)
      BACKGROUND_MODE="yes"
      ;;
    i)
      BIND_ADDRESS="$OPTARG"
      ;;
    h)
      usage
      ;;
    \?)
      echo -e "${COLOR_RED}[ $(get_timestamp) ] Invalid option: -$OPTARG${COLOR_RESET}"
      usage
      ;;
    :)
      echo -e "${COLOR_RED}[ $(get_timestamp) ] Option -$OPTARG requires an argument.${COLOR_RESET}"
      usage
      ;;
  esac
done
shift $((OPTIND -1))

# Display header banner with custom message
echo -e "${COLOR_BLUE}╔════════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_BLUE}║    Shadow@Bhanu Python Server Starting ║${COLOR_RESET}"
echo -e "${COLOR_BLUE}╚════════════════════════════════════════╝${COLOR_RESET}"

# Check Python dependency
check_dependency

# Prompt for port if not provided via options
if [ -z "${PORT:-}" ]; then
  read -p "Enter the port number to start the server: " PORT
fi
validate_port "$PORT"
check_port_usage "$PORT"

# Default bind address is 0.0.0.0 (public/internet access) if not provided
if [ -z "$BIND_ADDRESS" ]; then
  BIND_ADDRESS="0.0.0.0"
  echo -e "${COLOR_GREEN}[ $(get_timestamp) ] No bind address specified. Defaulting to ${BIND_ADDRESS} (accessible over the internet).${COLOR_RESET}"
fi

# Create a unique log file name based on port and timestamp
LOG_FILE="server_${PORT}_$(date +%Y%m%d-%H%M%S).log"

# Start the Python HTTP server with the specified parameters
if [ "$BACKGROUND_MODE" = "yes" ]; then
  echo -e "${COLOR_GREEN}[ $(get_timestamp) ] Starting Python HTTP server on port $PORT (bind: $BIND_ADDRESS) in background...${COLOR_RESET}"
  nohup python3 -m http.server "$PORT" --bind "$BIND_ADDRESS" > "$LOG_FILE" 2>&1 &
  PID=$!
  echo -e "${COLOR_YELLOW}[ $(get_timestamp) ] Server is running in background (PID: $PID).${COLOR_RESET}"
  echo -e "${COLOR_YELLOW}[ $(get_timestamp) ] Logs are available in: $LOG_FILE${COLOR_RESET}"
else
  echo -e "${COLOR_GREEN}[ $(get_timestamp) ] Starting Python HTTP server on port $PORT (bind: $BIND_ADDRESS)...${COLOR_RESET}"
  python3 -m http.server "$PORT" --bind "$BIND_ADDRESS" > "$LOG_FILE" 2>&1 &
  PID=$!
  echo -e "${COLOR_YELLOW}[ $(get_timestamp) ] Server is running (PID: $PID).${COLOR_RESET}"
fi

echo -e "${COLOR_YELLOW}[ $(get_timestamp) ] To stop the server, press CTRL+C or run: kill $PID${COLOR_RESET}"

# Trap SIGINT (Ctrl+C) for graceful shutdown
trap stop_server SIGINT

# Wait for the server process to complete
wait "$PID"
