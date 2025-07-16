#!/bin/bash

# Shadow@Bhanu KALI Customization Script
# This script automates the customization of Kali Linux terminal environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to backup existing config files
backup_configs() {
    print_header "Backing up existing configuration files"
    
    local backup_dir="$HOME/.config_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup shell configs
    [ -f "$HOME/.zshrc" ] && cp "$HOME/.zshrc" "$backup_dir/"
    [ -f "$HOME/.bashrc" ] && cp "$HOME/.bashrc" "$backup_dir/"
    [ -f "$HOME/.bash_aliases" ] && cp "$HOME/.bash_aliases" "$backup_dir/"
    
    print_status "Backup created at: $backup_dir"
}

# Function to update system
update_system() {
    print_header "Updating system packages"
    sudo apt update && sudo apt upgrade -y
    print_status "System updated successfully"
}

# Function to install essential packages
install_packages() {
    print_header "Installing essential packages"
    
    local packages=(
        "zsh"
        "git"
        "curl"
        "wget"
        "eza"
        "ripgrep"
        "fd-find"
        "fastfetch"
        "fzf"
        "plymouth"
        "plymouth-themes"
        "zsh-autosuggestions"
        "zsh-syntax-highlighting"
        "figlet"
        "toilet"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            print_status "Installing $package..."
            sudo apt install -y "$package"
        else
            print_status "$package is already installed"
        fi
    done
}

# Function to install Powerlevel10k
install_powerlevel10k() {
    print_header "Installing Powerlevel10k theme"
    
    if [ ! -d "$HOME/.powerlevel10k" ]; then
        git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$HOME/.powerlevel10k"
        print_status "Powerlevel10k installed successfully"
    else
        print_status "Powerlevel10k already installed"
    fi
}

# Function to install GRUB2 themes
install_grub_themes() {
    print_header "Installing GRUB2 themes"
    
    if [ ! -d "$HOME/grub2-themes" ]; then
        cd "$HOME"
        git clone https://github.com/vinceliuice/grub2-themes.git
        cd grub2-themes
        sudo ./install.sh -b -t tela
        print_status "GRUB2 themes installed successfully"
    else
        print_status "GRUB2 themes already installed"
    fi
}

# Function to configure Zsh
configure_zsh() {
    print_header "Configuring Zsh"
    
    # Change default shell to zsh
    if [ "$SHELL" != "/usr/bin/zsh" ] && [ "$SHELL" != "/bin/zsh" ]; then
        chsh -s $(which zsh)
        print_status "Default shell changed to Zsh"
    fi
    
    # Create .zshrc configuration
    cat > "$HOME/.zshrc" << 'EOF'
# Shadow@Bhanu Zsh Configuration

# Powerlevel10k theme
source ~/.powerlevel10k/powerlevel10k.zsh-theme

# Zsh plugins
source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh

# Enhanced ls aliases with eza
alias ls='eza --icons --long --group-directories-first'
alias ll='ls -l'
alias la='ls -A'
alias l='ls -CF'

# System update alias
alias update="sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt dist-upgrade -y && sudo apt update --fix-missing -y && sudo apt upgrade --fix-missing -y"

# Enhanced search and file commands
alias grep='rg --color=auto'
alias find='fd'

# TLDR man pages
alias man='tldr'

# Custom script aliases (adjust paths as needed)
alias setup="python3 ~/Scripts/wifi_auto_login.py"
alias server="bash /home/bhanu/Scripts/server.sh"

# Random color generator (foreground colors only)
random_color() {
  COLORS=("31" "32" "33" "34" "35" "36" "37")
  echo ${COLORS[$RANDOM % ${#COLORS[@]}]}
}

# Typewriter effect to display text character-by-character
typewriter_effect() {
  text=$1
  delay=$2
  for ((i=0; i<${#text}; i++)); do
    echo -n "${text:$i:1}"
    sleep $delay
  done
}

# Show message with random color and typewriter effect using figlet
show_message() {
  FG_COLOR=$(random_color)
  echo -n -e "\033[${FG_COLOR}m"
  typewriter_effect "bhanu㉿Shadow" 0.1 | figlet -f slant
  echo -e "\033[0m"
}

# Time-based function to display the welcome message
time_based_colors() {
  hour=$(date +"%H")
  show_message
}

# Display the message on terminal startup
time_based_colors

# Override clear to show the welcome message after clearing the terminal
clear() {
  command clear
  time_based_colors
}

# Custom prompt
export PS1="%F{green}bhanu㉿Shadow%f:%F{red}%~%f ~ "

# Environment variables
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

# Fastfetch on startup
fastfetch

# Advanced man function with fzf integration
man() {
    local cmd
    if [[ -z "$1" ]]; then
        # If no command is provided, use fzf to search tldr commands
        cmd=$(tldr --list | fzf --preview 'tldr {}' --height 80% --border --reverse)
        [[ -n "$cmd" ]] && tldr "$cmd"
    else
        # Try TLDR first, fallback to man if no page exists
        if tldr "$1" &>/dev/null; then
            tldr "$1"
        else
            command man "$1"
        fi
    fi
}
EOF
    
    print_status "Zsh configuration created"
}

# Function to configure Bash
configure_bash() {
    print_header "Configuring Bash"
    
    # Backup existing .bashrc
    [ -f "$HOME/.bashrc" ] && cp "$HOME/.bashrc" "$HOME/.bashrc.bak"
    
    # Append configurations to .bashrc
    cat >> "$HOME/.bashrc" << 'EOF'

# Shadow@Bhanu Bash Configuration

# Enhanced ls aliases with eza
alias ls='eza --icons --long --group-directories-first'
alias ll='ls -l'
alias la='ls -A'
alias l='ls -CF'

# System update alias
alias update="sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt dist-upgrade -y && sudo apt update --fix-missing -y && sudo apt upgrade --fix-missing -y"

# Enhanced search and file commands
alias grep='rg --color=auto'
alias find='fd'

# TLDR man pages
alias man='tldr'

# Custom script aliases (adjust paths as needed)
alias setup="python3 ~/Scripts/wifi_auto_login.py"
alias server="bash /home/bhanu/Scripts/server.sh"

# Random color generator (foreground colors only)
random_color() {
  COLORS=("31" "32" "33" "34" "35" "36" "37")
  echo ${COLORS[$RANDOM % ${#COLORS[@]}]}
}

# Typewriter effect to display text character-by-character
typewriter_effect() {
  text=$1
  delay=$2
  for ((i=0; i<${#text}; i++)); do
    echo -n "${text:$i:1}"
    sleep $delay
  done
}

# Show message with random color and typewriter effect using figlet
show_message() {
  FG_COLOR=$(random_color)
  echo -n -e "\033[${FG_COLOR}m"
  typewriter_effect "bhanu㉿Shadow" 0.1 | figlet -f slant
  echo -e "\033[0m"
}

# Time-based function to display the welcome message
time_based_colors() {
  hour=$(date +"%H")
  show_message
}

# Display the message on terminal startup
time_based_colors

# Override clear to show the welcome message after clearing the terminal
clear() {
  command clear
  time_based_colors
}

# Custom prompt
export PS1="\[\e[1;32m\]bhanu㉿Shadow\[\e[0m\]:\[\e[1;31m\]\w\[\e[0m\]# "

# Environment variables
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

# Fastfetch on startup
fastfetch

# Advanced man function with fzf integration
man() {
    local cmd
    if [[ -z "$1" ]]; then
        # If no command is provided, use fzf to search tldr commands
        cmd=$(tldr --list | fzf --preview 'tldr {}' --height 80% --border --reverse)
        [[ -n "$cmd" ]] && tldr "$cmd"
    else
        # Try TLDR first, fallback to man if no page exists
        if tldr "$1" &>/dev/null; then
            tldr "$1"
        else
            command man "$1"
        fi
    fi
}

# Load bash aliases if they exist
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# Enable programmable completion features
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
EOF
    
    print_status "Bash configuration updated"
}

# Function to configure Plymouth theme
configure_plymouth() {
    print_header "Configuring Plymouth theme"
    
    # List available themes
    print_status "Available Plymouth themes:"
    plymouth-set-default-theme --list
    
    # Set spinfinity theme
    sudo plymouth-set-default-theme -R spinfinity
    print_status "Plymouth theme set to spinfinity"
}

# Function to configure MOTD and issue
configure_motd() {
    print_header "Configuring MOTD and issue messages"
    
    # Update /etc/issue
    echo "🔥 WELCOME TO Shadow@Bh4nu KALI 😈🔥" | sudo tee /etc/issue > /dev/null
    
    # Update /etc/motd
    echo "🔥 WELCOME TO Shadow@Bh4nu KALI 😈🔥" | sudo tee /etc/motd > /dev/null
    
    print_status "MOTD and issue messages updated"
}

# Function to configure root environment
configure_root() {
    print_header "Configuring root environment"
    
    # Add hacker banner to root's .bashrc
    sudo bash -c 'cat >> /root/.bashrc << "EOF"

# Hacker banner
toilet -f mono12 -F metal "Shadow"
EOF'
    
    print_status "Root environment configured"
}

# Function to update GRUB
update_grub() {
    print_header "Updating GRUB configuration"
    sudo update-grub
    print_status "GRUB updated successfully"
}

# Function to configure TLDR
configure_tldr() {
    print_header "Configuring TLDR"
    tldr --update
    print_status "TLDR database updated"
}

# Main function
main() {
    print_header "Shadow@Bhanu KALI Customization Script"
    echo -e "${PURPLE}This script will customize your Kali Linux terminal environment${NC}"
    echo -e "${PURPLE}Please run this script as your regular user (not root)${NC}"
    echo
    
    # Check if running as root
    if [ "$(id -u)" -eq 0 ]; then
        print_error "Please run this script as your regular user, not as root"
        exit 1
    fi
    
    # Confirm before proceeding
    read -p "Do you want to proceed with the customization? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Customization cancelled"
        exit 0
    fi
    
    # Execute customization steps
    backup_configs
    update_system
    install_packages
    install_powerlevel10k
    install_grub_themes
    configure_zsh
    configure_bash
    configure_plymouth
    configure_motd
    configure_root
    configure_tldr
    update_grub
    
    print_header "Customization Complete!"
    echo -e "${GREEN}Your Kali terminal has been customized successfully!${NC}"
    echo -e "${YELLOW}Please restart your terminal or run 'source ~/.zshrc' (or ~/.bashrc) to apply changes${NC}"
    echo -e "${YELLOW}Run 'p10k configure' to customize your Powerlevel10k theme${NC}"
    echo -e "${YELLOW}Reboot your system to see the GRUB and Plymouth themes${NC}"
}

# Run the main function
main "$@"
