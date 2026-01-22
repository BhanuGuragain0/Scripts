#!/usr/bin/env bash

# ============================================================================
# Shadow@Bhanu Elite Kali Linux Customization - Installation Script v2.0
# ============================================================================
# 
# DESCRIPTION:
#   Production-grade installation script for elite penetration testing
#   terminal environment. Implements best practices for error handling,
#   logging, and user feedback.
#
# FEATURES:
#   - Comprehensive dependency management
#   - Intelligent error handling with rollback capability
#   - Detailed logging for troubleshooting
#   - Non-destructive backup system
#   - Performance benchmarking
#   - Health checks post-installation
#
# AUTHOR: Shadow@Bhanu
# VERSION: 2.0.0
# LICENSE: MIT
# ============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Sane word splitting

# ============================================================================
# CONFIGURATION
# ============================================================================

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/tmp/kali-setup-$(date +%Y%m%d_%H%M%S).log"
readonly BACKUP_DIR="$HOME/.config_backup_$(date +%Y%m%d_%H%M%S)"

# XDG Base Directory Specification
readonly XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
readonly XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
readonly XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
readonly XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"

# Installation paths
readonly ZSH_CONFIG_DIR="$XDG_CONFIG_HOME/zsh"
readonly ZSH_DATA_DIR="$XDG_DATA_HOME/zsh"
readonly ZSH_CACHE_DIR="$XDG_CACHE_HOME/zsh"
readonly ZSH_STATE_DIR="$XDG_STATE_HOME/zsh"
readonly ZINIT_HOME="$XDG_DATA_HOME/zinit/zinit.git"
readonly P10K_HOME="$XDG_DATA_HOME/powerlevel10k"
readonly FONTS_DIR="$HOME/.local/share/fonts"
readonly PENTEST_WORKSPACE="$HOME/Pentest"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'  # No Color

# Feature flags
SKIP_BACKUP=false
SKIP_FONTS=false
VERBOSE=false
DRY_RUN=false

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Print colored output with timestamps
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo -e "[${timestamp}] ${level} ${message}" | tee -a "$LOG_FILE"
}

info() {
    log "${CYAN}[INFO]${NC}" "$*"
}

success() {
    log "${GREEN}[SUCCESS]${NC}" "$*"
}

warning() {
    log "${YELLOW}[WARNING]${NC}" "$*"
}

error() {
    log "${RED}[ERROR]${NC}" "$*" >&2
}

debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        log "${PURPLE}[DEBUG]${NC}" "$*"
    fi
}

# Print section headers
print_header() {
    local title="$1"
    local width=80
    local padding=$(( (width - ${#title} - 2) / 2 ))
    
    echo -e "\n${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}"
    printf "${CYAN}=%*s%s%*s=\n" $padding "" "$title" $padding ""
    echo -e "${CYAN}$(printf '=%.0s' $(seq 1 $width))${NC}\n"
}

# Error handler with cleanup
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    
    error "$message"
    error "Installation failed. Check log file: $LOG_FILE"
    
    if [[ -d "$BACKUP_DIR" ]]; then
        warning "Backup available at: $BACKUP_DIR"
        warning "To restore: cp -r $BACKUP_DIR/* $HOME/"
    fi
    
    exit "$exit_code"
}

# Check if running as root (we don't want that)
check_not_root() {
    if [[ $EUID -eq 0 ]]; then
        error_exit "This script should NOT be run as root. Run as regular user." 1
    fi
}

# Check if required commands exist
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        return 1
    fi
    return 0
}

# Verify system requirements
check_system_requirements() {
    print_header "System Requirements Check"
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        error_exit "Cannot detect OS. /etc/os-release not found." 1
    fi
    
    source /etc/os-release
    info "Detected OS: $NAME $VERSION"
    
    # Warn if not Kali (but allow continuation)
    if [[ "$ID" != "kali" ]]; then
        warning "This script is optimized for Kali Linux."
        warning "Detected: $ID"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
    
    # Check Zsh version
    if check_command zsh; then
        local zsh_version=$(zsh --version | cut -d' ' -f2)
        info "Zsh version: $zsh_version"
        
        # Version comparison (requires 5.8+)
        if [[ "$(printf '%s\n' "5.8" "$zsh_version" | sort -V | head -n1)" != "5.8" ]]; then
            warning "Zsh 5.8+ recommended. You have $zsh_version"
        fi
    else
        warning "Zsh not found. Will be installed."
    fi
    
    # Check available disk space (need at least 500MB)
    local available_space=$(df -m "$HOME" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 500 ]]; then
        warning "Low disk space: ${available_space}MB available"
        warning "Recommend at least 500MB free space"
    else
        info "Available disk space: ${available_space}MB"
    fi
    
    success "System requirements check completed"
}

# ============================================================================
# BACKUP FUNCTIONS
# ============================================================================

backup_existing_configs() {
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        info "Skipping backup (--skip-backup flag set)"
        return 0
    fi
    
    print_header "Backing Up Existing Configuration"
    
    mkdir -p "$BACKUP_DIR"
    
    local files_to_backup=(
        "$HOME/.zshrc"
        "$HOME/.zshenv"
        "$HOME/.p10k.zsh"
        "$ZSH_CONFIG_DIR"
        "$HOME/.oh-my-zsh"
    )
    
    local backed_up=0
    for file in "${files_to_backup[@]}"; do
        if [[ -e "$file" ]]; then
            local basename_file=$(basename "$file")
            info "Backing up: $file"
            cp -r "$file" "$BACKUP_DIR/$basename_file" 2>/dev/null || true
            ((backed_up++))
        fi
    done
    
    if [[ $backed_up -gt 0 ]]; then
        success "Backed up $backed_up items to: $BACKUP_DIR"
    else
        info "No existing configuration found to backup"
    fi
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

update_system() {
    print_header "System Update"
    
    info "Updating package repositories..."
    if [[ "$DRY_RUN" == "false" ]]; then
        sudo apt update || error_exit "Failed to update package repositories"
    else
        info "[DRY RUN] Would update package repositories"
    fi
    
    info "Upgrading installed packages..."
    if [[ "$DRY_RUN" == "false" ]]; then
        sudo apt upgrade -y || warning "Some packages failed to upgrade"
    else
        info "[DRY RUN] Would upgrade packages"
    fi
    
    success "System updated successfully"
}

install_essential_packages() {
    print_header "Installing Essential Packages"
    
    # Core packages
    local core_packages=(
        "zsh"           # Shell
        "git"           # Version control
        "curl"          # Data transfer
        "wget"          # File download
        "build-essential" # Compilation tools
    )
    
    # Modern CLI tools
    local cli_tools=(
        "eza"           # Modern ls (or exa as fallback)
        "ripgrep"       # Fast grep
        "fd-find"       # Fast find
        "bat"           # Better cat
        "fzf"           # Fuzzy finder
        "jq"            # JSON processor
        "delta"         # Better diff
    )
    
    # System info tools
    local info_tools=(
        "fastfetch"     # System info
        "neofetch"      # Fallback system info
        "btop"          # Modern top
        "htop"          # Alternative top
    )
    
    # Visual/fun tools
    local visual_tools=(
        "figlet"        # ASCII art text
        "toilet"        # Colored ASCII text
        "lolcat"        # Rainbow colors
    )
    
    # Security/monitoring tools
    local security_tools=(
        "inotify-tools" # File monitoring
    )
    
    # Python tools
    local python_tools=(
        "python3"
        "python3-pip"
    )
    
    # Combine all packages
    local all_packages=(
        "${core_packages[@]}"
        "${cli_tools[@]}"
        "${info_tools[@]}"
        "${visual_tools[@]}"
        "${security_tools[@]}"
        "${python_tools[@]}"
    )
    
    # Install packages
    for package in "${all_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            debug "$package is already installed"
        else
            info "Installing $package..."
            if [[ "$DRY_RUN" == "false" ]]; then
                if ! sudo apt install -y "$package"; then
                    warning "Failed to install $package (non-critical)"
                fi
            else
                info "[DRY RUN] Would install $package"
            fi
        fi
    done
    
    # Check for alternative package names
    if ! check_command bat && check_command batcat; then
        info "Creating 'bat' symlink for 'batcat'"
        mkdir -p "$HOME/.local/bin"
        ln -sf "$(which batcat)" "$HOME/.local/bin/bat"
    fi
    
    if ! check_command fd && check_command fdfind; then
        info "Creating 'fd' symlink for 'fdfind'"
        mkdir -p "$HOME/.local/bin"
        ln -sf "$(which fdfind)" "$HOME/.local/bin/fd"
    fi
    
    # Try to install eza, fallback to exa
    if ! check_command eza; then
        if check_command exa; then
            info "Using 'exa' (eza not available)"
        else
            warning "Neither eza nor exa available. Will use standard ls"
        fi
    fi
    
    success "Essential packages installed"
}

install_zinit() {
    print_header "Installing Zinit Plugin Manager"
    
    if [[ -d "$ZINIT_HOME" ]]; then
        info "Zinit already installed at: $ZINIT_HOME"
        return 0
    fi
    
    info "Cloning Zinit repository..."
    if [[ "$DRY_RUN" == "false" ]]; then
        mkdir -p "$(dirname "$ZINIT_HOME")"
        if ! git clone --depth=1 https://github.com/zdharma-continuum/zinit.git "$ZINIT_HOME"; then
            error_exit "Failed to clone Zinit repository"
        fi
    else
        info "[DRY RUN] Would clone Zinit to $ZINIT_HOME"
    fi
    
    success "Zinit installed successfully"
}

install_powerlevel10k() {
    print_header "Installing Powerlevel10k Theme"
    
    if [[ -d "$P10K_HOME" ]]; then
        info "Powerlevel10k already installed at: $P10K_HOME"
        return 0
    fi
    
    info "Cloning Powerlevel10k repository..."
    if [[ "$DRY_RUN" == "false" ]]; then
        mkdir -p "$(dirname "$P10K_HOME")"
        if ! git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$P10K_HOME"; then
            error_exit "Failed to clone Powerlevel10k repository"
        fi
    else
        info "[DRY RUN] Would clone Powerlevel10k to $P10K_HOME"
    fi
    
    success "Powerlevel10k installed successfully"
}

install_nerd_fonts() {
    if [[ "$SKIP_FONTS" == "true" ]]; then
        info "Skipping Nerd Fonts installation (--skip-fonts flag set)"
        return 0
    fi
    
    print_header "Installing Nerd Fonts"
    
    mkdir -p "$FONTS_DIR"
    cd "$FONTS_DIR"
    
    local fonts=(
        "MesloLGS NF Regular.ttf"
        "MesloLGS NF Bold.ttf"
        "MesloLGS NF Italic.ttf"
        "MesloLGS NF Bold Italic.ttf"
    )
    
    local base_url="https://github.com/romkatv/powerlevel10k-media/raw/master"
    
    for font in "${fonts[@]}"; do
        local encoded_font="${font// /%20}"
        if [[ -f "$font" ]]; then
            debug "$font already exists"
        else
            info "Downloading $font..."
            if [[ "$DRY_RUN" == "false" ]]; then
                if ! curl -fLo "$font" "$base_url/$encoded_font"; then
                    warning "Failed to download $font"
                fi
            else
                info "[DRY RUN] Would download $font"
            fi
        fi
    done
    
    if [[ "$DRY_RUN" == "false" ]]; then
        info "Refreshing font cache..."
        fc-cache -fv >/dev/null 2>&1
    else
        info "[DRY RUN] Would refresh font cache"
    fi
    
    success "Nerd Fonts installed successfully"
    info "⚠️  IMPORTANT: Set your terminal font to 'MesloLGS NF Regular' for icons to display correctly"
}

setup_directory_structure() {
    print_header "Setting Up Directory Structure"
    
    local directories=(
        "$ZSH_CONFIG_DIR"
        "$ZSH_CONFIG_DIR/modules"
        "$ZSH_CONFIG_DIR/completion"
        "$ZSH_DATA_DIR"
        "$ZSH_CACHE_DIR"
        "$ZSH_STATE_DIR"
        "$HOME/.local/bin"
        "$PENTEST_WORKSPACE"
        "$PENTEST_WORKSPACE/recon"
        "$PENTEST_WORKSPACE/scanning"
        "$PENTEST_WORKSPACE/exploitation"
        "$PENTEST_WORKSPACE/loot"
        "$PENTEST_WORKSPACE/reports"
    )
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            info "Creating directory: $dir"
            if [[ "$DRY_RUN" == "false" ]]; then
                mkdir -p "$dir" || warning "Failed to create $dir"
            else
                info "[DRY RUN] Would create $dir"
            fi
        else
            debug "Directory already exists: $dir"
        fi
    done
    
    success "Directory structure created"
}

deploy_configuration() {
    print_header "Deploying Configuration Files"
    
    # Check if zsh.sh exists in script directory
    local source_zshrc="$SCRIPT_DIR/zsh.sh"
    if [[ ! -f "$source_zshrc" ]]; then
        error_exit "zsh.sh not found in $SCRIPT_DIR"
    fi
    
    # Deploy main .zshrc
    info "Deploying .zshrc to $ZSH_CONFIG_DIR/.zshrc"
    if [[ "$DRY_RUN" == "false" ]]; then
        cp "$source_zshrc" "$ZSH_CONFIG_DIR/.zshrc" || error_exit "Failed to copy zsh.sh"
        chmod 644 "$ZSH_CONFIG_DIR/.zshrc"
    else
        info "[DRY RUN] Would copy $source_zshrc to $ZSH_CONFIG_DIR/.zshrc"
    fi
    
    # Create symlink in home directory
    info "Creating symlink: ~/.zshrc -> $ZSH_CONFIG_DIR/.zshrc"
    if [[ "$DRY_RUN" == "false" ]]; then
        ln -sf "$ZSH_CONFIG_DIR/.zshrc" "$HOME/.zshrc"
    else
        info "[DRY RUN] Would create symlink"
    fi
    
    # Create .zshenv for XDG compliance
    info "Creating .zshenv"
    if [[ "$DRY_RUN" == "false" ]]; then
        cat > "$HOME/.zshenv" << 'EOF'
# XDG Base Directory Specification
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_STATE_HOME="$HOME/.local/state"

# Zsh configuration location
export ZDOTDIR="$XDG_CONFIG_HOME/zsh"
EOF
        chmod 644 "$HOME/.zshenv"
    else
        info "[DRY RUN] Would create .zshenv"
    fi
    
    success "Configuration files deployed"
}

change_default_shell() {
    print_header "Setting Zsh as Default Shell"
    
    local current_shell="$SHELL"
    local zsh_path="$(which zsh)"
    
    if [[ "$current_shell" == "$zsh_path" ]]; then
        info "Zsh is already the default shell"
        return 0
    fi
    
    info "Current shell: $current_shell"
    info "Changing default shell to: $zsh_path"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        if ! chsh -s "$zsh_path"; then
            warning "Failed to change default shell. You may need to run:"
            warning "  chsh -s $(which zsh)"
        else
            success "Default shell changed to Zsh"
        fi
    else
        info "[DRY RUN] Would change default shell to $zsh_path"
    fi
}

# ============================================================================
# POST-INSTALLATION
# ============================================================================

run_health_check() {
    print_header "Running Health Check"
    
    local issues=0
    
    # Check Zsh installation
    if check_command zsh; then
        success "✓ Zsh installed: $(zsh --version)"
    else
        error "✗ Zsh not found"
        ((issues++))
    fi
    
    # Check Zinit
    if [[ -d "$ZINIT_HOME" ]]; then
        success "✓ Zinit installed"
    else
        error "✗ Zinit not found"
        ((issues++))
    fi
    
    # Check Powerlevel10k
    if [[ -d "$P10K_HOME" ]]; then
        success "✓ Powerlevel10k installed"
    else
        error "✗ Powerlevel10k not found"
        ((issues++))
    fi
    
    # Check essential tools
    local tools=("eza" "bat" "fd" "rg" "fzf" "jq")
    for tool in "${tools[@]}"; do
        if check_command "$tool"; then
            success "✓ $tool"
        else
            warning "⚠ $tool not found (optional)"
        fi
    done
    
    # Check configuration files
    if [[ -f "$ZSH_CONFIG_DIR/.zshrc" ]]; then
        success "✓ Configuration deployed"
    else
        error "✗ Configuration not found"
        ((issues++))
    fi
    
    # Check fonts
    if fc-list | grep -q "MesloLGS NF"; then
        success "✓ Nerd Fonts installed"
    else
        warning "⚠ Nerd Fonts not detected"
        warning "  Install manually and set terminal font to 'MesloLGS NF Regular'"
    fi
    
    if [[ $issues -eq 0 ]]; then
        success "\nHealth check passed! No critical issues found."
    else
        warning "\nHealth check completed with $issues critical issues."
        warning "Review the output above and fix any errors."
    fi
}

benchmark_startup() {
    print_header "Benchmarking Startup Performance"
    
    if ! check_command zsh; then
        warning "Zsh not available, skipping benchmark"
        return
    fi
    
    info "Running startup benchmark (5 iterations)..."
    
    local total_time=0
    local iterations=5
    
    for i in $(seq 1 $iterations); do
        local start_time=$(date +%s%N)
        zsh -ic exit 2>/dev/null
        local end_time=$(date +%s%N)
        local elapsed=$(( (end_time - start_time) / 1000000 ))  # Convert to ms
        total_time=$((total_time + elapsed))
        debug "Iteration $i: ${elapsed}ms"
    done
    
    local avg_time=$((total_time / iterations))
    
    info "Average startup time: ${avg_time}ms"
    
    if [[ $avg_time -lt 150 ]]; then
        success "Excellent! Startup time < 150ms"
    elif [[ $avg_time -lt 500 ]]; then
        info "Good startup time (< 500ms)"
    else
        warning "Slow startup detected (> 500ms)"
        warning "Run 'zinit times' to identify slow plugins"
    fi
}

show_next_steps() {
    print_header "Installation Complete!"
    
    cat << EOF
${GREEN}✅ Shadow@Bhanu Elite Kali Customization installed successfully!${NC}

${CYAN}📋 Next Steps:${NC}

1. ${YELLOW}Restart your terminal${NC} or run:
   ${WHITE}exec zsh${NC}

2. ${YELLOW}Configure Powerlevel10k${NC} (first-time wizard):
   ${WHITE}p10k configure${NC}

3. ${YELLOW}Set terminal font${NC} to:
   ${WHITE}MesloLGS NF Regular${NC}
   (Preferences → Appearance → Font)

4. ${YELLOW}Initialize file integrity baseline${NC}:
   ${WHITE}sec-baseline${NC}

5. ${YELLOW}Test the installation${NC}:
   ${WHITE}sysinfo${NC}
   ${WHITE}suggest${NC}
   ${WHITE}ai help me scan a target${NC}

${CYAN}📚 Quick Reference:${NC}

  • System Dashboard:     ${WHITE}sysinfo${NC}
  • AI Commands:          ${WHITE}ai <your query>${NC}
  • Smart Suggestions:    ${WHITE}suggest${NC}
  • Set Target:           ${WHITE}set-target <ip> [name]${NC}
  • Security Checks:      ${WHITE}sec-check-fs${NC}, ${WHITE}sec-check-net${NC}
  • Live Dashboard:       ${WHITE}live-dashboard${NC}

${CYAN}📁 Files:${NC}

  • Config:      ${WHITE}$ZSH_CONFIG_DIR/.zshrc${NC}
  • Backup:      ${WHITE}$BACKUP_DIR${NC}
  • Log:         ${WHITE}$LOG_FILE${NC}
  • Workspace:   ${WHITE}$PENTEST_WORKSPACE${NC}

${CYAN}🔧 Customization:${NC}

  • Edit config:    ${WHITE}nvim $ZSH_CONFIG_DIR/.zshrc${NC}
  • Reload:         ${WHITE}source ~/.zshrc${NC}
  • Update:         ${WHITE}zinit update${NC}

${GREEN}🔥 Happy hacking, Shadow! 🔥${NC}

${PURPLE}For issues/feedback: https://github.com/BhanuGuragain0/Scripts${NC}

EOF
}

# ============================================================================
# COMMAND-LINE ARGUMENTS
# ============================================================================

show_usage() {
    cat << EOF
${CYAN}Shadow@Bhanu Elite Kali Customization Installer v$SCRIPT_VERSION${NC}

${YELLOW}Usage:${NC}
  $SCRIPT_NAME [OPTIONS]

${YELLOW}Options:${NC}
  -h, --help              Show this help message
  -v, --verbose           Enable verbose output
  -n, --dry-run           Show what would be done without making changes
  --skip-backup           Skip backing up existing configuration
  --skip-fonts            Skip Nerd Fonts installation
  --no-system-update      Skip system package update

${YELLOW}Examples:${NC}
  # Standard installation
  ./$SCRIPT_NAME

  # Dry run to see what would happen
  ./$SCRIPT_NAME --dry-run

  # Verbose installation without system update
  ./$SCRIPT_NAME -v --no-system-update

EOF
}

parse_arguments() {
    local skip_system_update=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=true
                info "DRY RUN MODE - No changes will be made"
                shift
                ;;
            --skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --skip-fonts)
                SKIP_FONTS=true
                shift
                ;;
            --no-system-update)
                skip_system_update=true
                shift
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Store for later use
    if [[ "$skip_system_update" == "true" ]]; then
        export SKIP_SYSTEM_UPDATE=true
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Parse command-line arguments
    parse_arguments "$@"
    
    # Print banner
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗                    ║
║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║                    ║
║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║                    ║
║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║                    ║
║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝                    ║
║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝                     ║
║                                                                           ║
║            Elite Kali Linux Customization - Installer v2.0                ║
║                     by Shadow@Bhanu                                       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    
    echo
    info "Starting installation at $(date)"
    info "Log file: $LOG_FILE"
    echo
    
    # Pre-flight checks
    check_not_root
    check_system_requirements
    
    # Confirm installation
    if [[ "$DRY_RUN" == "false" ]]; then
        echo
        read -p "$(echo -e ${YELLOW}Proceed with installation? [y/N]:${NC} )" -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Installation cancelled by user"
            exit 0
        fi
    fi
    
    # Start installation timer
    local start_time=$(date +%s)
    
    # Execute installation steps
    backup_existing_configs
    
    if [[ "${SKIP_SYSTEM_UPDATE:-false}" == "false" ]]; then
        update_system
    else
        info "Skipping system update (--no-system-update flag set)"
    fi
    
    install_essential_packages
    install_zinit
    install_powerlevel10k
    install_nerd_fonts
    setup_directory_structure
    deploy_configuration
    change_default_shell
    
    # Post-installation
    run_health_check
    
    if [[ "$DRY_RUN" == "false" ]]; then
        benchmark_startup
    fi
    
    # Calculate installation time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    info "Installation completed in ${duration}s"
    
    # Show next steps
    show_next_steps
}

# Execute main function
main "$@"
