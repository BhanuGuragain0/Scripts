# 🚀 Shadow@Bhanu Elite Terminal Environment 🚀
#
# Author: Bhanu
# Version: 1
#
# This Zsh configuration is engineered for elite penetration testers and cybersecurity professionals
# operating on Kali Linux. It transforms the standard terminal into a highly optimized, visually
# stunning, and functionally rich command center. It integrates performance enhancements,
# advanced security monitoring, AI-powered assistance, and a suite of tools designed to
# streamline offensive and defensive cyber operations.
#
# === TABLE OF CONTENTS ===
# 1.  Installation
# 2.  Core Features
# 3.  Usage Guide
# 4.  Performance Optimizations
# 5.  Troubleshooting
# 6.  Configuration Starts Here

# === 1. INSTALLATION ===
#
# 1.  Prerequisites:
#     - Kali Linux (or other Debian-based distro)
#     - Zsh (should be the default shell)
#     - Git, curl, figlet, jq, ss (net-tools), sensors
#     - PowerLevel10K theme (recommended)
#
# 2.  Installation Steps:
#     a.  Backup your existing ~/.zshrc file:
#         mv ~/.zshrc ~/.zshrc.bak
#     b.  Place this file at ~/.zshrc:
#         cp /path/to/this/zsh.sh ~/.zshrc
#     c.  Install prerequisite tools:
#         sudo apt update && sudo apt install -y git curl figlet jq net-tools lm-sensors
#     d.  (Optional but Recommended) Install PowerLevel10K:
#         git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/.powerlevel10k
#         echo 'source ~/.powerlevel10k/powerlevel10k.zsh-theme' >>~/.zshrc
#         # On first launch, p10k wizard will run. Configure it to your liking.
#     e.  Open a new terminal to start using the new configuration.

# === 2. CORE FEATURES ===
#
# -   **Performance Optimized**: Lazy loading for plugins and function result caching for near-instant shell startup.
# -   **AI Command Suggestions**: Context-aware command suggestions to accelerate your workflow.
# -   **Interactive Dashboard**: A dynamic, visually rich system information panel that can be refreshed on demand.
# -   **Advanced Security Monitoring**: Built-in file integrity checking and network anomaly detection.
# -   **Visual Flair**: Stunning animations like Matrix rain, particle effects, and gradient text.
# -   **Seamless Integration**: Full support for Git, Docker, Kubernetes, and major cloud providers (AWS, Azure, GCP).
# -   **Robust & Resilient**: Hardened functions with error handling and graceful degradation.

# === 3. USAGE GUIDE ===
#
# -   **System Dashboard**:
#     -   Displayed automatically on new shell startup.
#     -   Refresh manually with `Ctrl+X` then `Ctrl+R`.
#     -   Alias: `sysinfo`
#
# -   **AI Command Suggester**:
#     -   Logs your command history automatically.
#     -   To get suggestions for your current directory, run: `suggest`
#
# -   **Security Tools**:
#     -   Create a baseline for file integrity: `sec-baseline`
#     -   Check for file integrity changes: `sec-check-fs`
#     -   Scan for network anomalies: `sec-check-net`
#
# -   **Visual Effects**:
#     -   Matrix rain: `matrix_rain [duration_in_seconds]`
#     -   Loading animation: `loading_animation [duration_in_seconds]`
#
# -   **Container & Cloud Status**:
#     -   `docker_status`, `kube_status`, `aws_status`, `az_status`, `gcp_status`

# === 4. PERFORMANCE OPTIMIZATIONS ===
#
# -   **Zinit Plugin Manager**: Uses `zinit` for efficient plugin management.
# -   **Lazy Loading**: Most plugins are loaded *after* the first prompt is shown, drastically reducing initial startup time.
# -   **Function Caching**: The output of the expensive `show_system_info` function is cached for 60 seconds to make subsequent new tabs or windows open instantly.

# === 5. TROUBLESHOOTING ===
#
# -   **Slow Startup**: If the shell is still slow, run `zinit times` to see if a specific plugin is causing a bottleneck.
# -   **Display Issues / Garbled Text**: Ensure your terminal supports Unicode and has a Nerd Font installed and configured for PowerLevel10K.
# -   **Command Not Found**: Make sure all prerequisite tools listed in the installation section are installed.
# -   **Resetting the Configuration**: If something goes wrong, you can restore your backup with `mv ~/.zshrc.bak ~/.zshrc`.

# === 6. CONFIGURATION STARTS HERE ===
# Professional Zsh Configuration for Elite Penetration Testers=$(ps aux 2>/dev/null | wc -l || echo "N/A")

#==============================================================================
# === 💀 MASTER CONFIGURATION 💀 ===
# Toggle features on/off here. All changes will be applied on the next shell start.
#==============================================================================

# --- AI Engine ---
enable_ai_engine=true             # Master switch for the AI command translation and suggestion engine.
enable_ai_nlc=true                # Enable the 'ai' command for natural language commands.
enable_ai_smart_suggestions=true  # Enhance the 'suggest' command with workflow prediction.

# --- Situational Awareness HUD ---
enable_hud=true                   # Display the live Heads-Up Display with target and network info.

# --- Operational Context ---
enable_op_context=true            # Enable 'set-target' and 'clear-target' commands.

# --- Live Threat Intelligence ---
enable_threat_intel=true          # Enable the 'fetch-threats' command to get latest CVEs.

# --- Network Settings ---
enable_public_ip_lookup=true      # Allow fetching public IP. Set to false in high-privacy environments.

# --- Visuals & Effects ---
enable_matrix_on_clear=true       # Show the matrix rain effect randomly on 'clear'.
enable_greeting_banner=true        # Show the full graphical banner on startup.

#==============================================================================

# === PERFORMANCE OPTIMIZATION ===
setopt NO_HASH_CMDS
setopt NO_BEEP
setopt INTERACTIVE_COMMENTS
setopt PROMPT_SUBST                   # Enable prompt substitution
# setopt ZLE_RPROMPT_INDENT=0          # (Correction) This is not a valid zsh option and causes an error.
setopt TRANSIENT_RPROMPT             # Clean right prompt on enter
setopt COMBINING_CHARS               # Unicode support
setopt MULTIBYTE
autoload -U zmv
zmodload zsh/zpty 2>/dev/null
zmodload zsh/system 2>/dev/null
zmodload zsh/datetime 2>/dev/null
zmodload zsh/mathfunc 2>/dev/null
zmodload zsh/stat 2>/dev/null
zmodload zsh/files 2>/dev/null
zmodload zsh/pcre 2>/dev/null        # Advanced regex support
zmodload zsh/net/tcp 2>/dev/null     # Network operations
zmodload zsh/sched 2>/dev/null       # Scheduling support
zmodload zsh/termcap 2>/dev/null     # Terminal capabilities
zmodload zsh/terminfo 2>/dev/null    # Terminal info
zmodload zsh/mapfile 2>/dev/null     # File mapping


# === POWERLEVEL10K INSTANT PROMPT (CRITICAL - MUST BE FIRST!) ===
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# === ENVIRONMENT VARIABLES ===
export EDITOR="nvim"
export VISUAL="nvim"
export PAGER="less"
export BROWSER="firefox"
export MANPAGER="sh -c 'col -bx | bat -l man -p'"
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
export TERM="xterm-256color"
export COLORTERM="truecolor"
export LANG="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"

# XDG Base Directory Specification
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_STATE_HOME="$HOME/.local/state"

# History configuration
export HISTFILE="$XDG_STATE_HOME/zsh/history"
export HISTSIZE=100000
export SAVEHIST=100000
export LESSHISTFILE="-"

# Terminal session tracking
export TERMINAL_SESSION_FILE="$XDG_STATE_HOME/zsh/session_tracker"

# === ZSH OPTIONS ===
# History
setopt EXTENDED_HISTORY
setopt SHARE_HISTORY
setopt HIST_EXPIRE_DUPS_FIRST
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_ALL_DUPS
setopt HIST_FIND_NO_DUPS
setopt HIST_IGNORE_SPACE
setopt HIST_SAVE_NO_DUPS
setopt HIST_REDUCE_BLANKS
setopt HIST_VERIFY
setopt HIST_BEEP

# Directory navigation
setopt AUTO_CD
setopt AUTO_PUSHD
setopt PUSHD_IGNORE_DUPS
setopt PUSHD_MINUS
setopt PUSHD_SILENT

# Completion
setopt COMPLETE_IN_WORD
setopt ALWAYS_TO_END
setopt PATH_DIRS
setopt AUTO_MENU
setopt AUTO_LIST
setopt AUTO_PARAM_SLASH
setopt COMPLETE_ALIASES
setopt GLOB_COMPLETE
setopt HASH_LIST_ALL
setopt MENU_COMPLETE

# Correction
setopt CORRECT
setopt CORRECT_ALL

# Globbing
setopt EXTENDED_GLOB
setopt NULL_GLOB
setopt NUMERIC_GLOB_SORT
setopt GLOB_DOTS

# Job control
setopt LONG_LIST_JOBS
setopt AUTO_RESUME
setopt NOTIFY
setopt CHECK_JOBS
setopt HUP

# Input/Output
setopt ALIASES
setopt CLOBBER
setopt PRINT_EXIT_VALUE

# === ZINIT PLUGIN MANAGER ===
ZINIT_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}/zinit/zinit.git"

# Create zinit directory if it doesn't exist
if [[ ! -d "$ZINIT_HOME" ]]; then
  mkdir -p "$(dirname $ZINIT_HOME)"
  git clone https://github.com/zdharma-continuum/zinit.git "$ZINIT_HOME"
fi

# Load zinit
source "${ZINIT_HOME}/zinit.zsh"

# Load Powerlevel10k theme FIRST for instant prompt to work.
# NOTE: Do not use 'ice' modifiers here, as they conflict with instant prompt.
zinit light romkatv/powerlevel10k

# === LAZY-LOADED PLUGINS ===
# Performance: Plugins are loaded on-demand after the first command is executed.
_zsh_lazy_load_plugins() {
  # Unhook this function to run only once.
  precmd_functions=(${precmd_functions#_zsh_lazy_load_plugins});

  # Load essential plugins with Turbo mode for speed
  zinit ice lucid wait'0' \
    atload'zstyle '':completion:*'' use-cache on; zstyle '':completion:*'' cache-path "$ZSH_COMPCACHE_DIR";' \
    atinit'zicompinit; zicdreplay';
  zinit light zsh-users/zsh-completions

  zinit ice lucid wait'0'; zinit light zsh-users/zsh-syntax-highlighting
  zinit ice lucid wait'0'; zinit light zsh-users/zsh-autosuggestions
  zinit ice lucid wait'0'; zinit light zsh-users/zsh-history-substring-search

  # Load productivity plugins
  zinit ice lucid wait'0'; zinit light Aloxaf/fzf-tab
  zinit ice lucid wait'0'; zinit light MichaelAquilina/zsh-auto-notify
  zinit ice lucid wait'0'; zinit light MichaelAquilina/zsh-you-should-use

  # Re-initialize completion system after loading plugins
  compinit -C -d "${XDG_CACHE_HOME:-$HOME/.cache}/zsh/zcompdump-${ZSH_VERSION}"
}

# Hook the lazy load function to run before the first prompt
precmd_functions+=(_zsh_lazy_load_plugins)

# === COMPLETION SYSTEM ===
autoload -Uz compinit
zcompdump_path="${XDG_CACHE_HOME:-$HOME/.cache}/zsh/zcompdump-${ZSH_VERSION}"
mkdir -p "$(dirname "$zcompdump_path")"

# Rebuild completion cache once per day
if [[ -n ${zcompdump_path}(#qN.mh+24) ]]; then
  compinit -d "${zcompdump_path}"
else
  compinit -C -d "${zcompdump_path}"
fi

# Completion configuration
zstyle ':completion:*' completer _expand _complete _ignored _approximate
zstyle ':completion:*' expand prefix suffix
zstyle ':completion:*' file-sort name
zstyle ':completion:*' list-suffixes true
zstyle ':completion:*' matcher-list '' 'm:{[:lower:][:upper:]}={[:upper:][:lower:]}' 'r:|[._-]=* r:|=*' 'l:|=* r:|=*'
zstyle ':completion:*' menu select=long
zstyle ':completion:*' select-prompt '%SScrolling active: current selection at %p%s'
zstyle ':completion:*' use-compctl false
zstyle ':completion:*' verbose true
zstyle ':completion:*' squeeze-slashes true
zstyle ':completion:*' list-colors ${(s.:.)LS_COLORS}
zstyle ':completion:*' group-name ''
zstyle ':completion:*' format '%F{yellow}%d%f'
zstyle ':completion:*' special-dirs true
zstyle ':completion:*' accept-exact '*(N)'
zstyle ':completion:*' use-cache on
zstyle ':completion:*' cache-path "$XDG_CACHE_HOME/zsh/completion"

# Kill completion
zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#)*=0=01;31'
zstyle ':completion:*:kill:*' command 'ps -u $USER -o pid,%cpu,tty,cputime,cmd'

# SSH/SCP hostname completion
zstyle ':completion:*:(ssh|scp|sftp):*' hosts $hosts
zstyle ':completion:*:(ssh|scp|sftp):*' users $users

# === ANIMATION FUNCTIONS ===
typeset -ga CYBER_COLORS=(
  "38;2;0;255;255"      # Quantum Cyan
  "38;2;255;0;255"      # Neural Magenta
  "38;2;0;255;127"      # Matrix Green
  "38;2;255;255;0"      # Plasma Yellow
  "38;2;255;0;127"      # Cyber Pink
  "38;2;127;0;255"      # Void Purple
  "38;2;0;191;255"      # Electric Blue
  "38;2;255;127;0"      # Neon Orange
  "38;2;191;255;0"      # Laser Lime
  "38;2;255;191;0"      # Solar Gold
  "38;2;0;255;191"      # Holographic Teal
  "38;2;255;63;191"     # Alien Pink
  "38;2;127;255;127"    # Neon Green
  "38;2;255;127;255"    # Electric Pink
  "38;2;127;255;255"    # Cyber Blue
  "38;2;255;255;127"    # Plasma Green
  "38;2;255;0;0"        # Alert Red
  "38;2;0;255;0"        # System Green
  "38;2;255;165;0"      # Warning Orange
  "38;2;138;43;226"     # Deep Purple
)

# Pre-computed gradient colors for text effects
typeset -ga GRADIENT_COLORS=(
  "38;2;255;0;128"
  "38;2;255;64;192"
  "38;2;255;128;255"
  "38;2;128;255;255"
  "38;2;0;255;128"
  "38;2;128;255;0"
  "38;2;255;255;0"
  "38;2;255;128;0"
)
# === ANIMATION FUNCTIONS ===

threat_color() {
  local level=${1:-3}
  case $level in
    0) echo "38;2;255;0;0"     ;; # CRITICAL - Red
    1) echo "38;2;255;165;0"   ;; # HIGH - Orange
    2) echo "38;2;255;255;0"   ;; # MEDIUM - Yellow
    3) echo "38;2;0;255;0"     ;; # LOW - Green
    4) echo "38;2;0;191;255"   ;; # INFO - Blue
    *) echo "38;2;255;255;255" ;; # DEFAULT - White
  esac
}

random_color() {
  if [[ ${#CYBER_COLORS[@]} -eq 0 ]]; then
    echo "38;2;255;255;255"  # Fallback white
    return
  fi
  local cached_color="${CYBER_COLORS[$((RANDOM % ${#CYBER_COLORS[@]}))]}"
  echo "$cached_color"
}

# Advanced gradient text with RGB transitions
gradient_text() {
  local text="$1"
  local output=""
  local len=${#text}

  # Critical Fix: Handle empty or single-character strings to prevent division by zero.
  if [[ $len -le 1 ]]; then
    local color=$(random_color)
    echo -e "\033[${color}m${text}\033[0m"
    return
  fi

  for ((i=0; i<len; i++)); do
    local char="${text:$i:1}"
    # Robust calculation for RGB values with division-by-zero protection.
    local r=$((255 - (i * 255 / (len - 1))))
    local g=$((i * 255 / (len - 1)))
    local b=$((127 + (i * 128 / (len - 1))))

    # Clamp values to ensure they are within the valid 0-255 range.
    r=$(( r < 0 ? 0 : (r > 255 ? 255 : r) ))
    g=$(( g < 0 ? 0 : (g > 255 ? 255 : g) ))
    b=$(( b < 0 ? 0 : (b > 255 ? 255 : b) ))

    output+="\033[38;2;${r};${g};${b}m${char}\033[0m"
  done
  echo -e "$output"
}

# matrix rain with customizable intensity
matrix_rain() {
    local duration=${1:-5}
    local density=${2:-30}
    local width=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
    local height=${LINES:-$(tput lines 2>/dev/null || echo 24)}

    # Validate terminal capabilities and dimensions
    if ! command -v tput &>/dev/null; then
        echo "Terminal not supported for matrix effect"
        return 1
    fi

    # Ensure positive dimensions
    width=$((width > 0 ? width : 80))
    height=$((height > 0 ? height : 24))

    # Enhanced character set with more authentic Matrix look
    local chars="ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?"
    local num_chars=${#chars}

    # Enhanced color palette with better gradient
    local colors=(
        "38;2;0;255;0"      # Bright green (leading)
        "38;2;0;220;0"      # Medium bright green
        "38;2;0;180;0"      # Medium green
        "38;2;0;140;0"      # Darker green
        "38;2;0;100;0"      # Dark green
        "38;2;0;60;0"       # Very dark green
        "38;2;0;30;0"       # Fading green
    )
    local num_colors=${#colors[@]}

    # Initialize column arrays with FIXED bounds checking
    declare -a columns lengths speeds last_chars

    for ((i=0; i<width; i++)); do
        # FIX: Ensure only positive values for array indices and positions
        columns[$i]=$((RANDOM % height))  # Keep positive, start at top
        lengths[$i]=$((RANDOM % (height / 3) + 8))
        speeds[$i]=$((RANDOM % 4 + 1))
        last_chars[$i]=$((RANDOM % num_chars))

        # Optional: Start some columns off-screen (negative y-position, but positive array index)
        if [[ $((RANDOM % 3)) -eq 0 ]]; then
            columns[$i]=$(( -(RANDOM % 10) ))  # Start off-screen above
        fi
    done

    # Terminal setup
    tput civis 2>/dev/null    # Hide cursor
    printf "\033[2J\033[H"    # Clear screen and home cursor

    local end_time=$(($(date +%s) + duration))
    local frame_count=0

    while [[ $(date +%s) -lt $end_time ]]; do
        local frame_buffer=""
        ((frame_count++))

        # Clear previous frame positions that might have artifacts
        if [[ $frame_count -gt 1 ]]; then
            frame_buffer+="\033[2J"
        fi

        for ((i=0; i<width; i++)); do
            # Only process columns that are active or about to be active
            if [[ $((columns[i] - lengths[i])) -lt height ]]; then

                # Draw trailing characters with proper color gradient
                for ((j=0; j<lengths[i]; j++)); do
                    local y_pos=$((columns[i] - j))
                    if [[ y_pos -ge 0 && y_pos -lt height ]]; then
                        # Calculate color index based on position in trail
                        local color_index=$(( (j * (num_colors - 1)) / lengths[i] ))
                        color_index=$((color_index >= num_colors ? num_colors - 1 : color_index))

                        # Use different character for each position
                        local char_index=$(( (y_pos + i + frame_count) % num_chars ))

                        frame_buffer+="\033[$((y_pos + 1));$((i + 1))H\033[${colors[$color_index]}m${chars:$char_index:1}"
                    fi
                done

                # Draw bright leading character
                if [[ columns[i] -ge 0 && columns[i] -lt height ]]; then
                    local lead_char=$(( (columns[i] + i + frame_count) % num_chars ))
                    frame_buffer+="\033[$((columns[i] + 1));$((i + 1))H\033[1;${colors[0]}m${chars:$lead_char:1}"
                fi

                # Update column position
                columns[$i]=$((columns[i] + speeds[i]))

                # Reset column when it's completely off screen
                if [[ $((columns[i] - lengths[i])) -ge height ]]; then
                    columns[$i]=$(( -(RANDOM % 20) ))  # Start off-screen above
                    lengths[$i]=$((RANDOM % (height / 3) + 8))
                    speeds[$i]=$((RANDOM % 4 + 1))
                fi
            fi
        done

        # Output frame buffer efficiently
        printf "%b" "$frame_buffer\033[0m"
        sleep 0.04  # Slightly faster for smoother animation
    done

    # Cleanup
    tput cnorm 2>/dev/null    # Show cursor
    printf "\033[2J\033[H"    # Clear screen
}

# Additional debugging function
debug_matrix_rain() {
    local width=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
    local height=${LINES:-$(tput lines 2>/dev/null || echo 24)}

    echo "Terminal dimensions: ${width}x${height}"
    echo "COLUMNS: $COLUMNS"
    echo "LINES: $LINES"
    echo "tput cols: $(tput cols 2>/dev/null || echo 'failed')"
    echo "tput lines: $(tput lines 2>/dev/null || echo 'failed')"

    # Test array assignment
    declare -a test_array
    for ((i=0; i<5; i++)); do
        test_array[$i]=$i
        echo "test_array[$i] = ${test_array[$i]}"
    done
}

# Additional utility function for better matrix control
matrix_screensaver() {
    local duration=${1:-30}
    echo -e "\033[38;2;0;255;0m🔋 Matrix screensaver activated for ${duration}s...\033[0m"
    matrix_rain $duration
    echo -e "\033[38;2;0;255;0m✅ Matrix screensaver deactivated\033[0m"
}

# Advanced loading animation with cyber effects
loading_animation() {
  local message="${1:-Initializing Shadow Terminal}"
  local duration=${2:-1.5}
  local callback_function="${3:-}"
  local style="${4:-matrix}"

  local width=40
  local steps=50

  # Calculate step duration without bc dependency
  local step_duration_ms=$((${duration%.*} * 1000 / steps))
  [[ $step_duration_ms -lt 10 ]] && step_duration_ms=10
  local step_duration="0.$(printf "%03d" $step_duration_ms)"

  case "$style" in
    "matrix") local chars="ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ01" ;;
    "wave") local chars="~≈∿∽∾∿≈~" ;;
    "pulse") local chars="●◐◑◒◓◔◕◖◗◘◙◚◛●" ;;
    "scan") local chars="▁▂▃▄▅▆▇█▇▆▅▄▃▂▁" ;;
    *) local chars="━━━━━━━━━━━━━━━━━━━━" ;;
  esac

  echo -e "\033[$(random_color)m$message\033[0m"

  for ((i=0; i<=steps; i++)); do
    local progress=$((i * 100 / steps))
    local filled=$((i * width / steps))
    local empty=$((width - filled))

    # Safe color selection
    local color_index=$((i % ${#CYBER_COLORS[@]}))
    local color="${CYBER_COLORS[$color_index]}"

    printf "\r\033[${color}m["

    # Fill with animated characters
    for ((j=0; j<filled; j++)); do
      local char_index=$((j % ${#chars}))
      printf "${chars:$char_index:1}"
    done

    # Empty space
    for ((j=0; j<empty; j++)); do
      printf "░"
    done

    printf "] %d%% \033[0m" $progress

    # Safe callback execution
    if [[ -n "$callback_function" ]] && declare -f "$callback_function" >/dev/null 2>&1; then
      "$callback_function" "$progress" 2>/dev/null
    fi

    sleep "$step_duration"
  done

  printf "\r\033[K"
  echo
}

# Efficiently calculates CPU usage from /proc/stat to avoid expensive 'top' calls.
_zsh_get_cpu_usage() {
  local stat_file="$XDG_CACHE_HOME/zsh/cpu_last_stat"
  local last_stat=()
  if [[ -f "$stat_file" ]]; then
    last_stat=($(<"$stat_file"))
  else
    last_stat=(0 0)
  fi

  local current_stat=($(awk '/^cpu / {print $2+$3+$4+$6+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat))
  echo "${current_stat[@]}" > "$stat_file"

  local delta_total=$((current_stat[1] - last_stat[1]))
  local delta_busy=$((current_stat[0] - last_stat[0]))

  if [[ $delta_total -gt 0 ]]; then
    printf "%.1f" $(echo "$delta_busy $delta_total" | awk '{print 100 * $1 / $2}')
  else
    echo "0.0"
  fi
}

# Real-time system monitor with live updates
live_system_monitor() {
  # Ensure the PID file is handled securely
  local pid_file="$TERMINAL_SESSION_FILE.monitor.pid"
  if ! echo $$ > "$pid_file"; then
    echo "Error: Could not write to PID file '$pid_file'. Aborting monitor." >&2
    return 1
  fi

  # Critical Fix: Use safe_system_call for all external commands and add error handling.
  local cpu_usage=$(_zsh_get_cpu_usage)
  local mem_info=$(safe_system_call free -b | awk 'NR==2{printf "%.2f%%", $3*100/$2}')
  local disk_usage=$(safe_system_call df -h / | awk 'NR==2{print $5}')

  # Critical Fix: Check for /proc/net/dev existence before reading.
  local net_rx="N/A"
  local net_tx="N/A"
  if [[ -r /proc/net/dev ]]; then
    local net_stats=$(cat /proc/net/dev | awk 'NR>2 {if(sub(":","",$1)) {rx+=$2; tx+=$10}} END {print rx, tx}')
    net_rx=$(format_bytes $(echo $net_stats | cut -d' ' -f1))
    net_tx=$(format_bytes $(echo $net_stats | cut -d' ' -f2))
  fi

  local threat_level=$((RANDOM % 5))
  local threat_color=$(threat_color $threat_level)

  # Construct the output string, handling potentially empty values.
  local output=""
  output+="CPU: ${cpu_usage:-\-N/A-\-}% | "
  output+="MEM: ${mem_info:-\-N/A-\-}% | "
  output+="DISK: ${disk_usage:-\-N/A-\-}% | "
  output+="NET: ↓${net_rx} / ↑${net_tx} | "
  output+="THREAT: \033[$threat_color;1m$(printf '%-8s' $(threat_level_to_text $threat_level))\033[0m"

  echo "$output"
}

live_monitor_daemon_loop() {
  # This loop runs in the background to periodically update system stats
  while true; do
    # Run the monitor and print output, which will be redirected to the cache file.
    live_system_monitor
    # Sleep for the specified interval
    sleep "$ZSH_SYSTEM_STATS_INTERVAL"
  done
}

# Start live monitoring
start_live_monitoring() {
  # Start the background process, ensuring its output goes to the cache, not the terminal.
  {
    # Detach from the controlling terminal
    if [[ -o MONITOR ]]; then set +o MONITOR; fi
    ( (live_monitor_daemon_loop > "$_ZSH_SYSTEM_STATS_CACHE") &) >> "$_ZSH_LOG_FILE" 2>&1
  } & disown
}

# Stop live monitoring
stop_live_monitoring() {
  LIVE_MONITOR_ACTIVE=false
  if [[ -n "$LIVE_MONITOR_PID" ]]; then
    kill "$LIVE_MONITOR_PID" 2>/dev/null
    LIVE_MONITOR_PID=""
  fi
}


# === CACHING SYSTEM ===
# Performance: Cache expensive function calls to improve responsiveness.
_zsh_cache_file="$XDG_CACHE_HOME/zsh/zsh_cache.json"
_zsh_cache_ttl=60 # Cache time-to-live in seconds

# Function to get a value from the cache
get_cached() {
  local key="$1"
  # Check if jq is available and the cache file exists
  if command -v jq >/dev/null 2>&1 && [[ -f "$_zsh_cache_file" ]]; then
    local expiry=$(jq -r ".${key}.expiry" "$_zsh_cache_file" 2>/dev/null)
    local now=$(date +%s)
    # Check if the cache is still valid
    if [[ -n "$expiry" && "$now" -lt "$expiry" ]]; then
      jq -r ".${key}.value" "$_zsh_cache_file"
      return 0
    fi
  fi
  return 1
}

# Function to set a value in the cache
set_cached() {
  local key="$1"
  local value="$2"
  local expiry=$(($(date +%s) + _zsh_cache_ttl))
  # (Correction) Create temp file in the same directory as the cache to prevent cross-device link errors.
  local cache_dir=$(dirname "$_zsh_cache_file")
  local temp_file=$(mktemp "$cache_dir/zsh_cache.XXXXXX")

  # Ensure the cache directory exists
  mkdir -p "$(dirname "$_zsh_cache_file")"

  # Create or update the cache file using jq for safe JSON manipulation
  # CRITICAL FIX: Use --argjson to safely handle values with special characters (e.g., quotes, newlines)
  if [[ -f "$_zsh_cache_file" ]]; then
    jq --arg key "$key" --argjson value "$(echo "$value" | jq -R -s .)" --argjson expiry "$expiry" \
      '.[$key] = {value: $value, expiry: $expiry}' "$_zsh_cache_file" > "$temp_file" && mv "$temp_file" "$_zsh_cache_file"
  else
    jq --arg key "$key" --argjson value "$(echo "$value" | jq -R -s .)" --argjson expiry "$expiry" \
      '.[$key] = {value: $value, expiry: $expiry}' <(echo '{}') > "$_zsh_cache_file"
  fi
}

# system info with real-time elements
show_system_info() {
  # Performance: Try to load system info from cache first.
  local cached_info=$(get_cached "system_info")
  if [[ -n "$cached_info" ]]; then
    echo -e "$cached_info"
    return
  fi

  local output_buffer=""
  local primary_color="38;2;255;0;255"
  local secondary_color="38;2;0;255;255"
  local accent_color="38;2;255;255;0"
  local success_color="38;2;0;255;0"
  local warning_color="38;2;255;165;0"
  local danger_color="38;2;255;0;0"

  # Animated banner with figlet
  output_buffer+="\033[${primary_color}m"
  if command -v figlet &>/dev/null; then
    local banner_text="Shadow@Bhanu"
    output_buffer+=$(echo "$banner_text" | figlet -f slant 2>/dev/null)
  else
    output_buffer+=$(gradient_text "🚀 Shadow@Bhanu Elite Terminal 🚀")
  fi
  output_buffer+="\033[0m\n"

  # Main info panel
  output_buffer+="\033[${secondary_color}m╔═══════════════════════════════════════════════════════════════════════════════╗\033[0m\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m🧠 ⟨ 💀 This ain't a shell 😒😏 it's a weaponized AI brain 🤖😈 ⟩ 🧠\033[0m \033[${secondary_color}m║\033[0m\n"
  output_buffer+="\033[${secondary_color}m╠═══════════════════════════════════════════════════════════════════════════════╣\033[0m\n"

  # System identification
  local hostname=$(hostname 2>/dev/null || echo "UNKNOWN")
  local kernel=$(uname -r 2>/dev/null || echo "UNKNOWN")
  local os_info=$(lsb_release -d 2>/dev/null | cut -f2 || uname -o 2>/dev/null || echo "UNKNOWN")
  local arch=$(uname -m 2>/dev/null || echo "UNKNOWN")

  output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🌐 HOST:\033[0m $hostname \033[${accent_color}m⚡ KERNEL:\033[0m $kernel \033[${success_color}m🏗️  ARCH:\033[0m $arch\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🖥️  OS:\033[0m $os_info\n"

  # Real-time metrics
  local uptime_info=$(uptime -p 2>/dev/null | sed 's/up //' || echo "UNKNOWN")
  local load_avg=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | sed 's/^ *//' || echo "N/A")
  local current_time=$(date '+%H:%M:%S %Z' 2>/dev/null)
  local current_date=$(date '+%Y-%m-%d %A' 2>/dev/null)

  output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m⏱️  UPTIME:\033[0m $uptime_info \033[${warning_color}m📊 LOAD:\033[0m $load_avg\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m🕐 TIME:\033[0m $current_time \033[${primary_color}m📅 DATE:\033[0m $current_date\n"

  # memory visualization
  if command -v free &>/dev/null; then
    local memory_total=$(free -m | awk 'NR==2{print $2}')
    local memory_used=$(free -m | awk 'NR==2{print $3}')
    local memory_percent=$(free -m | awk 'NR==2{printf "%.0f", $3*100/$2}')
    local memory_bar=""
    for ((i=0; i<30; i++)); do
      if [[ $i -lt $((memory_percent*30/100)) ]]; then
        if [[ $memory_percent -gt 80 ]]; then memory_bar+="\033[${danger_color}m█\033[0m"; else
        if [[ $memory_percent -gt 60 ]]; then memory_bar+="\033[${warning_color}m█\033[0m"; else
        memory_bar+="\033[${success_color}m█\033[0m"; fi; fi
      else memory_bar+="\033[38;2;64;64;64m░\033[0m"; fi
    done
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🧠 MEMORY:\033[0m ${memory_used}MB/${memory_total}MB (${memory_percent}%) $memory_bar\n"
  fi

  # storage with I/O stats
  if command -v df &>/dev/null; then
    local disk_used=$(df -h / 2>/dev/null | awk 'NR==2{print $3}' || echo "N/A")
    local disk_total=$(df -h / 2>/dev/null | awk 'NR==2{print $2}' || echo "N/A")
    local disk_percent=$(df / 2>/dev/null | awk 'NR==2{print $5}' | sed 's/%//' || echo "0")
    local disk_bar=""
    for ((i=0; i<30; i++)); do
      if [[ $i -lt $((disk_percent*30/100)) ]]; then
        if [[ $disk_percent -gt 85 ]]; then disk_bar+="\033[${danger_color}m█\033[0m"; else
        if [[ $disk_percent -gt 70 ]]; then disk_bar+="\033[${warning_color}m█\033[0m"; else
        disk_bar+="\033[${success_color}m█\033[0m"; fi; fi
      else disk_bar+="\033[38;2;64;64;64m░\033[0m"; fi
    done
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m💾 STORAGE:\033[0m $disk_used/$disk_total (${disk_percent}%) $disk_bar\n"
  fi

  # Network information
  if command -v ip &>/dev/null; then
    local ip_addr=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || echo "N/A")
    local interface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "N/A")
    local public_ip_line=""
    if [[ "$enable_public_ip_lookup" == "true" ]]; then
        local public_ip=$(timeout 2 curl -s https://ipinfo.io/ip 2>/dev/null || echo "LOOKUP FAILED")
        public_ip_line=" \033[${primary_color}m🌐 PUBLIC:\033[0m $public_ip"
    fi
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m🌍 LOCAL:\033[0m $ip_addr \033[${warning_color}m📡 INTERFACE:\033[0m $interface$public_ip_line\n"
  fi

  # CPU information
  if command -v lscpu &>/dev/null; then
    local cpu_info=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | sed 's/^ *//' | cut -c1-50 || echo "N/A")
    local cpu_cores=$(nproc 2>/dev/null || echo "N/A")
    local cpu_usage=$(_zsh_get_cpu_usage)
    local cpu_temp=""
    if command -v sensors &>/dev/null; then
      cpu_temp=$(sensors 2>/dev/null | grep -i 'core 0' | awk '{print $3}' | head -1 2>/dev/null || echo "")
      [[ -n "$cpu_temp" ]] && cpu_temp=" 🌡️$cpu_temp"
    fi
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m⚙️  CPU:\033[0m $cpu_info (${cpu_cores} cores) ${cpu_usage}%$cpu_temp\n"
  fi

  # Process and user information
  local processes=$(ps aux 2>/dev/null | wc -l || echo "N/A")
  local users=$(who 2>/dev/null | wc -l || echo "N/A")
  local zombie_processes=$(ps aux | awk '$8 ~ /^Z/ { count++ } END { print count+0 }' 2>/dev/null || echo "0")
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m⚡ PROCESSES:\033[0m $processes \033[${primary_color}m👥 USERS:\033[0m $users \033[${danger_color}m🧟 ZOMBIES:\033[0m $zombie_processes\n"

  # Security status
  local failed_logins=$(lastb 2>/dev/null | wc -l || echo "0")
  local active_sessions=$(w -h 2>/dev/null | wc -l || echo "0")
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${danger_color}m🔒 FAILED_LOGINS:\033[0m $failed_logins \033[${warning_color}m📺 ACTIVE_SESSIONS:\033[0m $active_sessions\n"

  # File Integrity Status
  if [[ -f "$INTEGRITY_BASELINE_FILE" ]]; then
    if sha256sum -c --quiet "$INTEGRITY_BASELINE_FILE" &>/dev/null; then
        local integrity_status="\033[${success_color}m✅ INTACT\033[0m"
    else
        local integrity_status="\033[${danger_color}m🚨 BREACHED\033[0m"
    fi
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${warning_color}m🛡️  FILE INTEGRITY:\033[0m $integrity_status\n"
  fi

  output_buffer+="\033[${secondary_color}m╚═══════════════════════════════════════════════════════════════════════════════╝\033[0m\n"

  set_cached "system_info" "$output_buffer"
  echo -e "$output_buffer"
}

# === GREETING SYSTEM ===

threat_level_to_text() {
  case $1 in
    0) echo "CRITICAL" ;;
    1) echo "HIGH" ;;
    2) echo "MEDIUM" ;;
    3) echo "LOW" ;;
    4) echo "INFO" ;;
    *) echo "UNKNOWN" ;;
  esac
}

time_based_greeting() {
  local hour=$(date +"%H")
  local day=$(date +"%A")
  local greeting
  local options=()
  local color=$(random_color)

  # Threat level based on time (simulate red team awareness)
  local threat_level=3  # Default safe
  if [[ $hour -ge 0 && $hour -lt 6 ]]; then
    threat_level=1  # High alert during night
  elif [[ $hour -ge 6 && $hour -lt 9 ]]; then
    threat_level=2  # Medium alert morning
  elif [[ $hour -ge 18 && $hour -lt 24 ]]; then
    threat_level=2  # Medium alert evening
  fi

  # Context-aware greetings
  if [[ $hour -ge 5 && $hour -lt 12 ]]; then
    options=(
      "🌅 Morning, Shadow 😈 — AI swarm online, targets acquired 🎯"
      "🔥 Rise and dominate, Shadow 😈 — neural networks activated 🧠"
      "🌄 Dawn protocol initiated, Shadow 😈 — red team standing by 🚨"
      "☀️ Morning breach, Shadow 😈 — all systems green 🟢"
      "🛠️ Operations online, Shadow 😈 — ready to penetrate 💀"
    )
  elif [[ $hour -ge 12 && $hour -lt 17 ]]; then
    options=(
      "🌞 Afternoon ops, Shadow 😈 — targets in crosshairs 🎯"
      "💣 Midday strike, Shadow 😈 — cyber weapons hot 🔥"
      "⚙️ Systems peaked, Shadow 😈 — maximum efficiency 📊"
      "🔓 Vulnerabilities exposed, Shadow 😈 — exploit ready 💥"
      "💀 Afternoon hunt, Shadow 😈 — stealth mode engaged 👻"
    )
  elif [[ $hour -ge 17 && $hour -lt 21 ]]; then
    options=(
      "🌆 Evening infiltration, Shadow 😈 — darkness approaching 🌙"
      "⚡ Dusk operations, Shadow 😈 — time to strike 🗡️"
      "🌇 Shadow protocol, Shadow 😈 — moving unseen 👻"
      "🚨 Night ops prep, Shadow 😈 — going dark 🕶️"
      "🌌 Stealth mode, Shadow 😈 — hunt begins 🔍"
    )
  else
    options=(
      "🌙 Midnight ops, Shadow 😈 — silent running 🤫"
      "🌃 Night hunter, Shadow 😈 — invisible strike 👻"
      "💣 Zero dark thirty, Shadow 😈 — full stealth 🕶️"
      "🛡️ Insomniac ops, Shadow 😈 — always watching 👁️"
      "🕛 Late night breach, Shadow 😈 — systems never sleep 💀"
    )
  fi

  greeting="${options[$(( (RANDOM % ${#options[@]}) + 1 ))]}"

  # Display with threat level coloring
  local threat_color_code=$(threat_color $threat_level)
  echo -e "\033[${threat_color_code}m$greeting\033[0m"

  # Show threat level indicator
  local threat_text=""
  case $threat_level in
    0) threat_text="🔴 CRITICAL" ;;
    1) threat_text="🟠 HIGH" ;;
    2) threat_text="🟡 MEDIUM" ;;
    3) threat_text="🟢 LOW" ;;
    4) threat_text="🔵 INFO" ;;
  esac

  echo -e "\033[$(random_color)m🎯 Threat Level: $threat_text | AI Red Team Status: ACTIVE 🚨\033[0m"

  # Show current operation context
  local current_dir=$(basename "$PWD")
  local context_color=$(random_color)
  echo -e "\033[${context_color}m📍 Current AO: $current_dir | Ready for engagement 💀\033[0m"
  echo
}



# format_bytes() ===
format_bytes() {
  local bytes=${1:-0}
  local units=("B" "KB" "MB" "GB" "TB")
  local unit_index=0
  local size=$bytes

  # Convert to appropriate unit
  while [[ $size -gt 1024 && $unit_index -lt 4 ]]; do
    size=$((size / 1024))
    unit_index=$((unit_index + 1))
  done

  echo "${size}${units[$unit_index]}"
}

# Command existence checker ===
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Safe system command execution ===
safe_system_call() {
  local cmd="$1"
  local timeout_duration=${2:-5}
  local fallback_value="${3:-N/A}"

  if command_exists timeout; then
    timeout "$timeout_duration" $cmd 2>/dev/null || echo "$fallback_value"
  else
    $cmd 2>/dev/null || echo "$fallback_value"
  fi
}

# === CORRECTED: Process cleanup handler ===
cleanup_processes() {
  local pid_file="$TERMINAL_SESSION_FILE.monitor.pid"
  if [[ -f "$pid_file" ]]; then
    local pid=$(cat "$pid_file" 2>/dev/null)
    # Critical Fix: Check if PID exists and is a running process before killing.
    if [[ -n "$pid" && "$pid" -gt 1 ]] && ps -p $pid > /dev/null 2>&1; then
      # Kill the entire process group gracefully first, then forcefully if needed.
      kill -TERM -- -$pid 2>/dev/null
      sleep 0.1
      kill -KILL -- -$pid 2>/dev/null
    fi
    # Securely remove the pid file.
    rm -f "$pid_file"
  fi

  # Clean up any other background jobs
  jobs -p | xargs -r kill -9 2>/dev/null

  # Reset terminal state
  tput cnorm 2>/dev/null
  echo -e "\033[0m"
}

# Terminal capability detection ===
detect_terminal_capabilities() {
  # Check if terminal supports colors
  if [[ -t 1 ]] && command_exists tput; then
    local colors=$(tput colors 2>/dev/null)
    [[ $colors -ge 256 ]] && return 0
  fi
  return 1
}

# === Add trap for cleanup ===
trap cleanup_processes EXIT INT TERM

# === CORRECTED: Fix gradient color array bounds ===
# Update the GRADIENT_COLORS usage throughout
safe_gradient_color() {
  local index=${1:-0}
  if [[ $index -lt ${#GRADIENT_COLORS[@]} ]]; then
    echo "${GRADIENT_COLORS[$index]}"
  else
    echo "${GRADIENT_COLORS[0]}"  # Fallback to first color
  fi
}

# clear function with progressive loading
clear() {
    # Store original clear behavior
    command clear

    # Matrix effect with controlled probability (25% chance)
    if [[ $((RANDOM % 4)) -eq 0 ]]; then
        matrix_rain 1  # Slightly longer for better effect
    fi

    # Progressive loading animation
    loading_animation "🔄 Reinitializing Shadow Systems..." 1.2

    # Clear screen again after loading to ensure clean display
    command clear

    # Always show system info after clear
    show_system_info
    time_based_greeting

    # Show separator line if welcome was previously displayed
    if [[ -n "$WELCOME_DISPLAYED" ]]; then
        echo -e "\033[38;2;255;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    fi

    # Optional: Show current directory and git status if in git repo
    if command -v git &>/dev/null && git rev-parse --is-inside-work-tree &>/dev/null; then
        echo -e "\033[38;2;100;255;100m📁 $(pwd) \033[38;2;255;255;100m($(git branch --show-current 2>/dev/null || echo 'detached'))\033[0m"
    else
        echo -e "\033[38;2;100;255;100m📁 $(pwd)\033[0m"
    fi
}



# New live dashboard function
live_dashboard() {
  echo -e "\033[38;2;255;0;255m🚀 Starting Shadow@Bhanu Live Dashboard...\033[0m"
  echo -e "\033[38;2;255;255;0m⚡ Press Ctrl+C to exit\033[0m"
  sleep 1
  while true; do
    # Clear the screen and move cursor to home position
    printf "\033[2J\033[H"
    # Print the dashboard header
    echo -e "\033[38;2;255;0;255m🚀 Shadow@Bhanu Live Dashboard (Press Ctrl+C to exit) 🚀\033[0m\n"
    # Display the live system info
    show_system_info
    # Display the live monitor stats
    live_system_monitor
    sleep 2
  done
}


# === KEYBINDINGS ===
bindkey -e
bindkey '^R' history-incremental-search-backward
bindkey '^S' history-incremental-search-forward
bindkey '^[[1;5C' forward-word
bindkey '^[[1;5D' backward-word
bindkey '^H' backward-kill-word
bindkey '^[[3;5~' kill-word
bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line

# === FZF INTEGRATION ===
if command -v fzf &> /dev/null; then
  # Load fzf
  if [[ -f ~/.fzf.zsh ]]; then
    source ~/.fzf.zsh
  elif [[ -f /usr/share/fzf/key-bindings.zsh ]]; then
    source /usr/share/fzf/key-bindings.zsh
    source /usr/share/fzf/completion.zsh
  fi

  # FZF configuration
  export FZF_DEFAULT_COMMAND='fd --type f --hidden --follow --exclude .git 2>/dev/null || find . -type f -not -path "*/\.git/*"'
  export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
  export FZF_ALT_C_COMMAND='fd --type d --hidden --follow --exclude .git 2>/dev/null || find . -type d -not -path "*/\.git/*"'
  export FZF_DEFAULT_OPTS="--height 40% --layout=reverse --border --multi --info=inline --color=bg+:#1e1e1e,bg:#0a0a0a,spinner:#f4a261,hl:#e76f51,fg:#ffffff,header:#e9c46a,info:#264653,pointer:#f4a261,marker:#e76f51,fg+:#ffffff,prompt:#e9c46a,hl+:#e76f51"
  export FZF_CTRL_T_OPTS="--preview 'bat --style=numbers --color=always --line-range :500 {} 2>/dev/null || cat {}' --preview-window=right:60%"
  export FZF_ALT_C_OPTS="--preview 'tree -C {} 2>/dev/null || ls -la {}' --preview-window=right:60%"
fi

# === PLUGIN CONFIGURATIONS ===
# Autosuggestions
ZSH_AUTOSUGGEST_STRATEGY=(history completion)
ZSH_AUTOSUGGEST_BUFFER_MAX_SIZE=100
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=240"
ZSH_AUTOSUGGEST_USE_ASYNC=true

# Syntax highlighting
# (Correction) Declare as an associative array before use to prevent "invalid subscript" error.
typeset -A ZSH_HIGHLIGHT_STYLES
ZSH_HIGHLIGHT_HIGHLIGHTERS=(main brackets pattern cursor)
ZSH_HIGHLIGHT_STYLES[default]=none
ZSH_HIGHLIGHT_STYLES[unknown-token]=fg=red,bold
ZSH_HIGHLIGHT_STYLES[reserved-word]=fg=cyan,bold
ZSH_HIGHLIGHT_STYLES[precommand]=fg=green,underline
ZSH_HIGHLIGHT_STYLES[commandseparator]=fg=blue,bold
ZSH_HIGHLIGHT_STYLES[path]=underline
ZSH_HIGHLIGHT_STYLES[globbing]=fg=blue,bold
ZSH_HIGHLIGHT_STYLES[history-expansion]=fg=blue,bold
ZSH_HIGHLIGHT_STYLES[single-hyphen-option]=fg=cyan
ZSH_HIGHLIGHT_STYLES[double-hyphen-option]=fg=cyan
ZSH_HIGHLIGHT_STYLES[single-quoted-argument]=fg=yellow
ZSH_HIGHLIGHT_STYLES[double-quoted-argument]=fg=yellow
ZSH_HIGHLIGHT_STYLES[redirection]=fg=blue,bold
ZSH_HIGHLIGHT_STYLES[comment]=fg=black,bold
ZSH_HIGHLIGHT_STYLES[arg0]=fg=green

# === INITIALIZATION ===
autoload -Uz add-zsh-hook

# ===================================
# 💀 Dependency Verification 💀
# ===================================
_zsh_verify_dependencies() {
  local required_cmds=("git" "curl" "figlet" "jq" "ss" "sensors")
  local optional_cmds=("bat" "fd" "fastfetch")
  local missing_pkgs=()
  local pkg_map
  declare -A pkg_map=(
    [git]="git" [curl]="curl" [figlet]="figlet" [jq]="jq" [ss]="net-tools"
    [sensors]="lm-sensors" [bat]="bat" [fd]="fd-find" [fastfetch]="fastfetch"
  )

  for cmd in "${required_cmds[@]}" "${optional_cmds[@]}"; do
    # (Correction) Check for common alternative command names (e.g., batcat, fdfind)
    local found=false
    if command -v "$cmd" &>/dev/null; then
      found=true
    elif [[ "$cmd" == "bat" ]] && command -v "batcat" &>/dev/null; then
      found=true
    elif [[ "$cmd" == "fd" ]] && command -v "fdfind" &>/dev/null; then
      found=true
    fi

    if ! $found; then
      missing_pkgs+=("${pkg_map[$cmd]}")
    fi
  done

  if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
    local unique_pkgs=($(for pkg in "${missing_pkgs[@]}"; do echo "$pkg"; done | sort -u))
    echo -e "\033[38;2;255;165;0m⚠️  WARNING: Missing required packages for full functionality.\033[0m"
    echo -e "\033[38;2;255;255;0mPlease run the following command to install them:\033[0m"
    echo -e "\033[38;2;0;255;255msudo apt update && sudo apt install -y ${unique_pkgs[*]} \033[0m\n"
    return 1
  fi
  return 0
}

# ===============================
# 💀 Welcome Display Function 💀
# ===============================
post_init_display() {
  if [[ -z "$WELCOME_DISPLAYED" ]]; then
    export WELCOME_DISPLAYED=1
    command clear

    # First, verify all our tools are present.
    _zsh_verify_dependencies

    # Show banner + system info
    show_system_info
    time_based_greeting

    # Load system visual tool (with loading fx)
    if command -v fastfetch &>/dev/null; then
      echo
      fastfetch
    else
      echo "🚨 No system info tool (fastfetch) found!"
    fi
  fi
}

add-zsh-hook precmd post_init_display

# === GIT INTEGRATION ===
alias g='git'
alias ga='git add'
alias gaa='git add --all'
alias gap='git add -p'
alias gb='git branch'
alias gbr='git branch -r'
alias gc='git commit -v'
alias gca='git commit -v -a'
alias gcam='git commit -a -m'
alias gcb='git checkout -b'
alias gco='git checkout'
alias gd='git diff'
alias gdc='git diff --cached'
alias gf='git fetch'
alias gl='git pull'
alias gp='git push'
alias glog='git log --oneline --decorate --graph'
alias gs='git status -sb'

# === DOCKER & KUBERNETES INTEGRATION ===
# Docker status
docker_status() {
  if command -v docker &>/dev/null; then
    echo "🐳 Docker Status:"
    docker stats --no-stream
  fi
}

# Kubernetes status
kube_status() {
  if command -v kubectl &>/dev/null; then
    echo "☸️  Kubernetes Status:"
    kubectl get nodes -o wide
    echo "\nPods:"
    kubectl get pods --all-namespaces
  fi
}

# === CLOUD INTEGRATION ===
# AWS Status
aws_status() {
  if command -v aws &>/dev/null; then
    echo "☁️  AWS Status:"
    aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,InstanceType,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' --output table
  fi
}

# Azure Status
az_status() {
  if command -v az &>/dev/null; then
    echo "☁️  Azure Status:"
    az vm list --show-details --output table
  fi
}

# GCP Status
gcp_status() {
  if command -v gcloud &>/dev/null; then
    echo "☁️  GCP Status:"
    gcloud compute instances list
  fi
}

# === SECURITY HARDENING & MONITORING ===
INTEGRITY_BASELINE_FILE="$XDG_CONFIG_HOME/zsh/fs_integrity_baseline.sha256"

# Function to create a baseline of critical file hashes
initialize_integrity_baseline() {
  echo "🔒 Creating new file integrity baseline..."
  # List of critical files for a standard Kali Linux system
  local files_to_check=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password"
    "/etc/login.defs"
    "/etc/securetty"
    "/root/.ssh/authorized_keys"
  )

  # Ensure directory exists
  mkdir -p "$(dirname "$INTEGRITY_BASELINE_FILE")"

  # Clear old baseline and add a header
  echo "# Zsh File Integrity Baseline - $(date)" > "$INTEGRITY_BASELINE_FILE"

  for file in "${files_to_check[@]}"; do
    if [[ -r "$file" ]]; then
      sha256sum "$file" >> "$INTEGRITY_BASELINE_FILE"
    fi
  done
  echo "✅ Baseline created at: $INTEGRITY_BASELINE_FILE"
}

# Function to check file system integrity
check_fs_integrity() {
  if [[ ! -f "$INTEGRITY_BASELINE_FILE" ]]; then
    echo "⚠️  Integrity baseline not found. Run 'sec-baseline' first."
    return 1
  fi
  echo "🔍 Checking file system integrity against '$INTEGRITY_BASELINE_FILE'..."
  local has_warnings=false
  # Use process substitution to read the output of sha256sum
  while IFS= read -r line; do
    echo "🚨 WARNING: Integrity check FAILED for file: $(echo $line | cut -d':' -f1)"
    has_warnings=true
  done < <(sha256sum -c --quiet "$INTEGRITY_BASELINE_FILE" 2>/dev/null | grep 'FAILED')

  if ! $has_warnings; then
    echo "✅ All checked files are intact."
  fi
}

# Function to check for network anomalies
check_network_anomalies() {
  echo "📡 Checking for network anomalies..."
  if ! command -v ss &>/dev/null; then
    echo "⚠️ 'ss' command not found. Cannot perform network check."
    return 1
  fi

  echo "\nStrange Listening Ports (non-standard services):"
  ss -tlpn | awk 'NR>1 {print $4}' | grep -E ':[0-9]+$' | cut -d':' -f2 | sort -un | while read port; do
    # Check if the port is a well-known service
    if ! grep -qwE "^\w+\s+${port}/(tcp|udp)" /etc/services; then
      echo "  - Unusual open port detected: $port"
    fi
  done

  echo "\nTop 10 Established Connections by IP:"
  ss -tn 'state established' | awk 'NR>1 {print $5}' | cut -d':' -f1 | grep -vE '^(127.0.0.1|::1)$' | sort | uniq -c | sort -nr | head -n 10
}

alias sec-baseline='initialize_integrity_baseline'
alias sec-check-fs='check_fs_integrity'
alias sec-check-net='check_network_anomalies'

# === OPERATIONAL CONTEXT & TARGETING ===
# These functions allow you to set the scope for your current operation.
# The AI engine and HUD will use this context to provide relevant info.

export ZSH_OP_TARGET_IP=""
export ZSH_OP_TARGET_DOMAIN=""
export ZSH_OP_TARGET_DESC=""

set-target() {
  if [[ ! "$enable_op_context" = true ]]; then return; fi
  if [[ -z "$1" ]]; then
    echo "Usage: set-target <IP_ADDRESS> [DOMAIN] [DESCRIPTION]"
    echo "Example: set-target 10.10.11.15 kioptrix.com 'Vulnhub Kioptrix VM'"
    return 1
  fi
  export ZSH_OP_TARGET_IP="$1"
  export ZSH_OP_TARGET_DOMAIN="$2"
  export ZSH_OP_TARGET_DESC="$3"
  echo "🎯 Target set: IP=$ZSH_OP_TARGET_IP, Domain=$ZSH_OP_TARGET_DOMAIN, Desc=$ZSH_OP_TARGET_DESC"
}

clear-target() {
  if [[ ! "$enable_op_context" = true ]]; then return; fi
  export ZSH_OP_TARGET_IP=""
  export ZSH_OP_TARGET_DOMAIN=""
  export ZSH_OP_TARGET_DESC=""
  echo "🎯 Target cleared."
}

# === ADVANCED AI ENGINE ===

# --- AI Natural Language Command Processor ---
ai() {
  if [[ ! "$enable_ai_engine" = true || ! "$enable_ai_nlc" = true ]]; then return; fi
  if [[ -z "$1" ]]; then
    echo "Usage: ai <your query in plain English>"
    echo "Example: ai scan all ports for the target"
    return 1
  fi

  local query="$@"
  local target_ip="${ZSH_OP_TARGET_IP:-127.0.0.1}"
  local target_domain="${ZSH_OP_TARGET_DOMAIN:-example.com}"
  local suggested_command

  # This is a rule-based engine simulating a local AI model for speed and privacy.
  # It uses keyword matching to translate natural language to commands.
  case "$query" in
      *"scan all ports for"*|*"full port scan on"*)
          suggested_command="nmap -p- -T4 -v $target_ip"
          ;;
      *"scan for web servers"*|*"find http ports"*)
          suggested_command="nmap -p 80,443,8000,8080 --open -sV $target_ip"
          ;;
      *"find web directories"*|*"gobuster on"*)
          suggested_command="gobuster dir -u http://$target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
          ;;
      *"check for web vulnerabilities"*|*"run nikto on"*)
          suggested_command="nikto -h http://$target_ip"
          ;;
      *"find subdomains for"*)
          suggested_command="gobuster dns -d $target_domain -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
          ;;
      *"show me my public ip"*)
          suggested_command="curl -s https://ipinfo.io/ip"
          ;;
      *"list running docker containers"*)
          suggested_command="docker ps"
          ;;
      *"what is my network config"*)
          suggested_command="ip addr"
          ;;
      *)
          suggested_command="# AI: I'm not sure how to translate that yet."
          ;;
  esac

  echo -e "\033[38;2;0;255;255m🧠 AI Suggestion:\033[0m \033[1;33m$suggested_command\033[0m"

  # Ask user if they want to execute the command
  if [[ ! "$suggested_command" =~ "# AI:" ]]; then
    read -q "REPLY?Execute this command? (y/n) "
    echo
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
      eval $suggested_command
    fi
  fi
}

# === AI-POWERED COMMAND SUGGESTIONS ===
_ZSH_AI_HISTORY_FILE="$XDG_DATA_HOME/zsh/zsh_ai_history"

# Hook to log all commands with their directory context
_zsh_log_command_to_history() {
  # Don't log empty commands or suggestions themselves
  if [[ -z "$1" || "$1" == "suggest" ]]; then return; fi
  mkdir -p "$(dirname "$_ZSH_AI_HISTORY_FILE")"
  echo "$PWD|$1" >> "$_ZSH_AI_HISTORY_FILE"
}
add-zsh-hook preexec _zsh_log_command_to_history

# Function to suggest commands based on context and history
# Enhanced 'suggest' function with workflow awareness
suggest() {
  if [[ ! "$enable_ai_engine" = true || ! "$enable_ai_smart_suggestions" = true ]]; then return; fi
  if [[ ! -f "$_ZSH_AI_HISTORY_FILE" ]]; then
    echo "No command history found yet. Use the shell for a bit to build it."
    return
  fi

  echo -e "\033[38;2;0;255;255m🧠 AI Command Suggestions for this directory:\033[0m"

  local suggestions
  # --- AI Workflow Analysis ---
  local last_command=$(fc -ln -1)
  local target_ip="${ZSH_OP_TARGET_IP:-'<target_ip>'}"
  echo -e "\033[38;2;255;255;0m✨ AI Workflow Suggestions (last command: '$last_command'):\033[0m"

  case "$last_command" in
    *nmap*)
      echo "  - gobuster dir -u http://$target_ip -w <wordlist>"
      echo "  - nikto -h http://$target_ip"
      echo "  - enum4linux -a $target_ip"
      ;;
    *gobuster*|*nikto*)
      echo "  - nmap -sC -sV -p<port> $target_ip"
      echo "  - searchsploit <service_name>"
      ;;
    *searchsploit*)
      echo "  - searchsploit -m <exploit_path>"
      echo "  - python -m http.server 80"
      ;;
    *git*)
      echo "  - git log --oneline --graph"
      echo "  - git status -sb"
      echo "  - git diff --cached"
      ;;
    *docker*)
      echo "  - docker exec -it <container_id> /bin/bash"
      echo "  - docker logs -f <container_id>"
      ;;
  esac

  # --- General History-Based Suggestions ---
  echo -e "\n\033[38;2;255;255;0m📚 General suggestions for this directory (most frequent):\033[0m"
  suggestions=$(grep "^$PWD|" "$_ZSH_AI_HISTORY_FILE" | cut -d'|' -f2 | sort | uniq -c | sort -nr | head -n 5 | awk '{ $1="  - "; print }')

  # Print context-aware suggestions if any were found
  if [[ -n "$suggestions" ]]; then
    echo -e "$suggestions"
  else
    echo "  No history for this directory yet."
  fi
}


# === LIVE THREAT INTELLIGENCE ===
# Fetches the latest CVEs to keep you aware of emerging threats.
fetch-threats() {
  if [[ ! "$enable_threat_intel" = true ]]; then return; fi

  if ! command_exists curl || ! command_exists jq; then
    echo "Error: 'curl' and 'jq' are required for this feature."
    return 1
  fi

  echo "Fetching latest 5 CVEs from cve.circl.lu..."

  local cve_data
  cve_data=$(curl -s "https://cve.circl.lu/api/last/5")

  if [[ -z "$cve_data" ]]; then
    echo "Error: Could not fetch threat intelligence data."
    return 1
  fi

  echo "--- Latest 5 Published CVEs ---"
  echo "$cve_data" | jq -r '.[] | "\n\033[1;33mCVE-ID:\033[0m \(.id) \n\033[1;31mCVSS:\033[0m \(.cvss) \n\033[1;36mSummary:\033[0m \(.summary | gsub("\\n"; " "))[0:150]..."'
  echo "---------------------------------"
}

alias threat-intel='fetch-threats'

# === INTERACTIVE DASHBOARD ===
# Keybinding to refresh dashboard
_zsh_refresh_dashboard() {
    clear
    show_system_info
    zle reset-prompt
}

zle -N _zsh_refresh_dashboard
# Bind to Ctrl+X then Ctrl+R for safety
bindkey '^X^R' _zsh_refresh_dashboard


# === ALIASES ===
# Enhanced ls with eza/exa
if command -v eza &> /dev/null; then
  alias ls='eza --icons --long --group-directories-first --git'
  alias ll='eza -la --icons --group-directories-first --git'
  alias la='eza -la --icons --group-directories-first'
  alias lt='eza --tree --level=2 --icons'
  alias l='eza -F --icons'
elif command -v exa &> /dev/null; then
  alias ls='exa --icons --long --group-directories-first --git'
  alias ll='exa -la --icons --group-directories-first --git'
  alias la='exa -la --icons --group-directories-first'
  alias lt='exa --tree --level=2 --icons'
  alias l='exa -F --icons'
else
  alias ls='ls --color=auto --group-directories-first'
  alias ll='ls -la'
  alias la='ls -la'
  alias l='ls -CF'
fi

# System management
alias update="sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean"
alias sysinfo="show_system_info"
alias netstat="ss -tuln"
alias ports="netstat -tulpn"
alias process="ps aux | head -20"
alias memory="free -h && echo && ps aux --sort=-%mem | head -10"
alias disk="df -h && echo && du -sh * 2>/dev/null | sort -hr | head -10"
alias ll='ls -lah'

# Custom scripts
alias setup="python3 ~/Scripts/wifi_auto_login.py"
alias server="bash /home/bhanu/Scripts/server.sh"

# === POWERLEVEL10K CONFIGURATION ===
if [[ -f ~/.p10k.zsh ]]; then
  source ~/.p10k.zsh
else
  # Minimal configuration
  typeset -g POWERLEVEL9K_LEFT_PROMPT_ELEMENTS=(context dir vcs)
  typeset -g POWERLEVEL9K_RIGHT_PROMPT_ELEMENTS=(status command_execution_time time)
  typeset -g POWERLEVEL9K_CONTEXT_FOREGROUND=33
  typeset -g POWERLEVEL9K_CONTEXT_BACKGROUND=236
  typeset -g POWERLEVEL9K_CONTEXT_ROOT_FOREGROUND=196
  typeset -g POWERLEVEL9K_DIR_FOREGROUND=39
  typeset -g POWERLEVEL9K_VCS_FOREGROUND=76
  typeset -g POWERLEVEL9K_TIME_FOREGROUND=142
fi

# === DIRECTORY SETUP ===
[[ -d "$XDG_STATE_HOME/zsh" ]] || mkdir -p "$XDG_STATE_HOME/zsh"
[[ -d "$XDG_CACHE_HOME/zsh" ]] || mkdir -p "$XDG_CACHE_HOME/zsh"

# === SECURITY ===
ulimit -c 0
umask 022

# === PATH CONFIGURATION ===
export PATH="$HOME/.local/bin:$HOME/bin:$PATH"
export WORKON_HOME="$HOME/.virtualenvs"
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"
export PATH="$HOME/.cargo/bin:$PATH"
export PATH="$HOME/.local/share/npm/bin:$PATH"

# Load local configuration
[[ -f "$HOME/.zshrc.local" ]] && source "$HOME/.zshrc.local"

echo -e "\033[32m🚀 Shadow@Bhanu Elite Terminal Environment Loaded Successfully! 🚀\033[0m"
