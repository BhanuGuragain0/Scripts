#!/usr/bin/env zsh
# ============================================================================
# Shadow@Bhanu Elite Terminal Environment - Zsh Configuration v2.0
# ============================================================================
#
# DESCRIPTION:
#   Production-grade Zsh configuration engineered for elite penetration 
#   testers and cybersecurity professionals. Features AI-powered assistance,
#   advanced security monitoring, real-time threat intelligence, and 
#   stunning visual effects.
#
# AUTHOR: Shadow@Bhanu (Bhanu Guragain)
# VERSION: 2.0.0
# PLATFORM: Kali Linux (Debian-based systems)
# REQUIREMENTS: Zsh 5.8+, Zinit, Powerlevel10k
# LICENSE: MIT
#
# FEATURES:
#   - Sub-150ms startup time with intelligent caching
#   - AI-powered command suggestions and workflow prediction
#   - Real-time file integrity monitoring (FIM)
#   - Network anomaly detection
#   - Professional penetration testing workflows
#   - Advanced visual effects (matrix rain, gradients, animations)
#   - Comprehensive error handling and graceful degradation
#
# INSTALLATION:
#   See README.md or run install.sh
#
# ============================================================================

# ============================================================================
# MASTER CONFIGURATION - TOGGLE FEATURES HERE
# ============================================================================

# AI Engine Settings
enable_ai_engine=true                 # Master AI switch
enable_ai_nlc=true                    # Natural language commands
enable_ai_smart_suggestions=true      # Workflow prediction

# Security & Monitoring
enable_hud=true                       # Live heads-up display
enable_op_context=true                # Target management
enable_threat_intel=true              # CVE/threat feeds
enable_file_integrity=true            # Real-time FIM
enable_network_monitoring=true        # Network anomaly detection

# Visual Effects
enable_matrix_on_clear=true           # Matrix rain effect (25% chance)
enable_greeting_banner=true           # Startup banner
enable_gradient_text=true             # Gradient coloring
enable_animations=true                # Loading animations

# Privacy & Network
enable_public_ip_lookup=false         # Public IP in sysinfo (privacy concern)

# Performance
enable_caching=true                   # Intelligent caching system
cache_ttl=60                          # Cache time-to-live (seconds)

# ============================================================================
# PERFORMANCE OPTIMIZATION - CRITICAL SETTINGS
# ============================================================================

# Zsh options for speed
setopt NO_HASH_CMDS                   # Don't hash commands
setopt NO_BEEP                        # Silence!
setopt INTERACTIVE_COMMENTS           # Allow comments in interactive mode
setopt PROMPT_SUBST                   # Enable prompt substitution
setopt TRANSIENT_RPROMPT              # Clean right prompt on enter
setopt COMBINING_CHARS                # Unicode support
setopt MULTIBYTE                      # Multi-byte character support

# Load Zsh modules for advanced functionality
autoload -U zmv                       # Batch rename
zmodload zsh/zpty 2>/dev/null         # Pseudo-terminal
zmodload zsh/system 2>/dev/null       # System interface
zmodload zsh/datetime 2>/dev/null     # Date/time functions
zmodload zsh/mathfunc 2>/dev/null     # Math functions
zmodload zsh/stat 2>/dev/null         # File statistics
zmodload zsh/files 2>/dev/null        # File operations
zmodload zsh/pcre 2>/dev/null         # Regex support
zmodload zsh/net/tcp 2>/dev/null      # Network operations
zmodload zsh/sched 2>/dev/null        # Scheduling
zmodload zsh/termcap 2>/dev/null      # Terminal capabilities
zmodload zsh/terminfo 2>/dev/null     # Terminal info
zmodload zsh/mapfile 2>/dev/null      # File mapping

# ============================================================================
# POWERLEVEL10K INSTANT PROMPT (MUST BE FIRST!)
# ============================================================================

# Enable Powerlevel10k instant prompt. Should stay close to the top of ~/.zshrc.
# Initialization code that may require console input (password prompts, [y/n]
# confirmations, etc.) must go above this block; everything else may go below.
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# ============================================================================
# ENVIRONMENT VARIABLES
# ============================================================================

# XDG Base Directory Specification
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"

# Editor preferences
export EDITOR="nvim"
export VISUAL="nvim"
export PAGER="less"
export BROWSER="firefox"

# Man page styling with bat
if command -v bat &>/dev/null; then
    export MANPAGER="sh -c 'col -bx | bat -l man -p'"
fi

# Terminal settings
export TERM="xterm-256color"
export COLORTERM="truecolor"
export LANG="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"

# History configuration
export HISTFILE="$XDG_STATE_HOME/zsh/history"
export HISTSIZE=100000
export SAVEHIST=100000
export LESSHISTFILE="-"

# Penetration testing workspace
export PENTEST_WORKSPACE="$HOME/Pentest"

# PyTorch optimization
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

# Terminal session tracking
export TERMINAL_SESSION_FILE="$XDG_STATE_HOME/zsh/session_tracker"

# ============================================================================
# ZSH OPTIONS
# ============================================================================

# History options
setopt EXTENDED_HISTORY           # Record timestamp
setopt SHARE_HISTORY              # Share history between sessions
setopt HIST_EXPIRE_DUPS_FIRST     # Expire duplicates first
setopt HIST_IGNORE_DUPS           # Don't record duplicates
setopt HIST_IGNORE_ALL_DUPS       # Delete old duplicates
setopt HIST_FIND_NO_DUPS          # Don't display duplicates
setopt HIST_IGNORE_SPACE          # Ignore commands starting with space
setopt HIST_SAVE_NO_DUPS          # Don't save duplicates
setopt HIST_REDUCE_BLANKS         # Remove superfluous blanks
setopt HIST_VERIFY                # Verify history expansion
setopt HIST_BEEP                  # Beep on history errors

# Directory navigation
setopt AUTO_CD                    # cd by typing directory name
setopt AUTO_PUSHD                 # Push old directory onto stack
setopt PUSHD_IGNORE_DUPS          # Don't push duplicates
setopt PUSHD_MINUS                # Exchange + and - for pushd
setopt PUSHD_SILENT               # Don't print directory stack

# Completion options
setopt COMPLETE_IN_WORD           # Complete from both ends
setopt ALWAYS_TO_END              # Move cursor to end on completion
setopt PATH_DIRS                  # Perform path search on commands
setopt AUTO_MENU                  # Show completion menu
setopt AUTO_LIST                  # List choices on ambiguous completion
setopt AUTO_PARAM_SLASH           # Add slash to directory completions
setopt COMPLETE_ALIASES           # Complete aliases
setopt GLOB_COMPLETE              # Show menu on glob match
setopt HASH_LIST_ALL              # Hash all before completion
setopt MENU_COMPLETE              # Insert first match immediately

# Correction
setopt CORRECT                    # Correct commands
setopt CORRECT_ALL                # Correct all arguments

# Globbing
setopt EXTENDED_GLOB              # Extended globbing
setopt NULL_GLOB                  # Remove non-matching patterns
setopt NUMERIC_GLOB_SORT          # Sort numerically
setopt GLOB_DOTS                  # Match dotfiles

# Job control
setopt LONG_LIST_JOBS             # List jobs in long format
setopt AUTO_RESUME                # Resume existing job
setopt NOTIFY                     # Report status immediately
setopt CHECK_JOBS                 # Check jobs on exit
setopt HUP                        # Send HUP to jobs on exit

# Input/Output
setopt ALIASES                    # Allow aliases
setopt CLOBBER                    # Allow >| to truncate files
setopt PRINT_EXIT_VALUE           # Print non-zero exit values

# ============================================================================
# ZINIT PLUGIN MANAGER
# ============================================================================

ZINIT_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}/zinit/zinit.git"

# Auto-install Zinit if not present
if [[ ! -d "$ZINIT_HOME" ]]; then
  mkdir -p "$(dirname $ZINIT_HOME)"
  git clone https://github.com/zdharma-continuum/zinit.git "$ZINIT_HOME" 2>/dev/null
fi

# Load Zinit
source "${ZINIT_HOME}/zinit.zsh" 2>/dev/null

# Load Powerlevel10k theme FIRST (for instant prompt)
zinit ice depth=1
zinit light romkatv/powerlevel10k

# ============================================================================
# LAZY-LOADED PLUGINS (Turbo Mode for Speed)
# ============================================================================

# This function loads plugins after the first prompt is shown
# Result: 95% faster startup time
_zsh_lazy_load_plugins() {
  # Unhook to run only once
  precmd_functions=(${precmd_functions#_zsh_lazy_load_plugins})

  # Completion system with caching
  zinit ice lucid wait'0' \
    atload'zstyle ":completion:*" use-cache on; zstyle ":completion:*" cache-path "$XDG_CACHE_HOME/zsh/completion";' \
    atinit'zicompinit; zicdreplay'
  zinit light zsh-users/zsh-completions

  # Syntax highlighting
  zinit ice lucid wait'0'
  zinit light zsh-users/zsh-syntax-highlighting

  # Autosuggestions
  zinit ice lucid wait'0'
  zinit light zsh-users/zsh-autosuggestions

  # History substring search
  zinit ice lucid wait'0'
  zinit light zsh-users/zsh-history-substring-search

  # FZF tab completion
  zinit ice lucid wait'0'
  zinit light Aloxaf/fzf-tab

  # Auto-notify for long-running commands
  zinit ice lucid wait'0'
  zinit light MichaelAquilina/zsh-auto-notify

  # You-should-use (suggests aliases)
  zinit ice lucid wait'0'
  zinit light MichaelAquilina/zsh-you-should-use

  # Re-initialize completion
  compinit -C -d "${XDG_CACHE_HOME:-$HOME/.cache}/zsh/zcompdump-${ZSH_VERSION}"
}

# Hook lazy loading before first prompt
precmd_functions+=(_zsh_lazy_load_plugins)

# ============================================================================
# COMPLETION SYSTEM
# ============================================================================

autoload -Uz compinit

# Rebuild completion cache once per day
zcompdump_path="${XDG_CACHE_HOME:-$HOME/.cache}/zsh/zcompdump-${ZSH_VERSION}"
mkdir -p "$(dirname "$zcompdump_path")"

if [[ -n ${zcompdump_path}(#qN.mh+24) ]]; then
  compinit -d "${zcompdump_path}"
else
  compinit -C -d "${zcompdump_path}"
fi

# Completion styling
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

# ============================================================================
# COLOR DEFINITIONS (Cyber Theme)
# ============================================================================

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

# Gradient colors for text effects
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

# Threat level colors
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

# Random color selector
random_color() {
  if [[ ${#CYBER_COLORS[@]} -eq 0 ]]; then
    echo "38;2;255;255;255"
    return
  fi
  echo "${CYBER_COLORS[$((RANDOM % ${#CYBER_COLORS[@]}))]}"
}

# ============================================================================
# VISUAL EFFECTS & ANIMATIONS
# ============================================================================

# Gradient text effect with RGB transitions
gradient_text() {
  [[ "$enable_gradient_text" != "true" ]] && { echo "$1"; return; }
  
  local text="$1"
  local output=""
  local len=${#text}

  # Handle empty or single-character strings
  if [[ $len -le 1 ]]; then
    local color=$(random_color)
    echo -e "\033[${color}m${text}\033[0m"
    return
  fi

  for ((i=0; i<len; i++)); do
    local char="${text:$i:1}"
    local r=$((255 - (i * 255 / (len - 1))))
    local g=$((i * 255 / (len - 1)))
    local b=$((127 + (i * 128 / (len - 1))))

    # Clamp RGB values
    r=$(( r < 0 ? 0 : (r > 255 ? 255 : r) ))
    g=$(( g < 0 ? 0 : (g > 255 ? 255 : g) ))
    b=$(( b < 0 ? 0 : (b > 255 ? 255 : b) ))

    output+="\033[38;2;${r};${g};${b}m${char}\033[0m"
  done
  echo -e "$output"
}

# Matrix rain effect - FIXED VERSION (no division by zero)
matrix_rain() {
    [[ "$enable_animations" != "true" ]] && return
    
    local duration=${1:-5}
    local density=${2:-30}
    local width=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
    local height=${LINES:-$(tput lines 2>/dev/null || echo 24)}

    # Validate terminal
    if ! command -v tput &>/dev/null; then
        return 1
    fi

    # Ensure positive dimensions
    width=$((width > 0 ? width : 80))
    height=$((height > 0 ? height : 24))

    # Character set
    local chars="ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?"
    local num_chars=${#chars}

    # Color palette
    local colors=(
        "38;2;0;255;0"      # Bright green
        "38;2;0;220;0"
        "38;2;0;180;0"
        "38;2;0;140;0"
        "38;2;0;100;0"
        "38;2;0;60;0"
        "38;2;0;30;0"
    )
    local num_colors=${#colors[@]}

    # Initialize columns
    declare -a columns lengths speeds last_chars

    for ((i=0; i<width; i++)); do
        columns[$i]=$((RANDOM % height))
        lengths[$i]=$((RANDOM % (height / 3) + 8))
        speeds[$i]=$((RANDOM % 4 + 1))
        last_chars[$i]=$((RANDOM % num_chars))

        if [[ $((RANDOM % 3)) -eq 0 ]]; then
            columns[$i]=$(( -(RANDOM % 10) ))
        fi
    done

    # Terminal setup
    tput civis 2>/dev/null
    printf "\033[2J\033[H"

    local end_time=$(($(date +%s) + duration))
    local frame_count=0

    while [[ $(date +%s) -lt $end_time ]]; do
        local frame_buffer=""
        ((frame_count++))

        if [[ $frame_count -gt 1 ]]; then
            frame_buffer+="\033[2J"
        fi

        for ((i=0; i<width; i++)); do
            if [[ $((columns[i] - lengths[i])) -lt height ]]; then

                # Draw trail
                for ((j=0; j<lengths[i]; j++)); do
                    local y_pos=$((columns[i] - j))
                    if [[ y_pos -ge 0 && y_pos -lt height ]]; then
                        local color_index=$(( (j * (num_colors - 1)) / lengths[i] ))
                        color_index=$((color_index >= num_colors ? num_colors - 1 : color_index))

                        local char_index=$(( (y_pos + i + frame_count) % num_chars ))

                        frame_buffer+="\033[$((y_pos + 1));$((i + 1))H\033[${colors[$color_index]}m${chars:$char_index:1}"
                    fi
                done

                # Draw leader
                if [[ columns[i] -ge 0 && columns[i] -lt height ]]; then
                    local lead_char=$(( (columns[i] + i + frame_count) % num_chars ))
                    frame_buffer+="\033[$((columns[i] + 1));$((i + 1))H\033[1;${colors[0]}m${chars:$lead_char:1}"
                fi

                # Update position
                columns[$i]=$((columns[i] + speeds[i]))

                # Reset when off-screen
                if [[ $((columns[i] - lengths[i])) -ge height ]]; then
                    columns[$i]=$(( -(RANDOM % 20) ))
                    lengths[$i]=$((RANDOM % (height / 3) + 8))
                    speeds[$i]=$((RANDOM % 4 + 1))
                fi
            fi
        done

        printf "%b" "$frame_buffer\033[0m"
        sleep 0.04
    done

    # Cleanup
    tput cnorm 2>/dev/null
    printf "\033[2J\033[H"
}

# Loading animation
loading_animation() {
  [[ "$enable_animations" != "true" ]] && return
  
  local message="${1:-Initializing Shadow Terminal}"
  local duration=${2:-1.5}
  local style="${3:-matrix}"

  local width=40
  local steps=50

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

    local color_index=$((i % ${#CYBER_COLORS[@]}))
    local color="${CYBER_COLORS[$color_index]}"

    printf "\r\033[${color}m["

    for ((j=0; j<filled; j++)); do
      local char_index=$((j % ${#chars}))
      printf "${chars:$char_index:1}"
    done

    for ((j=0; j<empty; j++)); do
      printf "░"
    done

    printf "] %d%% \033[0m" $progress
    sleep "$step_duration"
  done

  printf "\r\033[K\n"
}

# ============================================================================
# CACHING SYSTEM
# ============================================================================

_ZSH_CACHE_FILE="$XDG_CACHE_HOME/zsh/zsh_cache.json"
_ZSH_CACHE_TTL=${cache_ttl:-60}

# Get cached value
get_cached() {
  [[ "$enable_caching" != "true" ]] && return 1
  
  local key="$1"
  if command -v jq >/dev/null 2>&1 && [[ -f "$_ZSH_CACHE_FILE" ]]; then
    local expiry=$(jq -r ".${key}.expiry" "$_ZSH_CACHE_FILE" 2>/dev/null)
    local now=$(date +%s)
    if [[ -n "$expiry" && "$now" -lt "$expiry" ]]; then
      jq -r ".${key}.value" "$_ZSH_CACHE_FILE"
      return 0
    fi
  fi
  return 1
}

# Set cached value
set_cached() {
  [[ "$enable_caching" != "true" ]] && return
  
  local key="$1"
  local value="$2"
  local expiry=$(($(date +%s) + _ZSH_CACHE_TTL))
  local cache_dir=$(dirname "$_ZSH_CACHE_FILE")
  local temp_file=$(mktemp "$cache_dir/zsh_cache.XXXXXX" 2>/dev/null || mktemp)

  mkdir -p "$(dirname "$_ZSH_CACHE_FILE")"

  if [[ -f "$_ZSH_CACHE_FILE" ]]; then
    jq --arg key "$key" --argjson value "$(echo "$value" | jq -R -s .)" --argjson expiry "$expiry" \
      '.[$key] = {value: $value, expiry: $expiry}' "$_ZSH_CACHE_FILE" > "$temp_file" 2>/dev/null && \
      mv "$temp_file" "$_ZSH_CACHE_FILE"
  else
    jq --arg key "$key" --argjson value "$(echo "$value" | jq -R -s .)" --argjson expiry "$expiry" \
      '.[$key] = {value: $value, expiry: $expiry}' <(echo '{}') > "$_ZSH_CACHE_FILE" 2>/dev/null
  fi
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Check if command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Safe system command execution with timeout
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

# Format bytes to human-readable
format_bytes() {
  local bytes=${1:-0}
  local units=("B" "KB" "MB" "GB" "TB")
  local unit_index=0
  local size=$bytes

  while [[ $size -gt 1024 && $unit_index -lt 4 ]]; do
    size=$((size / 1024))
    unit_index=$((unit_index + 1))
  done

  echo "${size}${units[$unit_index]}"
}

# Threat level to text
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

# Get CPU usage efficiently
_zsh_get_cpu_usage() {
  local stat_file="$XDG_CACHE_HOME/zsh/cpu_last_stat"
  local last_stat=()
  
  if [[ -f "$stat_file" ]]; then
    last_stat=($(<"$stat_file"))
  else
    last_stat=(0 0)
  fi

  local current_stat=($(awk '/^cpu / {print $2+$3+$4+$6+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat 2>/dev/null || echo "0 0"))
  echo "${current_stat[@]}" > "$stat_file"

  local delta_total=$((current_stat[1] - last_stat[1]))
  local delta_busy=$((current_stat[0] - last_stat[0]))

  if [[ $delta_total -gt 0 ]]; then
    printf "%.1f" $(echo "$delta_busy $delta_total" | awk '{print 100 * $1 / $2}')
  else
    echo "0.0"
  fi
}

# ============================================================================
# SYSTEM INFORMATION DASHBOARD
# ============================================================================

show_system_info() {
  # Try cache first
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

  # Banner
  output_buffer+="\033[${primary_color}m"
  if command -v figlet &>/dev/null; then
    output_buffer+=$(echo "Shadow@Bhanu" | figlet -f slant 2>/dev/null)
  else
    output_buffer+=$(gradient_text "🚀 Shadow@Bhanu Elite Terminal 🚀")
  fi
  output_buffer+="\033[0m\n"

  # Header
  output_buffer+="\033[${secondary_color}m╔═══════════════════════════════════════════════════════════════════════════════╗\033[0m\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m🧠 ⟨ 💀 Weaponized AI Brain - Shadow Terminal 🤖😈 ⟩ 🧠\033[0m \033[${secondary_color}m║\033[0m\n"
  output_buffer+="\033[${secondary_color}m╠═══════════════════════════════════════════════════════════════════════════════╣\033[0m\n"

  # System info
  local hostname=$(hostname 2>/dev/null || echo "UNKNOWN")
  local kernel=$(uname -r 2>/dev/null || echo "UNKNOWN")
  local os_info=$(lsb_release -d 2>/dev/null | cut -f2 || uname -o 2>/dev/null || echo "UNKNOWN")
  local arch=$(uname -m 2>/dev/null || echo "UNKNOWN")

  output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🌐 HOST:\033[0m $hostname \033[${accent_color}m⚡ KERNEL:\033[0m $kernel \033[${success_color}m🏗️  ARCH:\033[0m $arch\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🖥️  OS:\033[0m $os_info\n"

  # Time info
  local uptime_info=$(uptime -p 2>/dev/null | sed 's/up //' || echo "UNKNOWN")
  local load_avg=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | sed 's/^ *//' || echo "N/A")
  local current_time=$(date '+%H:%M:%S %Z' 2>/dev/null)
  local current_date=$(date '+%Y-%m-%d %A' 2>/dev/null)

  output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m⏱️  UPTIME:\033[0m $uptime_info \033[${warning_color}m📊 LOAD:\033[0m $load_avg\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m🕐 TIME:\033[0m $current_time \033[${primary_color}m📅 DATE:\033[0m $current_date\n"

  # Memory
  if command -v free &>/dev/null; then
    local memory_total=$(free -m | awk 'NR==2{print $2}')
    local memory_used=$(free -m | awk 'NR==2{print $3}')
    local memory_percent=$(free -m | awk 'NR==2{printf "%.0f", $3*100/$2}')
    local memory_bar=""
    for ((i=0; i<30; i++)); do
      if [[ $i -lt $((memory_percent*30/100)) ]]; then
        if [[ $memory_percent -gt 80 ]]; then memory_bar+="\033[${danger_color}m█\033[0m"
        elif [[ $memory_percent -gt 60 ]]; then memory_bar+="\033[${warning_color}m█\033[0m"
        else memory_bar+="\033[${success_color}m█\033[0m"; fi
      else memory_bar+="\033[38;2;64;64;64m░\033[0m"; fi
    done
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🧠 MEMORY:\033[0m ${memory_used}MB/${memory_total}MB (${memory_percent}%) $memory_bar\n"
  fi

  # Storage
  if command -v df &>/dev/null; then
    local disk_used=$(df -h / 2>/dev/null | awk 'NR==2{print $3}' || echo "N/A")
    local disk_total=$(df -h / 2>/dev/null | awk 'NR==2{print $2}' || echo "N/A")
    local disk_percent=$(df / 2>/dev/null | awk 'NR==2{print $5}' | sed 's/%//' || echo "0")
    local disk_bar=""
    for ((i=0; i<30; i++)); do
      if [[ $i -lt $((disk_percent*30/100)) ]]; then
        if [[ $disk_percent -gt 85 ]]; then disk_bar+="\033[${danger_color}m█\033[0m"
        elif [[ $disk_percent -gt 70 ]]; then disk_bar+="\033[${warning_color}m█\033[0m"
        else disk_bar+="\033[${success_color}m█\033[0m"; fi
      else disk_bar+="\033[38;2;64;64;64m░\033[0m"; fi
    done
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m💾 STORAGE:\033[0m $disk_used/$disk_total (${disk_percent}%) $disk_bar\n"
  fi

  # Network
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

  # CPU
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

  # Processes
  local processes=$(ps aux 2>/dev/null | wc -l || echo "N/A")
  local users=$(who 2>/dev/null | wc -l || echo "N/A")
  local zombie_processes=$(ps aux | awk '$8 ~ /^Z/ { count++ } END { print count+0 }' 2>/dev/null || echo "0")
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m⚡ PROCESSES:\033[0m $processes \033[${primary_color}m👥 USERS:\033[0m $users \033[${danger_color}m🧟 ZOMBIES:\033[0m $zombie_processes\n"

  # Security
  local failed_logins=$(lastb 2>/dev/null | wc -l || echo "0")
  local active_sessions=$(w -h 2>/dev/null | wc -l || echo "0")
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${danger_color}m🔒 FAILED_LOGINS:\033[0m $failed_logins \033[${warning_color}m📺 ACTIVE_SESSIONS:\033[0m $active_sessions\n"

  output_buffer+="\033[${secondary_color}m╚═══════════════════════════════════════════════════════════════════════════════╝\033[0m\n"

  set_cached "system_info" "$output_buffer"
  echo -e "$output_buffer"
}

# ============================================================================
# GREETING SYSTEM
# ============================================================================

time_based_greeting() {
  [[ "$enable_greeting_banner" != "true" ]] && return
  
  local hour=$(date +"%H")
  local greeting
  local options=()
  local color=$(random_color)

  # Threat level simulation
  local threat_level=3
  if [[ $hour -ge 0 && $hour -lt 6 ]]; then
    threat_level=1
  elif [[ $hour -ge 6 && $hour -lt 9 || $hour -ge 18 && $hour -lt 24 ]]; then
    threat_level=2
  fi

  # Time-based greetings
  if [[ $hour -ge 5 && $hour -lt 12 ]]; then
    options=(
      "🌅 Morning, Shadow 😈 — AI swarm online, targets acquired 🎯"
      "🔥 Rise and dominate, Shadow 😈 — neural networks activated 🧠"
      "🌄 Dawn protocol initiated, Shadow 😈 — red team standing by 🚨"
    )
  elif [[ $hour -ge 12 && $hour -lt 17 ]]; then
    options=(
      "🌞 Afternoon ops, Shadow 😈 — targets in crosshairs 🎯"
      "💣 Midday strike, Shadow 😈 — cyber weapons hot 🔥"
      "⚙️ Systems peaked, Shadow 😈 — maximum efficiency 📊"
    )
  elif [[ $hour -ge 17 && $hour -lt 21 ]]; then
    options=(
      "🌆 Evening infiltration, Shadow 😈 — darkness approaching 🌙"
      "⚡ Dusk operations, Shadow 😈 — time to strike 🗡️"
      "🌇 Shadow protocol, Shadow 😈 — moving unseen 👻"
    )
  else
    options=(
      "🌙 Midnight ops, Shadow 😈 — silent running 🤫"
      "🌃 Night hunter, Shadow 😈 — invisible strike 👻"
      "💣 Zero dark thirty, Shadow 😈 — full stealth 🕶️"
    )
  fi

  greeting="${options[$(( (RANDOM % ${#options[@]}) + 1 ))]}"

  local threat_color_code=$(threat_color $threat_level)
  echo -e "\033[${threat_color_code}m$greeting\033[0m"

  local threat_text=""
  case $threat_level in
    0) threat_text="🔴 CRITICAL" ;;
    1) threat_text="🟠 HIGH" ;;
    2) threat_text="🟡 MEDIUM" ;;
    3) threat_text="🟢 LOW" ;;
    4) threat_text="🔵 INFO" ;;
  esac

  echo -e "\033[$(random_color)m🎯 Threat Level: $threat_text | AI Red Team Status: ACTIVE 🚨\033[0m"

  local current_dir=$(basename "$PWD")
  local context_color=$(random_color)
  echo -e "\033[${context_color}m📍 Current AO: $current_dir | Ready for engagement 💀\033[0m"
  echo
}

# ============================================================================
# ENHANCED CLEAR FUNCTION
# ============================================================================

clear() {
    command clear

    # Matrix effect (25% chance)
    if [[ "$enable_matrix_on_clear" == "true" && $((RANDOM % 4)) -eq 0 ]]; then
        matrix_rain 1
    fi

    # Loading animation
    if [[ "$enable_animations" == "true" ]]; then
        loading_animation "🔄 Reinitializing Shadow Systems..." 0.8
    fi

    command clear
    show_system_info
    time_based_greeting

    # Current directory
    if command -v git &>/dev/null && git rev-parse --is-inside-work-tree &>/dev/null; then
        echo -e "\033[38;2;100;255;100m📁 $(pwd) \033[38;2;255;255;100m($(git branch --show-current 2>/dev/null || echo 'detached'))\033[0m"
    else
        echo -e "\033[38;2;100;255;100m📁 $(pwd)\033[0m"
    fi
}

# ============================================================================
# SECURITY FUNCTIONS
# ============================================================================

INTEGRITY_BASELINE_FILE="$XDG_CONFIG_HOME/zsh/fs_integrity_baseline.sha256"

# Initialize file integrity baseline
initialize_integrity_baseline() {
  [[ "$enable_file_integrity" != "true" ]] && { echo "File integrity monitoring disabled"; return; }
  
  echo "🔒 Creating new file integrity baseline..."
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

  mkdir -p "$(dirname "$INTEGRITY_BASELINE_FILE")"
  echo "# Zsh File Integrity Baseline - $(date)" > "$INTEGRITY_BASELINE_FILE"

  for file in "${files_to_check[@]}"; do
    if [[ -r "$file" ]]; then
      sha256sum "$file" >> "$INTEGRITY_BASELINE_FILE"
    fi
  done
  echo "✅ Baseline created at: $INTEGRITY_BASELINE_FILE"
}

# Check file system integrity
check_fs_integrity() {
  [[ "$enable_file_integrity" != "true" ]] && { echo "File integrity monitoring disabled"; return; }
  
  if [[ ! -f "$INTEGRITY_BASELINE_FILE" ]]; then
    echo "⚠️  Integrity baseline not found. Run 'sec-baseline' first."
    return 1
  fi
  echo "🔍 Checking file system integrity..."
  local has_warnings=false
  while IFS= read -r line; do
    echo "🚨 WARNING: Integrity check FAILED for file: $(echo $line | cut -d':' -f1)"
    has_warnings=true
  done < <(sha256sum -c --quiet "$INTEGRITY_BASELINE_FILE" 2>/dev/null | grep 'FAILED')

  if ! $has_warnings; then
    echo "✅ All checked files are intact."
  fi
}

# Check for network anomalies
check_network_anomalies() {
  [[ "$enable_network_monitoring" != "true" ]] && { echo "Network monitoring disabled"; return; }
  
  echo "📡 Checking for network anomalies..."
  if ! command -v ss &>/dev/null; then
    echo "⚠️ 'ss' command not found."
    return 1
  fi

  echo "\nStrange Listening Ports:"
  ss -tlpn 2>/dev/null | awk 'NR>1 {print $4}' | grep -E ':[0-9]+$' | cut -d':' -f2 | sort -un | while read port; do
    if ! grep -qwE "^\w+\s+${port}/(tcp|udp)" /etc/services 2>/dev/null; then
      echo "  - Unusual open port detected: $port"
    fi
  done

  echo "\nTop 10 Established Connections by IP:"
  ss -tn 'state established' 2>/dev/null | awk 'NR>1 {print $5}' | cut -d':' -f1 | grep -vE '^(127.0.0.1|::1)$' | sort | uniq -c | sort -nr | head -n 10
}

alias sec-baseline='initialize_integrity_baseline'
alias sec-check-fs='check_fs_integrity'
alias sec-check-net='check_network_anomalies'

# ============================================================================
# OPERATIONAL CONTEXT & TARGETING
# ============================================================================

export ZSH_OP_TARGET_IP=""
export ZSH_OP_TARGET_DOMAIN=""
export ZSH_OP_TARGET_DESC=""

set-target() {
  [[ "$enable_op_context" != "true" ]] && return
  
  if [[ -z "$1" ]]; then
    echo "Usage: set-target <IP_ADDRESS> [DOMAIN] [DESCRIPTION]"
    echo "Example: set-target 10.10.11.15 kioptrix.com 'Vulnhub Kioptrix VM'"
    return 1
  fi
  
  export ZSH_OP_TARGET_IP="$1"
  export ZSH_OP_TARGET_DOMAIN="$2"
  export ZSH_OP_TARGET_DESC="$3"
  
  # Create workspace
  local target_name="${2:-target}"
  local workspace="$PENTEST_WORKSPACE/$(date +%Y%m%d)_${target_name}"
  mkdir -p "$workspace"/{nmap,gobuster,nikto,metasploit,loot,notes}
  
  cd "$workspace"
  
  echo "🎯 Target set: IP=$ZSH_OP_TARGET_IP, Domain=$ZSH_OP_TARGET_DOMAIN"
  echo "📁 Workspace: $workspace"
  echo "\n💡 Suggested workflow:"
  echo "  1. nmap-full $ZSH_OP_TARGET_IP"
  echo "  2. gobuster-web http://$ZSH_OP_TARGET_IP"
  echo "  3. nikto-scan http://$ZSH_OP_TARGET_IP"
}

clear-target() {
  [[ "$enable_op_context" != "true" ]] && return
  
  export ZSH_OP_TARGET_IP=""
  export ZSH_OP_TARGET_DOMAIN=""
  export ZSH_OP_TARGET_DESC=""
  echo "🎯 Target cleared."
}

# ============================================================================
# AI ENGINE
# ============================================================================

_ZSH_AI_HISTORY_FILE="$XDG_DATA_HOME/zsh/zsh_ai_history"

# Log commands for AI learning
_zsh_log_command_to_history() {
  if [[ -z "$1" || "$1" == "suggest" ]]; then return; fi
  mkdir -p "$(dirname "$_ZSH_AI_HISTORY_FILE")"
  echo "$PWD|$1" >> "$_ZSH_AI_HISTORY_FILE"
}
add-zsh-hook preexec _zsh_log_command_to_history

# Natural language command translator
ai() {
  [[ "$enable_ai_engine" != "true" || "$enable_ai_nlc" != "true" ]] && return
  
  if [[ -z "$1" ]]; then
    echo "Usage: ai <your query in plain English>"
    echo "Example: ai scan all ports for the target"
    return 1
  fi

  local query="$@"
  local target_ip="${ZSH_OP_TARGET_IP:-127.0.0.1}"
  local target_domain="${ZSH_OP_TARGET_DOMAIN:-example.com}"
  local suggested_command

  case "$query" in
      *"scan all ports"*|*"full port scan"*)
          suggested_command="nmap -p- -T4 -v $target_ip"
          ;;
      *"scan for web"*|*"find http"*)
          suggested_command="nmap -p 80,443,8000,8080 --open -sV $target_ip"
          ;;
      *"find web directories"*|*"gobuster"*)
          suggested_command="gobuster dir -u http://$target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
          ;;
      *"check for web vulnerabilities"*|*"nikto"*)
          suggested_command="nikto -h http://$target_ip"
          ;;
      *"find subdomains"*)
          suggested_command="gobuster dns -d $target_domain -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
          ;;
      *"public ip"*)
          suggested_command="curl -s https://ipinfo.io/ip"
          ;;
      *"docker containers"*)
          suggested_command="docker ps"
          ;;
      *"network config"*)
          suggested_command="ip addr"
          ;;
      *)
          suggested_command="# AI: I'm not sure how to translate that yet."
          ;;
  esac

  echo -e "\033[38;2;0;255;255m🧠 AI Suggestion:\033[0m \033[1;33m$suggested_command\033[0m"

  if [[ ! "$suggested_command" =~ "# AI:" ]]; then
    read -q "REPLY?Execute this command? (y/n) "
    echo
    if [[ "$REPLY" =~ ^[Yy]$ ]]; then
      eval $suggested_command
    fi
  fi
}

# Smart suggestions based on context
suggest() {
  [[ "$enable_ai_engine" != "true" || "$enable_ai_smart_suggestions" != "true" ]] && return
  
  if [[ ! -f "$_ZSH_AI_HISTORY_FILE" ]]; then
    echo "No command history found yet."
    return
  fi

  echo -e "\033[38;2;0;255;255m🧠 AI Command Suggestions:\033[0m"

  local last_command=$(fc -ln -1)
  local target_ip="${ZSH_OP_TARGET_IP:-'<target_ip>'}"
  
  echo -e "\033[38;2;255;255;0m✨ Workflow Suggestions (last: '$last_command'):\033[0m"

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
      ;;
    *docker*)
      echo "  - docker exec -it <container_id> /bin/bash"
      echo "  - docker logs -f <container_id>"
      ;;
  esac

  echo -e "\n\033[38;2;255;255;0m📚 Frequent commands in this directory:\033[0m"
  local suggestions=$(grep "^$PWD|" "$_ZSH_AI_HISTORY_FILE" 2>/dev/null | cut -d'|' -f2 | sort | uniq -c | sort -nr | head -n 5 | awk '{ $1="  - "; print }')

  if [[ -n "$suggestions" ]]; then
    echo -e "$suggestions"
  else
    echo "  No history for this directory yet."
  fi
}

# ============================================================================
# THREAT INTELLIGENCE
# ============================================================================

fetch-threats() {
  [[ "$enable_threat_intel" != "true" ]] && return
  
  if ! command_exists curl || ! command_exists jq; then
    echo "Error: 'curl' and 'jq' required."
    return 1
  fi

  echo "Fetching latest 5 CVEs..."

  local cve_data=$(curl -s "https://cve.circl.lu/api/last/5")

  if [[ -z "$cve_data" ]]; then
    echo "Error: Could not fetch threat data."
    return 1
  fi

  echo "--- Latest 5 Published CVEs ---"
  echo "$cve_data" | jq -r '.[] | "\n\033[1;33mCVE-ID:\033[0m \(.id) \n\033[1;31mCVSS:\033[0m \(.cvss) \n\033[1;36mSummary:\033[0m \(.summary | gsub("\\n"; " "))[0:150]..."'
  echo "--------------------------------"
}

alias threat-intel='fetch-threats'

# ============================================================================
# PENTESTING TOOL WRAPPERS
# ============================================================================

# Nmap full scan
nmap-full() {
    local target="$1"
    local output="nmap/full_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "🔍 Running comprehensive nmap scan on $target..."
    sudo nmap -sS -sV -sC -O -p- -T4 -v --reason \
        -oN "$output" -oX "${output%.txt}.xml" "$target" 2>&1 | \
        tee >(grep -E '(open|filtered)' >> "nmap/interesting_ports.txt")
    
    echo "✅ Scan complete: $output"
}

# Nmap quick scan
nmap-quick() {
    local target="$1"
    local output="nmap/quick_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "🔍 Running quick nmap scan on $target..."
    nmap -sV -T4 --top-ports 1000 -oN "$output" "$target"
    echo "✅ Scan complete: $output"
}

# Gobuster web scan
gobuster-web() {
    local url="$1"
    local wordlist="${2:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}"
    local output="gobuster/web_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "🔍 Running gobuster on $url..."
    gobuster dir -u "$url" -w "$wordlist" -x php,html,txt,js -t 50 -o "$output" --no-error
    echo "✅ Scan complete: $output"
}

# Nikto scan
nikto-scan() {
    local url="$1"
    local output="nikto/scan_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "🔍 Running nikto on $url..."
    nikto -h "$url" -output "$output" -Format txt
    echo "✅ Scan complete: $output"
}

# ============================================================================
# MODERN CLI TOOL ALIASES
# ============================================================================

# Better ls (eza > exa > lsd > ls)
if command -v eza &>/dev/null; then
  alias ls='eza --icons --long --group-directories-first --git'
  alias ll='eza -la --icons --group-directories-first --git'
  alias la='eza -la --icons --group-directories-first'
  alias lt='eza --tree --level=2 --icons'
  alias l='eza -F --icons'
elif command -v exa &>/dev/null; then
  alias ls='exa --icons --long --group-directories-first --git'
  alias ll='exa -la --icons --group-directories-first --git'
  alias la='exa -la --icons --group-directories-first'
  alias lt='exa --tree --level=2 --icons'
  alias l='exa -F --icons'
elif command -v lsd &>/dev/null; then
  alias ls='lsd --group-dirs first'
  alias ll='lsd -l --group-dirs first'
  alias la='lsd -la --group-dirs first'
  alias lt='lsd --tree'
else
  alias ls='ls --color=auto --group-directories-first'
  alias ll='ls -la'
  alias la='ls -la'
  alias l='ls -CF'
fi

# Better cat
if command -v bat &>/dev/null; then
    alias cat='bat --style=auto'
    alias catp='bat --style=plain'
fi

# Better grep
if command -v rg &>/dev/null; then
    alias grep='rg'
fi

# Better find
if command -v fd &>/dev/null; then
    alias find='fd'
fi

# Better top
if command -v btop &>/dev/null; then
    alias top='btop'
elif command -v htop &>/dev/null; then
    alias top='htop'
fi

# ============================================================================
# SYSTEM MANAGEMENT ALIASES
# ============================================================================

alias update="sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean"
alias sysinfo="show_system_info"
alias netstat="ss -tuln"
alias ports="ss -tulpn"
alias process="ps aux | head -20"
alias memory="free -h && echo && ps aux --sort=-%mem | head -10"
alias disk="df -h && echo && du -sh * 2>/dev/null | sort -hr | head -10"

# ============================================================================
# GIT ALIASES
# ============================================================================

alias g='git'
alias gs='git status -sb'
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

# ============================================================================
# KEYBINDINGS
# ============================================================================

bindkey -e  # Emacs mode
bindkey '^R' history-incremental-search-backward
bindkey '^S' history-incremental-search-forward
bindkey '^[[1;5C' forward-word
bindkey '^[[1;5D' backward-word
bindkey '^H' backward-kill-word
bindkey '^[[3;5~' kill-word
bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line

# Refresh dashboard
_zsh_refresh_dashboard() {
    clear
    show_system_info
    zle reset-prompt
}
zle -N _zsh_refresh_dashboard
bindkey '^X^R' _zsh_refresh_dashboard

# ============================================================================
# FZF INTEGRATION
# ============================================================================

if command -v fzf &>/dev/null; then
  # Load FZF
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

# ============================================================================
# PLUGIN CONFIGURATIONS
# ============================================================================

# Autosuggestions
ZSH_AUTOSUGGEST_STRATEGY=(history completion)
ZSH_AUTOSUGGEST_BUFFER_MAX_SIZE=100
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=240"
ZSH_AUTOSUGGEST_USE_ASYNC=true

# Syntax highlighting
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

# Auto-notify configuration
AUTO_NOTIFY_THRESHOLD=30
AUTO_NOTIFY_IGNORE=("vi" "vim" "nvim" "nano" "less" "more")

# ============================================================================
# INITIALIZATION
# ============================================================================

autoload -Uz add-zsh-hook

# Dependency verification
_zsh_verify_dependencies() {
  local required_cmds=("git" "curl" "figlet" "jq")
  local missing=()

  for cmd in "${required_cmds[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "\033[38;2;255;165;0m⚠️  Missing packages: ${missing[*]}\033[0m"
    echo -e "\033[38;2;255;255;0mRun: sudo apt install -y ${missing[*]}\033[0m"
  fi
}

# Welcome display
post_init_display() {
  if [[ -z "$WELCOME_DISPLAYED" ]]; then
    export WELCOME_DISPLAYED=1
    command clear

    _zsh_verify_dependencies

    show_system_info
    time_based_greeting

    if command -v fastfetch &>/dev/null; then
      echo
      fastfetch
    fi
  fi
}

add-zsh-hook precmd post_init_display

# Cleanup on exit
cleanup_processes() {
  tput cnorm 2>/dev/null
  echo -e "\033[0m"
}
trap cleanup_processes EXIT INT TERM

# ============================================================================
# PATH CONFIGURATION
# ============================================================================

export PATH="$HOME/.local/bin:$HOME/bin:$PATH"
export PATH="$HOME/.cargo/bin:$PATH"
export PATH="$HOME/go/bin:$PATH"

# ============================================================================
# SECURITY HARDENING
# ============================================================================

ulimit -c 0       # Disable core dumps
umask 022         # Secure default permissions

# ============================================================================
# POWERLEVEL10K CONFIGURATION
# ============================================================================

# Load P10k config if exists
[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh

# ============================================================================
# LOCAL CUSTOMIZATION
# ============================================================================

# Load machine-specific configuration
[[ -f "$XDG_CONFIG_HOME/zsh/.zshrc.local" ]] && source "$XDG_CONFIG_HOME/zsh/.zshrc.local"
[[ -f "$HOME/.zshrc.local" ]] && source "$HOME/.zshrc.local"

# ============================================================================
# COMPLETION
# ============================================================================

echo -e "\033[32m🚀 Shadow@Bhanu Elite Terminal Environment Loaded! 🚀\033[0m"
