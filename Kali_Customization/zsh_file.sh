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
typeset -g POWERLEVEL9K_INSTANT_PROMPT=quiet
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
export ZSH_COMPCACHE_DIR="$XDG_CACHE_HOME/zsh/completion"

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
unsetopt CORRECT_ALL

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

  zinit ice lucid wait'0'; zinit light zsh-users/zsh-autosuggestions
  zinit ice lucid wait'0'; zinit light zsh-users/zsh-history-substring-search

  # Load productivity plugins
  zinit ice lucid wait'0'; zinit light Aloxaf/fzf-tab
  zinit ice lucid wait'0'; zinit light MichaelAquilina/zsh-auto-notify
  zinit ice lucid wait'0'; zinit light MichaelAquilina/zsh-you-should-use

  # Must be loaded last
  zinit ice lucid wait'0'; zinit light zsh-users/zsh-syntax-highlighting

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

# === MATRIX RAIN - NEURAL CASCADE ===
matrix_rain() {
    setopt localoptions localtraps ksharrays
    trap 'tput cnorm 2>/dev/null; stty echo 2>/dev/null' EXIT INT TERM

    # === PARAMETER PARSING ===
    local duration=${1:-5}
    local density=${2:-50}  # 0-100 scale
    local theme=${3:-matrix}  # matrix, cyber, blood, ice, fire
    local charset=${4:-katakana}  # katakana, binary, hex, ascii, custom
    local show_fps=${5:-false}  # Performance monitoring

    # === TERMINAL VALIDATION ===
    if ! command -v tput &>/dev/null; then
        echo "❌ Terminal not supported for matrix effect"
        return 1
    fi

    local width=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
    local height=${LINES:-$(tput lines 2>/dev/null || echo 24)}
    
    # Clamp dimensions
    width=$((width > 0 && width < 500 ? width : 80))
    height=$((height > 0 && height < 200 ? height : 24))

    # === CHARACTER SET SELECTION ===
    local chars
    case "$charset" in
        katakana)
            chars="ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ日ﾊﾐﾋ"
            ;;
        binary)
            chars="01010101010101010101"
            ;;
        hex)
            chars="0123456789ABCDEF"
            ;;
        ascii)
            chars="!@#$%^&*()_+-=[]{}|;:,.<>?/~\`"
            ;;
        dna)
            chars="ATCGATCGATCGATCG"
            ;;
        *)
            chars="$charset"  # Custom charset
            ;;
    esac
    local num_chars=${#chars}

    # === COLOR THEME SELECTION ===
    local -a colors
    case "$theme" in
        matrix)
            colors=(
                "38;2;0;255;0"      # Bright green
                "38;2;0;220;0"
                "38;2;0;180;0"
                "38;2;0;140;0"
                "38;2;0;100;0"
                "38;2;0;60;0"
                "38;2;0;30;0"       # Fade to black
            )
            ;;
        cyber)
            colors=(
                "38;2;0;255;255"    # Cyan
                "38;2;255;0;255"    # Magenta
                "38;2;0;191;255"
                "38;2;138;43;226"
                "38;2;75;0;130"
                "38;2;50;0;90"
            )
            ;;
        blood)
            colors=(
                "38;2;255;0;0"      # Bright red
                "38;2;220;0;0"
                "38;2;180;0;0"
                "38;2;140;0;0"
                "38;2;100;0;0"
                "38;2;60;0;0"
            )
            ;;
        ice)
            colors=(
                "38;2;173;216;230"  # Light blue
                "38;2;135;206;250"
                "38;2;100;149;237"
                "38;2;70;130;180"
                "38;2;25;25;112"
            )
            ;;
        fire)
            colors=(
                "38;2;255;255;0"    # Yellow
                "38;2;255;165;0"    # Orange
                "38;2;255;69;0"     # Red-orange
                "38;2;220;20;60"    # Crimson
                "38;2;139;0;0"      # Dark red
            )
            ;;
        *)
            colors=("38;2;255;255;255")  # White fallback
            ;;
    esac
    local num_colors=${#colors[@]}

    # === COLUMN INITIALIZATION ===
    declare -a columns lengths speeds intensities
    local active_columns=$((width * density / 100))
    [[ $active_columns -lt 1 ]] && active_columns=1

    for ((i=0; i<width; i++)); do
        if [[ $i -lt $active_columns ]]; then
            columns[$i]=$(( -(RANDOM % height) ))  # Staggered start
            lengths[$i]=$((RANDOM % (height / 2) + height / 4))
            speeds[$i]=$((RANDOM % 3 + 1))
            intensities[$i]=$((RANDOM % 100))  # Brightness variation
        else
            columns[$i]=-9999  # Inactive column marker
        fi
    done

    # === TERMINAL SETUP ===
    tput civis 2>/dev/null
    stty -echo 2>/dev/null
    printf "\033[2J\033[H\033[?25l"

    # === PERFORMANCE TRACKING ===
    local frame_count=0
    local start_time=$(date +%s%N 2>/dev/null || echo $(($(date +%s) * 1000000000)))
    local end_time=$(($(date +%s) + duration))
    local last_fps_time=$start_time
    local fps=0

    # === MAIN RENDER LOOP ===
    while [[ $(date +%s) -lt $end_time ]]; do
        local frame_buffer=""
        ((frame_count++))

        # Performance: Only clear every 10 frames to reduce flicker
        if [[ $((frame_count % 10)) -eq 0 ]]; then
            frame_buffer+="\033[2J"
        fi

        # === RENDER ALL COLUMNS ===
        for ((i=0; i<width; i++)); do
            [[ ${columns[$i]} -eq -9999 ]] && continue  # Skip inactive

            local col_pos=${columns[$i]}
            local col_len=${lengths[$i]}
            local col_speed=${speeds[$i]}

            # Only render visible portions
            if [[ $((col_pos - col_len)) -lt height ]]; then
                
                # === DRAW TRAILING CHARACTERS ===
                for ((j=0; j<col_len; j++)); do
                    local y_pos=$((col_pos - j))
                    
                    if [[ y_pos -ge 0 && y_pos -lt height ]]; then
                        # Color gradient calculation
                        local color_idx=$(( (j * (num_colors - 1)) / col_len ))
                        color_idx=$((color_idx >= num_colors ? num_colors - 1 : color_idx))
                        
                        # Dynamic character selection with animation
                        local char_idx=$(( (y_pos + i + frame_count) % num_chars ))
                        
                        # Intensity-based brightness (1=bold, 0=dim)
                        local brightness=$((intensities[i] > 50 ? 1 : 2))
                        
                        frame_buffer+="\033[$((y_pos + 1));$((i + 1))H\033[${brightness};${colors[$color_idx]}m${chars:$char_idx:1}"
                    fi
                done

                # === DRAW BRIGHT LEADING CHARACTER ===
                if [[ col_pos -ge 0 && col_pos -lt height ]]; then
                    local lead_char=$(( (col_pos + i + frame_count * 2) % num_chars ))
                    frame_buffer+="\033[$((col_pos + 1));$((i + 1))H\033[1;${colors[0]}m${chars:$lead_char:1}"
                fi

                # === UPDATE COLUMN POSITION ===
                columns[$i]=$((col_pos + col_speed))

                # === RESET WHEN OFF-SCREEN ===
                if [[ $((col_pos - col_len)) -ge height ]]; then
                    columns[$i]=$(( -(RANDOM % (height / 2)) ))
                    lengths[$i]=$((RANDOM % (height / 2) + height / 4))
                    speeds[$i]=$((RANDOM % 3 + 1))
                    intensities[$i]=$((RANDOM % 100))
                fi
            fi
        done

        # === FPS COUNTER (OPTIONAL) ===
        if [[ "$show_fps" == "true" ]]; then
            local current_time=$(date +%s%N 2>/dev/null || echo $(($(date +%s) * 1000000000)))
            local time_diff=$(( (current_time - last_fps_time) / 1000000 ))  # Convert to ms
            
            if [[ $time_diff -gt 1000 ]]; then  # Update FPS every second
                fps=$((frame_count * 1000 / time_diff))
                last_fps_time=$current_time
                frame_count=0
            fi
            
            frame_buffer+="\033[1;1H\033[38;2;255;255;0m FPS: $fps \033[0m"
        fi

        # === FLUSH FRAME BUFFER ===
        printf "%b" "$frame_buffer\033[0m"
        
        # Adaptive sleep based on target FPS (aim for 25 FPS)
        sleep 0.04
    done

    # === CLEANUP ===
    tput cnorm 2>/dev/null
    stty echo 2>/dev/null
    printf "\033[2J\033[H\033[?25h\033[0m"
}

# === WRAPPER FUNCTIONS FOR EASY USE ===
matrix() { matrix_rain "${1:-5}" "${2:-50}" "${3:-matrix}" "${4:-katakana}" "${5:-false}"; }
matrix_cyber() { matrix_rain "${1:-5}" 70 "cyber" "hex" "false"; }
matrix_blood() { matrix_rain "${1:-5}" 60 "blood" "binary" "false"; }
matrix_screensaver() {
    echo -e "\033[38;2;0;255;0m🔋 Neural Cascade Screensaver Activated\033[0m"
    matrix_rain "${1:-30}" 80 "matrix" "katakana" "true"
    echo -e "\033[38;2;0;255;0m✅ Screensaver Deactivated\033[0m"
}

# === BENCHMARK MODE ===
matrix_benchmark() {
    echo "🔬 Matrix Benchmark Mode - Testing Performance..."
    local start=$(date +%s)
    matrix_rain 10 100 "matrix" "katakana" "true"
    local end=$(date +%s)
    echo "⏱️  Total time: $((end - start))s"
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

# === LOADING ANIMATION 2.0 - PROGRESS NEXUS ===
loading_animation() {
    local message="${1:-⚡ Initializing Shadow Systems}"
    local duration=${2:-2.0}
    local callback_function="${3:-}"
    local style="${4:-matrix}"
    local show_eta="${5:-true}"

    local width=50
    local steps=100

    # Calculate step duration (ms precision)
    local duration_int=${duration%.*}
    local duration_frac=${duration#*.}
    [[ "$duration_frac" == "$duration" ]] && duration_frac=0
    local total_ms=$(( (duration_int * 1000) + (duration_frac * 100) ))
    local step_ms=$((total_ms / steps))
    [[ $step_ms -lt 10 ]] && step_ms=10

    # === CHARACTER SET SELECTION ===
    local chars
    case "$style" in
        matrix)   chars="▓▒░▓▒░▓▒░" ;;
        wave)     chars="∿∾∽∼∽∾∿" ;;
        pulse)    chars="●◐◑◒◓◔◕◖" ;;
        scan)     chars="▁▂▃▄▅▆▇█" ;;
        arrows)   chars="→⇒➔➜➙➛" ;;
        dots)     chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" ;;
        blocks)   chars="▖▘▝▗▚▞█" ;;
        fire)     chars="🔥💥⚡✨" ;;
        *)        chars="━" ;;
    esac

    # === COLOR GRADIENTS ===
    local -a gradient
    case "$style" in
        matrix)
            gradient=(
                "38;2;0;255;0"
                "38;2;0;220;0"
                "38;2;0;180;0"
                "38;2;0;140;0"
            )
            ;;
        cyber)
            gradient=(
                "38;2;0;255;255"
                "38;2;255;0;255"
                "38;2;255;255;0"
            )
            ;;
        *)
            gradient=(
                "38;2;100;200;255"
                "38;2;150;100;255"
                "38;2;255;100;200"
            )
            ;;
    esac

    # === HEADER MESSAGE ===
    local msg_color="${gradient[0]}"
    echo -e "\033[${msg_color};1m$message\033[0m"

    local start_time=$(date +%s)

    # === MAIN PROGRESS LOOP ===
    for ((i=0; i<=steps; i++)); do
        local progress=$((i * 100 / steps))
        local filled=$((i * width / steps))
        local empty=$((width - filled))

        # Dynamic color based on progress
        local color_idx=$((i * ${#gradient[@]} / steps))
        [[ $color_idx -ge ${#gradient[@]} ]] && color_idx=$((${#gradient[@]} - 1))
        local color="${gradient[$color_idx]}"

        # Spinner animation
        local spinner_idx=$((i % ${#chars}))
        local spinner="${chars:$spinner_idx:1}"

        # Calculate ETA
        local eta_text=""
        if [[ "$show_eta" == "true" && $i -gt 5 ]]; then
            local elapsed=$(($(date +%s) - start_time))
            local rate=$((i > 0 ? i : 1))
            local remaining=$(( (steps - i) * elapsed / rate ))
            eta_text=" ETA: ${remaining}s"
        fi

        # Build progress bar
        printf "\r\033[${color}m[$spinner] ["

        # Filled portion with animated characters
        for ((j=0; j<filled; j++)); do
            local char_idx=$(( (j + i) % ${#chars} ))
            printf "${chars:$char_idx:1}"
        done

        # Empty portion
        for ((j=0; j<empty; j++)); do
            printf "░"
        done

        printf "] %3d%%%s\033[0m" "$progress" "$eta_text"

        # Execute callback at specific milestones
        if [[ -n "$callback_function" ]] && declare -f "$callback_function" >/dev/null 2>&1; then
            # Call on 25%, 50%, 75%, 100%
            if [[ $((progress % 25)) -eq 0 ]] || [[ $progress -eq 100 ]]; then
                "$callback_function" "$progress" 2>/dev/null &
            fi
        fi

        # Adaptive sleep
        sleep $(printf "0.%03d" $step_ms)
    done

    printf "\r\033[K"
    echo -e "\033[38;2;0;255;0m✅ Complete\033[0m"
}

# === MULTI-STAGE LOADING ===
loading_multi_stage() {
    local -a stages=("$@")
    local total_stages=${#stages[@]}
    
    for ((i=0; i<total_stages; i++)); do
        local stage_name="${stages[$i]}"
        local stage_duration=$((2 + RANDOM % 3))
        
        echo -e "\n\033[38;2;255;255;0m━━━ Stage $((i+1))/$total_stages: $stage_name ━━━\033[0m"
        loading_animation "$stage_name" "$stage_duration" "" "matrix" "true"
        sleep 0.5
    done
    
    echo -e "\n\033[38;2;0;255;0m🎯 All stages completed successfully!\033[0m"
}

# === BACKGROUND LOADING WITH PID TRACKING ===
loading_background() {
    local message="$1"
    local command="$2"
    local pid_file="/tmp/loading_$$.pid"
    
    # Start spinner in background
    {
        local i=0
        local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        while kill -0 $$ 2>/dev/null; do
            local spinner="${chars:$((i % ${#chars})):1}"
            printf "\r\033[38;2;0;255;255m[$spinner] %s\033[0m" "$message"
            ((i++))
            sleep 0.1
        done
    } &
    local spinner_pid=$!
    echo $spinner_pid > "$pid_file"
    
    # Execute the actual command
    eval "$command"
    local exit_code=$?
    
    # Stop spinner
    kill $spinner_pid 2>/dev/null
    wait $spinner_pid 2>/dev/null
    rm -f "$pid_file"
    
    printf "\r\033[K"
    if [[ $exit_code -eq 0 ]]; then
        echo -e "\033[38;2;0;255;0m✅ $message - Success\033[0m"
    else
        echo -e "\033[38;2;255;0;0m❌ $message - Failed (code: $exit_code)\033[0m"
    fi
    
    return $exit_code
}

# === EXAMPLE USAGE ===
# loading_animation "Scanning network..." 3 "" "scan" "true"
# loading_multi_stage "Database init" "API warmup" "Cache build" "Security check"
# loading_background "Downloading payload..." "curl -O https://example.com/file.zip"

# Efficiently calculates CPU usage from /proc/stat to avoid expensive 'top' calls.

# === CPU MONITOR 2.0 - NEURAL METRICS ===

# Global cache for historical data
typeset -g -A _ZSH_CPU_HISTORY
typeset -g -a _ZSH_CPU_TIMESTAMPS

_zsh_init_cpu_monitor() {
    mkdir -p "$XDG_CACHE_HOME/zsh"
    _ZSH_CPU_HISTORY=()
    _ZSH_CPU_TIMESTAMPS=()
}

# === ENHANCED CPU USAGE CALCULATOR ===
_zsh_get_cpu_usage() {
    local mode="${1:-total}"  # total, per-core, detailed
    local stat_file="$XDG_CACHE_HOME/zsh/cpu_last_stat"
    
    # Read previous state
    local -a last_stat
    if [[ -f "$stat_file" ]]; then
        last_stat=($(<"$stat_file"))
    else
        last_stat=(0 0 0 0 0 0 0 0)
    fi

    # Read current state from /proc/stat
    local -a current_stat
    if [[ "$mode" == "per-core" ]]; then
        # Get all CPU cores
        current_stat=($(awk '/^cpu[0-9]+ / {print $2+$3+$4, $2+$3+$4+$5+$6+$7+$8}' /proc/stat))
    else
        # Total CPU only
        current_stat=($(awk '/^cpu / {print $2+$3+$4+$6+$7+$8, $2+$3+$4+$5+$6+$7+$8, $2, $4, $5, $6, $7, $8}' /proc/stat))
    fi

    # Save current state
    echo "${current_stat[@]}" > "$stat_file"

    # Calculate usage
    if [[ "$mode" == "detailed" ]]; then
        # Detailed breakdown: user, system, idle, iowait, irq, softirq
        local delta_total=$((current_stat[1] - last_stat[1]))
        if [[ $delta_total -gt 0 ]]; then
            local user_pct=$(( (current_stat[2] - last_stat[2]) * 100 / delta_total ))
            local system_pct=$(( (current_stat[3] - last_stat[3]) * 100 / delta_total ))
            local idle_pct=$(( (current_stat[4] - last_stat[4]) * 100 / delta_total ))
            local iowait_pct=$(( (current_stat[5] - last_stat[5]) * 100 / delta_total ))
            local irq_pct=$(( (current_stat[6] - last_stat[6]) * 100 / delta_total ))
            local softirq_pct=$(( (current_stat[7] - last_stat[7]) * 100 / delta_total ))
            
            echo "user:$user_pct system:$system_pct idle:$idle_pct iowait:$iowait_pct irq:$irq_pct softirq:$softirq_pct"
        else
            echo "user:0 system:0 idle:100 iowait:0 irq:0 softirq:0"
        fi
    elif [[ "$mode" == "per-core" ]]; then
        # Per-core usage
        local num_cores=$((${#current_stat[@]} / 2))
        local core_usages=()
        
        for ((i=0; i<num_cores; i++)); do
            local idx=$((i * 2))
            local delta_total=$((current_stat[$((idx + 1))] - last_stat[$((idx + 1))]))
            local delta_busy=$((current_stat[$idx] - last_stat[$idx]))
            
            if [[ $delta_total -gt 0 ]]; then
                local core_usage=$((delta_busy * 100 / delta_total))
                core_usages+=("$core_usage")
            else
                core_usages+=("0")
            fi
        done
        
        echo "${core_usages[@]}"
    else
        # Total CPU usage (backward compatible)
        local delta_total=$((current_stat[1] - last_stat[1]))
        local delta_busy=$((current_stat[0] - last_stat[0]))

        if [[ $delta_total -gt 0 ]]; then
            printf "%.1f" $(echo "$delta_busy $delta_total" | awk '{print 100 * $1 / $2}')
        else
            echo "0.0"
        fi
    fi
}

# === CPU TEMPERATURE MONITOR ===
_zsh_get_cpu_temp() {
    # Try multiple temperature sources
    if command -v sensors &>/dev/null; then
        sensors 2>/dev/null | awk '/^Core 0:/ {print $3}' | tr -d '+°C' | head -1
    elif [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
        local temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
        echo $(( temp / 1000 ))
    else
        echo "N/A"
    fi
}

# === TOP CPU PROCESSES ===
_zsh_get_top_cpu_processes() {
    local count="${1:-3}"
    ps aux --sort=-%cpu | awk 'NR>1 {printf "%s:%.1f ", $11, $3}' | head -n $count
}

# === CPU FREQUENCY ===
_zsh_get_cpu_freq() {
    if [[ -f /proc/cpuinfo ]]; then
        awk '/^cpu MHz/ {sum+=$4; count++} END {if(count>0) printf "%.0f", sum/count}' /proc/cpuinfo
    else
        echo "N/A"
    fi
}

# === ASCII GRAPH GENERATOR ===
_zsh_generate_cpu_graph() {
    local -a history=("$@")
    local max_height=10
    local max_val=100
    local graph=""

    # Normalize values and create bars
    for val in "${history[@]}"; do
        local bar_height=$(( (val * max_height) / max_val ))
        [[ $bar_height -gt max_height ]] && bar_height=$max_height
        
        # Color based on usage
        local color
        if [[ $val -gt 80 ]]; then
            color="38;2;255;0;0"  # Red
        elif [[ $val -gt 60 ]]; then
            color="38;2;255;165;0"  # Orange
        elif [[ $val -gt 40 ]]; then
            color="38;2;255;255;0"  # Yellow
        else
            color="38;2;0;255;0"  # Green
        fi
        
        # Build vertical bar
        local bar=""
        for ((i=0; i<bar_height; i++)); do
            bar="█$bar"
        done
        
        printf "\033[${color}m%-10s\033[0m " "$bar"
    done
    echo
}

# === COMPREHENSIVE CPU STATUS ===
cpu_status() {
    echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\033[38;2;255;255;0m          💀 NEURAL METRICS - CPU STATUS 💀\033[0m"
    echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    
    # Total usage
    local total_usage=$(_zsh_get_cpu_usage "total")
    echo -e "\033[38;2;0;255;0m🔋 Total CPU Usage:\033[0m $total_usage%"
    
    # Per-core usage
    echo -e "\033[38;2;0;255;0m⚡ Per-Core Usage:\033[0m"
    local -a core_usages=($(_zsh_get_cpu_usage "per-core"))
    for ((i=0; i<${#core_usages[@]}; i++)); do
        local usage=${core_usages[$i]}
        local bar=""
        local filled=$((usage / 5))  # Scale to 20 chars max
        
        for ((j=0; j<20; j++)); do
            if [[ $j -lt $filled ]]; then
                if [[ $usage -gt 80 ]]; then bar+="\033[38;2;255;0;0m█\033[0m"
                elif [[ $usage -gt 60 ]]; then bar+="\033[38;2;255;165;0m█\033[0m"
                else bar+="\033[38;2;0;255;0m█\033[0m"; fi
            else
                bar+="\033[38;2;50;50;50m░\033[0m"
            fi
        done
        
        printf "  Core %2d: [%b] %3d%%\n" "$i" "$bar" "$usage"
    done
    
    # Detailed breakdown
    echo -e "\n\033[38;2;0;255;0m📊 Breakdown:\033[0m"
    local detailed=$(_zsh_get_cpu_usage "detailed")
    echo "$detailed" | tr ' ' '\n' | while IFS=: read key val; do
        printf "  %-10s %3d%%\n" "$key:" "$val"
    done
    
    # Temperature
    local temp=$(_zsh_get_cpu_temp)
    if [[ "$temp" != "N/A" ]]; then
        local temp_color
        if [[ $temp -gt 80 ]]; then temp_color="38;2;255;0;0"
        elif [[ $temp -gt 70 ]]; then temp_color="38;2;255;165;0"
        else temp_color="38;2;0;255;0"; fi
        
        echo -e "\n\033[${temp_color}m🌡️  Temperature:\033[0m ${temp}°C"
    fi
    
    # Frequency
    local freq=$(_zsh_get_cpu_freq)
    [[ "$freq" != "N/A" ]] && echo -e "\033[38;2;0;255;255m⚡ Frequency:\033[0m ${freq} MHz"
    
    # Top processes
    echo -e "\n\033[38;2;255;255;0m🔥 Top CPU Consumers:\033[0m"
    ps aux --sort=-%cpu | awk 'NR>1 {printf "  %-20s %5.1f%%\n", $11, $3}' | head -5
    
    echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
}

# === LIVE CPU MONITOR WITH GRAPH ===
cpu_monitor_live() {
    local duration="${1:-30}"
    local sample_interval="${2:-1}"
    
    echo -e "\033[38;2;0;255;255m🔬 Live CPU Monitor - Press Ctrl+C to exit\033[0m\n"
    
    local -a history
    local end_time=$(($(date +%s) + duration))
    
    trap 'tput cnorm; echo -e "\n\033[38;2;0;255;0m✅ Monitor stopped\033[0m"; return' INT
    tput civis
    
    while [[ $(date +%s) -lt $end_time ]]; do
        local usage=$(_zsh_get_cpu_usage "total")
        history+=("${usage%.*}")  # Store integer part
        
        # Keep only last 30 samples
        [[ ${#history[@]} -gt 30 ]] && history=("${history[@]:1}")
        
        # Clear and redraw
        printf "\033[2J\033[H"
        echo -e "\033[38;2;255;255;0mCPU Usage History (last ${#history[@]} samples):\033[0m"
        _zsh_generate_cpu_graph "${history[@]}"
        echo -e "\n\033[38;2;0;255;0mCurrent: ${usage}%\033[0m"
        
        sleep $sample_interval
    done
    
    tput cnorm
    echo -e "\n\033[38;2;0;255;0m✅ Monitoring complete\033[0m"
}

# === ALIASES FOR EASY ACCESS ===
alias cpu='_zsh_get_cpu_usage'
alias cpu-detailed='_zsh_get_cpu_usage detailed'
alias cpu-cores='_zsh_get_cpu_usage per-core'
alias cpu-temp='_zsh_get_cpu_temp'
alias cpu-live='cpu_monitor_live'

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
bindkey '^I' expand-or-complete  # Ensure Tab triggers completion

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
alias kubectl='minikube kubectl --'

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
alias apt='nocorrect apt'
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

# === CHMOD FIX (use system chmod for symbolic modes) ===
alias chmod='command chmod'

# Load local configuration
[[ -f "$HOME/.zshrc.local" ]] && source "$HOME/.zshrc.local"

# pnpm
export PNPM_HOME="/home/bhanu/.local/share/pnpm"
case ":$PATH:" in
  *":$PNPM_HOME:"*) ;;
  *) export PATH="$PNPM_HOME:$PATH" ;;
esac
# pnpm end
