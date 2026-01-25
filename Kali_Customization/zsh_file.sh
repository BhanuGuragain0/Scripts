#!/usr/bin/env zsh
# ═══════════════════════════════════════════════════════════════════════════
# 🚀 Shadow@Bhanu Elite Terminal Environment v4.0 ULTIMATE HYBRID 🚀
# ═══════════════════════════════════════════════════════════════════════════
#
# Author: Bhanu Guragain (Shadow Junior)
# Version: 4.0 ULTIMATE HYBRID
# Date: 2026-01-26
# Repository: https://github.com/BhanuGuragain0/Scripts

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: MASTER CONFIGURATION TOGGLES
# ═══════════════════════════════════════════════════════════════════════════

# === Core AI & Intelligence ===
typeset -g ENABLE_AI_ENGINE=true
typeset -g ENABLE_AI_NLC=true              # Natural language commands
typeset -g ENABLE_AI_PREDICTIONS=true      # Workflow predictions

# === Visuals & Effects ===
typeset -g ENABLE_MATRIX_ON_CLEAR=true     # Matrix rain effect
typeset -g ENABLE_GREETING_BANNER=true     # Startup banner
typeset -g ENABLE_NERD_FONTS=true          # Icon system

# === Security & Monitoring ===
typeset -g ENABLE_SECURITY_HUD=true        # Real-time threat monitoring
typeset -g ENABLE_INTRUSION_DETECTION=true # Active threat detection
typeset -g ENABLE_FILE_INTEGRITY=true      # Integrity checks

# === Operational Context ===
typeset -g ENABLE_OP_CONTEXT=true          # Target management
typeset -g ENABLE_THREAT_INTEL=true        # CVE fetching

# === NEW: Extended Operational Features ===
typeset -g ENABLE_CLOUD_MONITORING=true    # AWS/Azure/GCP/Docker/K8s
typeset -g ENABLE_ADVANCED_CPU=true        # Advanced CPU monitoring
typeset -g ENABLE_LIVE_DASHBOARD=true      # Live monitoring dashboard

# === Network & Privacy ===
typeset -g ENABLE_PUBLIC_IP_LOOKUP=false   # Disable in high-privacy envs

# === Performance ===
typeset -g ENABLE_ASYNC_LOADING=true       # Async plugin loading
typeset -g ENABLE_CACHE_SYSTEM=true        # Function result caching

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: CORE ENVIRONMENT SETUP
# ═══════════════════════════════════════════════════════════════════════════

# Editor & Tools
export EDITOR="nvim"
export VISUAL="nvim"
export PAGER="less"
export BROWSER="firefox"
export MANPAGER="sh -c 'col -bx | bat -l man -p'"

# XDG Base Directory Specification
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"

# Terminal Configuration
export TERM="xterm-256color"
export COLORTERM="truecolor"
export LANG="en_US.UTF-8"
export LC_ALL="en_US.UTF-8"

# Zsh-specific directories
export ZSH_COMPCACHE_DIR="$XDG_CACHE_HOME/zsh/completion"
export HISTFILE="$XDG_STATE_HOME/zsh/history"
export HISTSIZE=100000
export SAVEHIST=100000
export LESSHISTFILE="-"

# Session tracking
export TERMINAL_SESSION_FILE="$XDG_STATE_HOME/zsh/session_tracker"

# Create necessary directories
[[ -d "$XDG_STATE_HOME/zsh" ]] || mkdir -p "$XDG_STATE_HOME/zsh"
[[ -d "$XDG_CACHE_HOME/zsh" ]] || mkdir -p "$XDG_CACHE_HOME/zsh"
[[ -d "$ZSH_COMPCACHE_DIR" ]] || mkdir -p "$ZSH_COMPCACHE_DIR"

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: ZSH OPTIONS (PERFORMANCE + FEATURES)
# ═══════════════════════════════════════════════════════════════════════════

# Performance Optimizations
setopt NO_HASH_CMDS
setopt NO_BEEP
setopt INTERACTIVE_COMMENTS
setopt PROMPT_SUBST
setopt TRANSIENT_RPROMPT
setopt COMBINING_CHARS
setopt MULTIBYTE

# History Management
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

# Directory Navigation
setopt AUTO_CD
setopt AUTO_PUSHD
setopt PUSHD_IGNORE_DUPS
setopt PUSHD_MINUS
setopt PUSHD_SILENT

# Completion System
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

# Job Control
setopt LONG_LIST_JOBS
setopt AUTO_RESUME
setopt NOTIFY
setopt CHECK_JOBS
setopt HUP

# Input/Output
setopt ALIASES
setopt CLOBBER
setopt PRINT_EXIT_VALUE

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: MODULE SYSTEM (LAZY LOADING)
# ═══════════════════════════════════════════════════════════════════════════

typeset -ga _ZSH_LOADED_MODULES=()

zsh_load_module() {
  local module=$1
  if [[ ! " ${_ZSH_LOADED_MODULES[@]} " =~ " ${module} " ]]; then
    zmodload "$module" 2>/dev/null && _ZSH_LOADED_MODULES+=("$module")
  fi
}

# Load essential modules immediately
zsh_load_module zsh/datetime
zsh_load_module zsh/mathfunc

# Lazy-load expensive modules
autoload -Uz zmv

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: POWERLEVEL10K INSTANT PROMPT
# ═══════════════════════════════════════════════════════════════════════════

typeset -g POWERLEVEL9K_INSTANT_PROMPT=quiet
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: ZINIT PLUGIN MANAGER
# ═══════════════════════════════════════════════════════════════════════════

ZINIT_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}/zinit/zinit.git"

if [[ ! -d "$ZINIT_HOME" ]]; then
  mkdir -p "$(dirname $ZINIT_HOME)"
  git clone https://github.com/zdharma-continuum/zinit.git "$ZINIT_HOME"
fi

source "${ZINIT_HOME}/zinit.zsh"
zinit light romkatv/powerlevel10k

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: LAZY-LOADED PLUGINS (ASYNC)
# ═══════════════════════════════════════════════════════════════════════════

_zsh_lazy_load_plugins() {
  precmd_functions=(${precmd_functions#_zsh_lazy_load_plugins})

  if [[ "$ENABLE_ASYNC_LOADING" != true ]]; then
    return
  fi

  zinit ice lucid wait'0' \
    atload'zstyle ":completion:*" use-cache on; zstyle ":completion:*" cache-path "$ZSH_COMPCACHE_DIR";' \
    atinit'zicompinit; zicdreplay'
  zinit light zsh-users/zsh-completions

  zinit ice lucid wait'0'; zinit light zsh-users/zsh-autosuggestions
  zinit ice lucid wait'0'; zinit light zsh-users/zsh-history-substring-search
  zinit ice lucid wait'0'; zinit light Aloxaf/fzf-tab
  zinit ice lucid wait'0'; zinit light MichaelAquilina/zsh-auto-notify
  zinit ice lucid wait'0'; zinit light MichaelAquilina/zsh-you-should-use
  zinit ice lucid wait'0'; zinit light zdharma-continuum/fast-syntax-highlighting
  zinit ice lucid wait'0'; zinit light agkozak/zsh-z
  zinit ice lucid wait'0'; zinit light hlissner/zsh-autopair
  zinit ice lucid wait'0'; zinit light ael-code/zsh-colored-man-pages
}

precmd_functions+=(_zsh_lazy_load_plugins)

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: COMPLETION SYSTEM (OPTIMIZED)
# ═══════════════════════════════════════════════════════════════════════════

autoload -Uz compinit
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

zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#)*=0=01;31'
zstyle ':completion:*:kill:*' command 'ps -u $USER -o pid,%cpu,tty,cputime,cmd'

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9: COLOR SYSTEM (NERD FONTS + THEMES)
# ═══════════════════════════════════════════════════════════════════════════

typeset -ga ZSH_COLOR_PALETTE=(
  "38;2;0;255;255"      # Quantum Cyan
  "38;2;255;0;255"      # Neural Magenta
  "38;2;0;255;0"        # Matrix Green
  "38;2;255;0;0"        # Alert Red
  "38;2;255;165;0"      # Warning Orange
  "38;2;138;43;226"     # Elite Purple
  "38;2;0;191;255"      # Electric Blue
  "38;2;255;215;0"      # Champion Gold
  "38;2;255;255;0"      # Plasma Yellow
  "38;2;127;255;0"      # Laser Lime
)

typeset -gA ZSH_THEME_PROFILES=(
  [stealth]="38;2;20;20;30"
  [matrix]="38;2;0;255;0"
  [cyber]="38;2;0;255;255"
  [blood]="38;2;255;0;0"
  [purple]="38;2;138;43;226"
  [gold]="38;2;255;215;0"
)

typeset -g ZSH_ACTIVE_THEME="cyber"

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10: NERD FONT ICON SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

typeset -gA ZSH_ICONS=(
  [cpu]=""        [memory]=""     [disk]=""       [network]="󰈀"
  [time]=""       [calendar]=""   [battery]=""    [temperature]=""
  [shield]=""     [lock]=""       [key]=""        [warning]=""
  [alert]=""      [check]=""      [error]=""      [success]=""
  [git]=""        [branch]=""     [docker]=""     [kubernetes]="󱃾"
  [python]=""     [nodejs]=""     [rust]=""       [go]=""
  [java]=""       [cpp]=""        [bash]=""       [terminal]=""
  [folder]=""     [file]=""       [home]=""       [root]=""
  [download]=""   [upload]=""
  [info]=""       [question]=""   [loading]=""    [done]=""
  [target]="🎯"   [exploit]="💥"   [pwned]="💀"     [recon]="🔍"
  [payload]="🚀"  [shell]=""      [scan]=""
)

icon() {
  [[ "$ENABLE_NERD_FONTS" != true ]] && return
  local name=$1
  echo -n "${ZSH_ICONS[$name]:-}"
}

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 11: CORE UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

threat_color() {
  local level=${1:-3}
  case $level in
    0) echo "38;2;255;0;0"     ;;
    1) echo "38;2;255;165;0"   ;;
    2) echo "38;2;255;255;0"   ;;
    3) echo "38;2;0;255;0"     ;;
    4) echo "38;2;0;191;255"   ;;
    *) echo "38;2;255;255;255" ;;
  esac
}

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

random_color() {
  if [[ ${#ZSH_COLOR_PALETTE[@]} -eq 0 ]]; then
    echo "38;2;255;255;255"
    return
  fi
  echo "${ZSH_COLOR_PALETTE[$((RANDOM % ${#ZSH_COLOR_PALETTE[@]} + 1))]}"
}

gradient_text() {
  local text="$1"
  local len=${#text}
  
  if [[ $len -le 1 ]]; then
    local color=$(random_color)
    echo -e "\033[${color}m${text}\033[0m"
    return
  fi
  
  local output=""
  for ((i=0; i<len; i++)); do
    local char="${text:$i:1}"
    local r=$((255 - (i * 255 / (len - 1))))
    local g=$((i * 255 / (len - 1)))
    local b=$((127 + (i * 128 / (len - 1))))
    
    r=$(( r < 0 ? 0 : (r > 255 ? 255 : r) ))
    g=$(( g < 0 ? 0 : (g > 255 ? 255 : g) ))
    b=$(( b < 0 ? 0 : (b > 255 ? 255 : b) ))
    
    output+="\033[38;2;${r};${g};${b}m${char}\033[0m"
  done
  echo -e "$output"
}

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

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

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

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 12: ANIMATION SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

loading_animation() {
  local message="${1:-⚡ Initializing Shadow Systems}"
  local duration=${2:-2.0}
  local callback_function="${3:-}"
  local style="${4:-matrix}"
  local show_eta="${5:-false}"

  local width=50
  local steps=100
  
  local duration_int=${duration%.*}
  local duration_frac=${duration#*.}
  [[ "$duration_frac" == "$duration" ]] && duration_frac=0
  local total_ms=$(( (duration_int * 1000) + (duration_frac * 100) ))
  local step_ms=$((total_ms / steps))
  [[ $step_ms -lt 10 ]] && step_ms=10

  local chars
  case "$style" in
    matrix)   chars="▓▒░▓▒░▓▒░" ;;
    wave)     chars="∿∾∽∼∽∾∿" ;;
    pulse)    chars="◉◎◑◒◓◔◕◖" ;;
    scan)     chars="▁▂▃▄▅▆▇█" ;;
    fire)     chars="🔥💥⚡✨" ;;
    *)        chars="⣾⣽⣻⢿⡿⣟⣯⣷" ;;
  esac

  local -a gradient=(
    "38;2;0;255;0"
    "38;2;0;220;0"
    "38;2;0;180;0"
    "38;2;0;140;0"
  )

  local msg_color="${gradient[0]}"
  echo -e "\033[${msg_color};1m$message\033[0m"

  local start_time=$(date +%s)

  for ((i=0; i<=steps; i++)); do
    local progress=$((i * 100 / steps))
    local filled=$((i * width / steps))
    local empty=$((width - filled))

    local color_idx=$((i * ${#gradient[@]} / steps))
    [[ $color_idx -ge ${#gradient[@]} ]] && color_idx=$((${#gradient[@]} - 1))
    local color="${gradient[$color_idx]}"

    local spinner_idx=$((i % ${#chars}))
    local spinner="${chars:$spinner_idx:1}"

    local eta_text=""
    if [[ "$show_eta" == "true" && $i -gt 5 ]]; then
      local elapsed=$(($(date +%s) - start_time))
      local rate=$((i > 0 ? i : 1))
      local remaining=$(( (steps - i) * elapsed / rate ))
      eta_text=" ETA: ${remaining}s"
    fi

    printf "\r\033[${color}m[$spinner] ["
    for ((j=0; j<filled; j++)); do
      local char_idx=$(( (j + i) % ${#chars} ))
      printf "${chars:$char_idx:1}"
    done
    for ((j=0; j<empty; j++)); do
      printf "░"
    done
    printf "] %3d%%%s\033[0m" "$progress" "$eta_text"

    if [[ -n "$callback_function" ]] && declare -f "$callback_function" >/dev/null 2>&1; then
      if [[ $((progress % 25)) -eq 0 ]] || [[ $progress -eq 100 ]]; then
        "$callback_function" "$progress" 2>/dev/null &
      fi
    fi

    sleep $(printf "0.%03d" $step_ms)
  done

  printf "\r\033[K"
  echo -e "\033[38;2;0;255;0m✅ Complete\033[0m"
}

# Multi-stage loading
loading_multi_stage() {
  local -a stages=("$@")
  local total_stages=${#stages[@]}
  
  for ((i=0; i<total_stages; i++)); do
    local stage_name="${stages[$i]}"
    local stage_duration=$((2 + RANDOM % 3))
    
    echo -e "\n\033[38;2;255;255;0m┏━━ Stage $((i+1))/$total_stages: $stage_name ━━┓\033[0m"
    loading_animation "$stage_name" "$stage_duration" "" "matrix" "true"
    sleep 0.5
  done
  
  echo -e "\n\033[38;2;0;255;0m🎯 All stages completed successfully!\033[0m"
}

# Background loading with PID tracking
loading_background() {
  local message="$1"
  local command="$2"
  local pid_file="/tmp/loading_$$.pid"
  
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
  
  eval "$command"
  local exit_code=$?
  
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

matrix_rain() {
  setopt localoptions localtraps ksharrays
  trap 'tput cnorm 2>/dev/null; stty echo 2>/dev/null; printf "\033[0m\033[?25h"' EXIT INT TERM

  local duration=${1:-5}
  local density=${2:-50}
  local theme=${3:-matrix}
  local charset=${4:-katakana}
  local show_fps=${5:-false}

  if ! command -v tput &>/dev/null; then
    echo "⚠️ Terminal not supported for matrix effect"
    return 1
  fi

  local width=$(tput cols 2>/dev/null)
  local height=$(tput lines 2>/dev/null)
  
  if [[ -z "$width" || -z "$height" || "$width" -lt 10 || "$height" -lt 10 ]]; then
    echo "⚠️ Terminal dimensions invalid: ${width}x${height}"
    return 1
  fi
  
  width=$((width > 500 ? 500 : width))
  height=$((height > 200 ? 200 : height))

  local chars
  case "$charset" in
    katakana) chars="ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜｦﾝ日ｱｲｳ" ;;
    binary)   chars="01010101010101010101" ;;
    hex)      chars="0123456789ABCDEF" ;;
    ascii)    chars="!@#$%^&*()_+-=[]{}|;:,.<>?/~\`" ;;
    dna)      chars="ATCGATCGATCGATCG" ;;
    *)        chars="$charset" ;;
  esac
  local num_chars=${#chars}

  local -a colors
  case "$theme" in
    matrix)
      colors=("38;2;0;255;0" "38;2;0;220;0" "38;2;0;180;0" "38;2;0;140;0" "38;2;0;100;0" "38;2;0;60;0" "38;2;0;30;0")
      ;;
    cyber)
      colors=("38;2;0;255;255" "38;2;255;0;255" "38;2;0;191;255" "38;2;138;43;226" "38;2;75;0;130" "38;2;50;0;90")
      ;;
    blood)
      colors=("38;2;255;0;0" "38;2;220;0;0" "38;2;180;0;0" "38;2;140;0;0" "38;2;100;0;0" "38;2;60;0;0")
      ;;
    ice)
      colors=("38;2;173;216;230" "38;2;135;206;250" "38;2;100;149;237" "38;2;70;130;180" "38;2;25;25;112")
      ;;
    fire)
      colors=("38;2;255;255;0" "38;2;255;165;0" "38;2;255;69;0" "38;2;220;20;60" "38;2;139;0;0")
      ;;
    *)
      colors=("38;2;255;255;255")
      ;;
  esac
  local num_colors=${#colors[@]}

  declare -a columns lengths speeds intensities
  local active_columns=$((width * density / 100))
  [[ $active_columns -lt 1 ]] && active_columns=1

  for ((i=0; i<width; i++)); do
    if [[ $i -lt $active_columns ]]; then
      columns[$i]=$(( -(RANDOM % height) ))
      lengths[$i]=$((RANDOM % (height / 2) + height / 4))
      speeds[$i]=$((RANDOM % 3 + 1))
      intensities[$i]=$((RANDOM % 100))
    else
      columns[$i]=-9999
    fi
  done

  tput civis 2>/dev/null
  stty -echo 2>/dev/null
  printf "\033[2J\033[H\033[?25l"

  local frame_count=0
  local start_time=$(date +%s)
  local end_time=$((start_time + duration))
  local last_fps_time=$start_time
  local fps=0

  while [[ $(date +%s) -lt $end_time ]]; do
    local frame_buffer=""
    ((frame_count++))

    if [[ $((frame_count % 10)) -eq 0 ]]; then
      frame_buffer+="\033[2J"
    fi

    for ((i=0; i<width; i++)); do
      [[ ${columns[$i]} -eq -9999 ]] && continue

      local col_pos=${columns[$i]}
      local col_len=${lengths[$i]}
      local col_speed=${speeds[$i]}

      if [[ $((col_pos - col_len)) -lt height ]]; then
        for ((j=0; j<col_len; j++)); do
          local y_pos=$((col_pos - j))
          
          if [[ y_pos -ge 0 && y_pos -lt height ]]; then
            local color_idx=$(( (j * (num_colors - 1)) / col_len ))
            color_idx=$((color_idx >= num_colors ? num_colors - 1 : color_idx))
            
            local char_idx=$(( (y_pos + i + frame_count) % num_chars ))
            local brightness=$((intensities[i] > 50 ? 1 : 2))
            
            frame_buffer+="\033[$((y_pos + 1));$((i + 1))H\033[${brightness};${colors[$color_idx]}m${chars:$char_idx:1}"
          fi
        done

        if [[ col_pos -ge 0 && col_pos -lt height ]]; then
          local lead_char=$(( (col_pos + i + frame_count * 2) % num_chars ))
          frame_buffer+="\033[$((col_pos + 1));$((i + 1))H\033[1;${colors[0]}m${chars:$lead_char:1}"
        fi

        columns[$i]=$((col_pos + col_speed))

        if [[ $((col_pos - col_len)) -ge height ]]; then
          columns[$i]=$(( -(RANDOM % (height / 2)) ))
          lengths[$i]=$((RANDOM % (height / 2) + height / 4))
          speeds[$i]=$((RANDOM % 3 + 1))
          intensities[$i]=$((RANDOM % 100))
        fi
      fi
    done

    if [[ "$show_fps" == "true" ]]; then
      local current_time=$(date +%s)
      if [[ $((current_time - last_fps_time)) -gt 0 ]]; then
        fps=$frame_count
        last_fps_time=$current_time
        frame_count=0
      fi
      frame_buffer+="\033[1;1H\033[38;2;255;255;0m FPS: $fps \033[0m"
    fi

    printf "%b" "$frame_buffer\033[0m"
    sleep 0.04
  done

  tput cnorm 2>/dev/null
  stty echo 2>/dev/null
  printf "\033[2J\033[H\033[?25h\033[0m"
}

matrix() { matrix_rain "${1:-5}" "${2:-50}" "${3:-matrix}" "${4:-katakana}" "${5:-false}"; }
matrix_cyber() { matrix_rain "${1:-5}" 70 "cyber" "hex" "false"; }
matrix_blood() { matrix_rain "${1:-5}" 60 "blood" "binary" "false"; }
matrix_screensaver() {
  echo -e "\033[38;2;0;255;0m🔋 Neural Cascade Screensaver Activated\033[0m"
  matrix_rain "${1:-30}" 80 "matrix" "katakana" "true"
  echo -e "\033[38;2;0;255;0m✅ Screensaver Deactivated\033[0m"
}
matrix_benchmark() {
  echo "🔬 Matrix Benchmark Mode - Testing Performance..."
  local start=$(date +%s)
  matrix_rain 10 100 "matrix" "katakana" "true"
  local end=$(date +%s)
  echo "⏱️ Total time: $((end - start))s"
}

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 13: CPU MONITORING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

typeset -gA _ZSH_CPU_HISTORY=()
typeset -ga _ZSH_CPU_TIMESTAMPS=()

_zsh_init_cpu_monitor() {
  mkdir -p "$XDG_CACHE_HOME/zsh"
  _ZSH_CPU_HISTORY=()
  _ZSH_CPU_TIMESTAMPS=()
}

_zsh_get_cpu_usage() {
  local mode="${1:-total}"
  local stat_file="$XDG_CACHE_HOME/zsh/cpu_last_stat"
  
  local -a last_stat
  if [[ -f "$stat_file" ]]; then
    last_stat=($(<"$stat_file"))
  else
    last_stat=(0 0 0 0 0 0 0 0)
  fi

  local -a current_stat
  if [[ "$mode" == "per-core" ]]; then
    current_stat=($(awk '/^cpu[0-9]+ / {print $2+$3+$4, $2+$3+$4+$5+$6+$7+$8}' /proc/stat 2>/dev/null))
  else
    current_stat=($(awk '/^cpu / {print $2+$3+$4+$6+$7+$8, $2+$3+$4+$5+$6+$7+$8, $2, $4, $5, $6, $7, $8}' /proc/stat 2>/dev/null))
  fi

  echo "${current_stat[@]}" > "$stat_file"

  if [[ "$mode" == "detailed" ]]; then
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
    local delta_total=$((current_stat[1] - last_stat[1]))
    local delta_busy=$((current_stat[0] - last_stat[0]))

    if [[ $delta_total -gt 0 ]]; then
      printf "%.1f" $(echo "$delta_busy $delta_total" | awk '{print 100 * $1 / $2}')
    else
      echo "0.0"
    fi
  fi
}

_zsh_get_cpu_temp() {
  if command -v sensors &>/dev/null; then
    sensors 2>/dev/null | awk '/^Core 0:/ {print $3}' | tr -d '+°C' | head -1
  elif [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
    local temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null)
    echo $(( temp / 1000 ))
  else
    echo "N/A"
  fi
}

_zsh_get_cpu_freq() {
  if [[ -f /proc/cpuinfo ]]; then
    awk '/^cpu MHz/ {sum+=$4; count++} END {if(count>0) printf "%.0f", sum/count}' /proc/cpuinfo
  else
    echo "N/A"
  fi
}

_zsh_generate_cpu_graph() {
  local -a history=("$@")
  local max_height=10
  local max_val=100
  local graph=""

  for val in "${history[@]}"; do
    local bar_height=$(( (val * max_height) / max_val ))
    [[ $bar_height -gt max_height ]] && bar_height=$max_height
    
    local color
    if [[ $val -gt 80 ]]; then
      color="38;2;255;0;0"
    elif [[ $val -gt 60 ]]; then
      color="38;2;255;165;0"
    elif [[ $val -gt 40 ]]; then
      color="38;2;255;255;0"
    else
      color="38;2;0;255;0"
    fi
    
    local bar=""
    for ((i=0; i<bar_height; i++)); do
      bar="█$bar"
    done
    
    printf "\033[${color}m%-10s\033[0m " "$bar"
  done
  echo
}

cpu_status() {
  if [[ "$ENABLE_ADVANCED_CPU" != true ]]; then
    echo "⚠️ Advanced CPU monitoring disabled. Enable ENABLE_ADVANCED_CPU in config."
    return 1
  fi

  echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[38;2;255;255;0m          💀 NEURAL METRICS - CPU STATUS 💀\033[0m"
  echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  
  local total_usage=$(_zsh_get_cpu_usage "total")
  echo -e "\n\033[38;2;0;255;0m🔋 Total CPU Usage:\033[0m $total_usage%"
  
  echo -e "\n\033[38;2;0;255;0m⚡ Per-Core Usage:\033[0m"
  local -a core_usages=($(_zsh_get_cpu_usage "per-core"))
  for ((i=0; i<${#core_usages[@]}; i++)); do
    local usage=${core_usages[$i]}
    local bar=""
    local filled=$((usage / 5))
    
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
  
  echo -e "\n\033[38;2;0;255;0m📊 Breakdown:\033[0m"
  local detailed=$(_zsh_get_cpu_usage "detailed")
  echo "$detailed" | tr ' ' '\n' | while IFS=: read key val; do
    printf "  %-10s %3d%%\n" "$key:" "$val"
  done
  
  local temp=$(_zsh_get_cpu_temp)
  if [[ "$temp" != "N/A" ]]; then
    local temp_color
    if [[ $temp -gt 80 ]]; then temp_color="38;2;255;0;0"
    elif [[ $temp -gt 70 ]]; then temp_color="38;2;255;165;0"
    else temp_color="38;2;0;255;0"; fi
    
    echo -e "\n\033[${temp_color}m🌡️ Temperature:\033[0m ${temp}°C"
  fi
  
  local freq=$(_zsh_get_cpu_freq)
  [[ "$freq" != "N/A" ]] && echo -e "\033[38;2;0;255;255m⚡ Frequency:\033[0m ${freq} MHz"
  
  echo -e "\n\033[38;2;255;255;0m🔥 Top CPU Consumers:\033[0m"
  ps aux --sort=-%cpu | awk 'NR>1 {printf "  %-20s %5.1f%%\n", $11, $3}' | head -5
  
  echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
}

cpu_monitor_live() {
  if [[ "$ENABLE_ADVANCED_CPU" != true ]]; then
    echo "⚠️ Advanced CPU monitoring disabled. Enable ENABLE_ADVANCED_CPU in config."
    return 1
  fi

  local duration="${1:-30}"
  local sample_interval="${2:-1}"
  
  echo -e "\033[38;2;0;255;255m🔬 Live CPU Monitor - Press Ctrl+C to exit\033[0m\n"
  
  local -a history
  local end_time=$(($(date +%s) + duration))
  
  trap 'tput cnorm; echo -e "\n\033[38;2;0;255;0m✅ Monitor stopped\033[0m"; return' INT
  tput civis
  
  while [[ $(date +%s) -lt $end_time ]]; do
    local usage=$(_zsh_get_cpu_usage "total")
    history+=("${usage%.*}")
    
    [[ ${#history[@]} -gt 30 ]] && history=("${history[@]:1}")
    
    printf "\033[2J\033[H"
    echo -e "\033[38;2;255;255;0mCPU Usage History (last ${#history[@]} samples):\033[0m"
    _zsh_generate_cpu_graph "${history[@]}"
    echo -e "\n\033[38;2;0;255;0mCurrent: ${usage}%\033[0m"
    
    sleep $sample_interval
  done
  
  tput cnorm
  echo -e "\n\033[38;2;0;255;0m✅ Monitoring complete\033[0m"
}

alias cpu='_zsh_get_cpu_usage'
alias cpu-temp='_zsh_get_cpu_temp'
alias cpu-detailed='_zsh_get_cpu_usage detailed'
alias cpu-cores='_zsh_get_cpu_usage per-core'
alias cpu-live='cpu_monitor_live'
alias cpu-status='cpu_status'

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 14: CACHING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

_zsh_cache_file="$XDG_CACHE_HOME/zsh/zsh_cache.json"
_zsh_cache_ttl=60

get_cached() {
  [[ "$ENABLE_CACHE_SYSTEM" != true ]] && return 1
  
  local key="$1"
  if command -v jq >/dev/null 2>&1 && [[ -f "$_zsh_cache_file" ]]; then
    local expiry=$(jq -r ".${key}.expiry" "$_zsh_cache_file" 2>/dev/null)
    local now=$(date +%s)
    if [[ -n "$expiry" && "$now" -lt "$expiry" ]]; then
      jq -r ".${key}.value" "$_zsh_cache_file"
      return 0
    fi
  fi
  return 1
}

set_cached() {
  [[ "$ENABLE_CACHE_SYSTEM" != true ]] && return 1
  
  local key="$1"
  local value="$2"
  local expiry=$(($(date +%s) + _zsh_cache_ttl))
  
  local cache_dir=$(dirname "$_zsh_cache_file")
  mkdir -p "$cache_dir"
  local temp_file=$(mktemp "$cache_dir/zsh_cache.XXXXXX")

  if [[ -f "$_zsh_cache_file" ]]; then
    jq --arg key "$key" --argjson value "$(echo "$value" | jq -R -s .)" --argjson expiry "$expiry" \
      '.[$key] = {value: $value, expiry: $expiry}' "$_zsh_cache_file" > "$temp_file" && \
      mv "$temp_file" "$_zsh_cache_file"
  else
    jq --arg key "$key" --argjson value "$(echo "$value" | jq -R -s .)" --argjson expiry "$expiry" \
      '.[$key] = {value: $value, expiry: $expiry}' <(echo '{}') > "$_zsh_cache_file"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 15: SYSTEM INFORMATION DISPLAY
# ═══════════════════════════════════════════════════════════════════════════

show_system_info() {
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

  output_buffer+="\033[${primary_color}m"
  if command -v figlet &>/dev/null; then
    output_buffer+=$(echo "Shadow@Bhanu" | figlet -f slant 2>/dev/null)
  else
    output_buffer+=$(gradient_text "🚀 Shadow@Bhanu Elite Terminal 🚀")
  fi
  output_buffer+="\033[0m\n"

  output_buffer+="\033[${secondary_color}m╔═══════════════════════════════════════════════════════════════════════════════╗\033[0m\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m🧠 ⟨ 💀 This ain't a shell 😏😎 it's a weaponized AI brain 🤖😈 ⟩ 🧠\033[0m \033[${secondary_color}m║\033[0m\n"
  output_buffer+="\033[${secondary_color}m╠═══════════════════════════════════════════════════════════════════════════════╣\033[0m\n"

  local hostname=$(hostname 2>/dev/null || echo "UNKNOWN")
  local kernel=$(uname -r 2>/dev/null || echo "UNKNOWN")
  local os_info=$(lsb_release -d 2>/dev/null | cut -f2 || uname -o 2>/dev/null || echo "UNKNOWN")
  local arch=$(uname -m 2>/dev/null || echo "UNKNOWN")

  output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🌐 HOST:\033[0m $hostname \033[${accent_color}m⚡ KERNEL:\033[0m $kernel \033[${success_color}m🗄️ ARCH:\033[0m $arch\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🖥️ OS:\033[0m $os_info\n"

  local uptime_info=$(uptime -p 2>/dev/null | sed 's/up //' || echo "UNKNOWN")
  local load_avg=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | sed 's/^ *//' || echo "N/A")
  local current_time=$(date '+%H:%M:%S %Z' 2>/dev/null)
  local current_date=$(date '+%Y-%m-%d %A' 2>/dev/null)

  output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m⏱️ UPTIME:\033[0m $uptime_info \033[${warning_color}m📊 LOAD:\033[0m $load_avg\n"
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m🕐 TIME:\033[0m $current_time \033[${primary_color}m📅 DATE:\033[0m $current_date\n"

  if command -v free &>/dev/null; then
    local memory_total=$(free -m 2>/dev/null | awk 'NR==2{print $2}')
    local memory_used=$(free -m 2>/dev/null | awk 'NR==2{print $3}')
    local memory_percent=$(free -m 2>/dev/null | awk 'NR==2{printf "%.0f", $3*100/$2}')
    local memory_bar=""
    
    for ((i=0; i<30; i++)); do
      if [[ $i -lt $((memory_percent*30/100)) ]]; then
        if [[ $memory_percent -gt 80 ]]; then
          memory_bar+="\033[${danger_color}m█\033[0m"
        elif [[ $memory_percent -gt 60 ]]; then
          memory_bar+="\033[${warning_color}m█\033[0m"
        else
          memory_bar+="\033[${success_color}m█\033[0m"
        fi
      else
        memory_bar+="\033[38;2;64;64;64m░\033[0m"
      fi
    done
    
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${primary_color}m🧠 MEMORY:\033[0m ${memory_used}MB/${memory_total}MB (${memory_percent}%) $memory_bar\n"
  fi

  if command -v df &>/dev/null; then
    local disk_used=$(df -h / 2>/dev/null | awk 'NR==2{print $3}' || echo "N/A")
    local disk_total=$(df -h / 2>/dev/null | awk 'NR==2{print $2}' || echo "N/A")
    local disk_percent=$(df / 2>/dev/null | awk 'NR==2{print $5}' | sed 's/%//' || echo "0")
    local disk_bar=""
    
    for ((i=0; i<30; i++)); do
      if [[ $i -lt $((disk_percent*30/100)) ]]; then
        if [[ $disk_percent -gt 85 ]]; then
          disk_bar+="\033[${danger_color}m█\033[0m"
        elif [[ $disk_percent -gt 70 ]]; then
          disk_bar+="\033[${warning_color}m█\033[0m"
        else
          disk_bar+="\033[${success_color}m█\033[0m"
        fi
      else
        disk_bar+="\033[38;2;64;64;64m░\033[0m"
      fi
    done
    
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m💾 STORAGE:\033[0m $disk_used/$disk_total (${disk_percent}%) $disk_bar\n"
  fi

  if command -v ip &>/dev/null; then
    local ip_addr=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || echo "N/A")
    local interface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "N/A")
    local public_ip_line=""
    
    if [[ "$ENABLE_PUBLIC_IP_LOOKUP" == "true" ]]; then
      local public_ip=$(timeout 2 curl -s https://ipinfo.io/ip 2>/dev/null || echo "LOOKUP FAILED")
      public_ip_line=" \033[${primary_color}m🌍 PUBLIC:\033[0m $public_ip"
    fi
    
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m🌐 LOCAL:\033[0m $ip_addr \033[${warning_color}m📡 INTERFACE:\033[0m $interface$public_ip_line\n"
  fi

  if command -v lscpu &>/dev/null; then
    local cpu_info=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | sed 's/^ *//' | cut -c1-50 || echo "N/A")
    local cpu_cores=$(nproc 2>/dev/null || echo "N/A")
    local cpu_usage=$(_zsh_get_cpu_usage)
    local cpu_temp=""
    
    if command -v sensors &>/dev/null; then
      cpu_temp=$(sensors 2>/dev/null | grep -i 'core 0' | awk '{print $3}' | head -1 2>/dev/null || echo "")
      [[ -n "$cpu_temp" ]] && cpu_temp=" 🌡️$cpu_temp"
    fi
    
    output_buffer+="\033[${secondary_color}m║\033[0m \033[${accent_color}m⚙️ CPU:\033[0m $cpu_info (${cpu_cores} cores) ${cpu_usage}%$cpu_temp\n"
  fi

  local processes=$(ps aux 2>/dev/null | wc -l || echo "N/A")
  local users=$(who 2>/dev/null | wc -l || echo "N/A")
  local zombie_processes=$(ps aux 2>/dev/null | awk '$8 ~ /^Z/ { count++ } END { print count+0 }' || echo "0")
  
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${success_color}m⚡ PROCESSES:\033[0m $processes \033[${primary_color}m👥 USERS:\033[0m $users \033[${danger_color}m🧟 ZOMBIES:\033[0m $zombie_processes\n"

  local failed_logins=$(lastb 2>/dev/null | wc -l || echo "0")
  local active_sessions=$(w -h 2>/dev/null | wc -l || echo "0")
  
  output_buffer+="\033[${secondary_color}m║\033[0m \033[${danger_color}m🔒 FAILED_LOGINS:\033[0m $failed_logins \033[${warning_color}m🔺 ACTIVE_SESSIONS:\033[0m $active_sessions\n"

  output_buffer+="\033[${secondary_color}m╚═══════════════════════════════════════════════════════════════════════════════╝\033[0m\n"

  set_cached "system_info" "$output_buffer"
  echo -e "$output_buffer"
}

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 16: GREETING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

time_based_greeting() {
  local hour=$(date +"%H")
  local greeting
  local -a options
  local color=$(random_color)

  local threat_level=3
  if [[ $hour -ge 0 && $hour -lt 6 ]]; then
    threat_level=1
  elif [[ $hour -ge 6 && $hour -lt 9 ]]; then
    threat_level=2
  elif [[ $hour -ge 18 && $hour -lt 24 ]]; then
    threat_level=2
  fi

  if [[ $hour -ge 5 && $hour -lt 12 ]]; then
    options=(
      "🌅 Morning, Shadow 😈 – AI swarm online, targets acquired 🎯"
      "🔥 Rise and dominate, Shadow 😈 – neural networks activated 🧠"
      "🌄 Dawn protocol initiated, Shadow 😈 – red team standing by 🚨"
      "☀️ Morning breach, Shadow 😈 – all systems green 🟢"
      "🛠️ Operations online, Shadow 😈 – ready to penetrate 💀"
    )
  elif [[ $hour -ge 12 && $hour -lt 17 ]]; then
    options=(
      "🌞 Afternoon ops, Shadow 😈 – targets in crosshairs 🎯"
      "💣 Midday strike, Shadow 😈 – cyber weapons hot 🔥"
      "⚙️ Systems peaked, Shadow 😈 – maximum efficiency 📊"
      "🔓 Vulnerabilities exposed, Shadow 😈 – exploit ready 💥"
      "💀 Afternoon hunt, Shadow 😈 – stealth mode engaged 👻"
    )
  elif [[ $hour -ge 17 && $hour -lt 21 ]]; then
    options=(
      "🌆 Evening infiltration, Shadow 😈 – darkness approaching 🌙"
      "⚡ Dusk operations, Shadow 😈 – time to strike 🗡️"
      "🌇 Shadow protocol, Shadow 😈 – moving unseen 👻"
      "🚨 Night ops prep, Shadow 😈 – going dark 🕶️"
      "🌌 Stealth mode, Shadow 😈 – hunt begins 🔍"
    )
  else
    options=(
      "🌙 Midnight ops, Shadow 😈 – silent running 🤫"
      "🌃 Night hunter, Shadow 😈 – invisible strike 👻"
      "💣 Zero dark thirty, Shadow 😈 – full stealth 🕶️"
      "🛡️ Insomniac ops, Shadow 😈 – always watching 👁️"
      "🕛 Late night breach, Shadow 😈 – systems never sleep 💀"
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

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 17: ENHANCED CLEAR FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

clear() {
  command clear

  if [[ "$ENABLE_MATRIX_ON_CLEAR" == true && $((RANDOM % 4)) -eq 0 ]]; then
    matrix_rain 1
  fi

  loading_animation "🔄 Reinitializing Shadow Systems..." 1.2 "" "pulse" "false"

  command clear

  show_system_info
  time_based_greeting

  if [[ -n "$WELCOME_DISPLAYED" ]]; then
    echo -e "\033[38;2;255;255;255m────────────────────────────────────────────────────────────────────────────────\033[0m"
  fi

  if command -v git &>/dev/null && git rev-parse --is-inside-work-tree &>/dev/null 2>&1; then
    echo -e "\033[38;2;100;255;100m📁 $(pwd) \033[38;2;255;255;100m($(git branch --show-current 2>/dev/null || echo 'detached'))\033[0m"
  else
    echo -e "\033[38;2;100;255;100m📁 $(pwd)\033[0m"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 18: PROCESS CLEANUP
# ═══════════════════════════════════════════════════════════════════════════

cleanup_processes() {
  local pid_file="$TERMINAL_SESSION_FILE.monitor.pid"
  
  if [[ -f "$pid_file" ]]; then
    local pid=$(cat "$pid_file" 2>/dev/null)
    
    if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM -"$pid" 2>/dev/null
      sleep 0.2
      kill -0 "$pid" 2>/dev/null && kill -KILL -"$pid" 2>/dev/null
    fi
    
    rm -f "$pid_file"
  fi

  jobs -p | xargs -r kill -TERM 2>/dev/null
  sleep 0.1
  jobs -p | xargs -r kill -KILL 2>/dev/null

  tput cnorm 2>/dev/null
  stty echo 2>/dev/null
  printf "\033[0m\033[?25h"
}

trap cleanup_processes EXIT INT TERM

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 19: KEYBINDINGS
# ═══════════════════════════════════════════════════════════════════════════

bindkey -e
bindkey '^R' history-incremental-search-backward
bindkey '^S' history-incremental-search-forward
bindkey '^[[1;5C' forward-word
bindkey '^[[1;5D' backward-word
bindkey '^H' backward-kill-word
bindkey '^[[3;5~' kill-word
bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line
bindkey '^I' expand-or-complete

_zsh_refresh_dashboard() {
  clear
  show_system_info
  zle reset-prompt
}
zle -N _zsh_refresh_dashboard
bindkey '^X^R' _zsh_refresh_dashboard

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 20: FZF INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════

if command -v fzf &> /dev/null; then
  if [[ -f ~/.fzf.zsh ]]; then
    source ~/.fzf.zsh
  elif [[ -f /usr/share/fzf/key-bindings.zsh ]]; then
    source /usr/share/fzf/key-bindings.zsh
    source /usr/share/fzf/completion.zsh
  fi

  export FZF_DEFAULT_COMMAND='fd --type f --hidden --follow --exclude .git 2>/dev/null || find . -type f -not -path "*/\.git/*"'
  export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"
  export FZF_ALT_C_COMMAND='fd --type d --hidden --follow --exclude .git 2>/dev/null || find . -type d -not -path "*/\.git/*"'
  export FZF_DEFAULT_OPTS="--height 40% --layout=reverse --border --multi --info=inline --color=bg+:#1e1e1e,bg:#0a0a0a,spinner:#f4a261,hl:#e76f51,fg:#ffffff,header:#e9c46a,info:#264653,pointer:#f4a261,marker:#e76f51,fg+:#ffffff,prompt:#e9c46a,hl+:#e76f51"
  export FZF_CTRL_T_OPTS="--preview 'bat --style=numbers --color=always --line-range :500 {} 2>/dev/null || cat {}' --preview-window=right:60%"
  export FZF_ALT_C_OPTS="--preview 'tree -C {} 2>/dev/null || ls -la {}' --preview-window=right:60%"
fi

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 21: PLUGIN CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════

ZSH_AUTOSUGGEST_STRATEGY=(history completion)
ZSH_AUTOSUGGEST_BUFFER_MAX_SIZE=100
ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE="fg=240"
ZSH_AUTOSUGGEST_USE_ASYNC=true

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

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 22: SECURITY & OPERATIONAL CONTEXT
# ═══════════════════════════════════════════════════════════════════════════

INTEGRITY_BASELINE_FILE="$XDG_CONFIG_HOME/zsh/fs_integrity_baseline.sha256"

initialize_integrity_baseline() {
  [[ "$ENABLE_FILE_INTEGRITY" != true ]] && return
  
  echo "🔒 Creating file integrity baseline..."
  local files_to_check=(
    "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow"
    "/etc/sudoers" "/etc/ssh/sshd_config"
    "/etc/pam.d/common-auth" "/etc/pam.d/common-password"
    "/etc/login.defs" "/etc/securetty"
    "/root/.ssh/authorized_keys"
  )

  mkdir -p "$(dirname "$INTEGRITY_BASELINE_FILE")"
  echo "# Zsh File Integrity Baseline - $(date)" > "$INTEGRITY_BASELINE_FILE"

  for file in "${files_to_check[@]}"; do
    [[ -r "$file" ]] && sha256sum "$file" >> "$INTEGRITY_BASELINE_FILE"
  done
  
  echo "✅ Baseline created at: $INTEGRITY_BASELINE_FILE"
}

check_fs_integrity() {
  [[ "$ENABLE_FILE_INTEGRITY" != true ]] && return
  
  if [[ ! -f "$INTEGRITY_BASELINE_FILE" ]]; then
    echo "⚠️ Baseline not found. Run 'sec-baseline' first."
    return 1
  fi
  
  echo "🔍 Checking file system integrity..."
  local has_warnings=false
  
  while IFS= read -r line; do
    echo "🚨 WARNING: Integrity check FAILED for: $(echo $line | cut -d':' -f1)"
    has_warnings=true
  done < <(sha256sum -c --quiet "$INTEGRITY_BASELINE_FILE" 2>/dev/null | grep 'FAILED')

  if ! $has_warnings; then
    echo "✅ All checked files are intact."
  fi
}

check_network_anomalies() {
  echo "📡 Checking for network anomalies..."
  
  if ! command -v ss &>/dev/null; then
    echo "⚠️ 'ss' command not found."
    return 1
  fi

  echo "\nUnusual Listening Ports:"
  ss -tlpn 2>/dev/null | awk 'NR>1 {print $4}' | grep -E ':[0-9]+$' | cut -d':' -f2 | sort -un | while read port; do
    if ! grep -qwE "^\w+\s+${port}/(tcp|udp)" /etc/services 2>/dev/null; then
      echo "  - Unusual port: $port"
    fi
  done

  echo "\nTop 10 Established Connections:"
  ss -tn 'state established' 2>/dev/null | awk 'NR>1 {print $5}' | cut -d':' -f1 | \
    grep -vE '^(127.0.0.1|::1)$' | sort | uniq -c | sort -nr | head -n 10
}

alias sec-baseline='initialize_integrity_baseline'
alias sec-check-fs='check_fs_integrity'
alias sec-check-net='check_network_anomalies'

export ZSH_OP_TARGET_IP=""
export ZSH_OP_TARGET_DOMAIN=""
export ZSH_OP_TARGET_DESC=""

set-target() {
  [[ "$ENABLE_OP_CONTEXT" != true ]] && return
  
  if [[ -z "$1" ]]; then
    echo "Usage: set-target <IP_ADDRESS> [DOMAIN] [DESCRIPTION]"
    echo "Example: set-target 10.10.11.15 kioptrix.com 'Vulnhub VM'"
    return 1
  fi
  
  export ZSH_OP_TARGET_IP="$1"
  export ZSH_OP_TARGET_DOMAIN="$2"
  export ZSH_OP_TARGET_DESC="$3"
  
  echo "🎯 Target set: IP=$ZSH_OP_TARGET_IP, Domain=$ZSH_OP_TARGET_DOMAIN"
}

clear-target() {
  [[ "$ENABLE_OP_CONTEXT" != true ]] && return
  
  export ZSH_OP_TARGET_IP=""
  export ZSH_OP_TARGET_DOMAIN=""
  export ZSH_OP_TARGET_DESC=""
  echo "🎯 Target cleared."
}

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 23: AI ENGINE
# ═══════════════════════════════════════════════════════════════════════════

ai() {
  [[ "$ENABLE_AI_ENGINE" != true || "$ENABLE_AI_NLC" != true ]] && return
  
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
    *"scan for web servers"*|*"find http ports"*)
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
    [[ "$REPLY" =~ ^[Yy]$ ]] && eval $suggested_command
  fi
}

_ZSH_AI_HISTORY_FILE="$XDG_DATA_HOME/zsh/zsh_ai_history"

_zsh_log_command_to_history() {
  [[ "$ENABLE_AI_ENGINE" != true ]] && return
  [[ -z "$1" || "$1" == "suggest" ]] && return
  
  mkdir -p "$(dirname "$_ZSH_AI_HISTORY_FILE")"
  echo "$PWD|$1" >> "$_ZSH_AI_HISTORY_FILE"
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec _zsh_log_command_to_history

suggest() {
  [[ "$ENABLE_AI_ENGINE" != true || "$ENABLE_AI_PREDICTIONS" != true ]] && return
  
  if [[ ! -f "$_ZSH_AI_HISTORY_FILE" ]]; then
    echo "No command history found yet."
    return
  fi

  echo -e "\033[38;2;0;255;255m🧠 AI Command Suggestions:\033[0m"

  local target_ip="${ZSH_OP_TARGET_IP:-127.0.0.1}"
  local target_domain="${ZSH_OP_TARGET_DOMAIN:-example.com}"
  local last_command=$(fc -ln -1 2>/dev/null)
  echo -e "\033[38;2;255;255;0m✨ Workflow Suggestions (last: '$last_command'):\033[0m"

  case "$last_command" in
    *nmap*)
      echo "  - gobuster dir -u http://${target_ip} -w <wordlist>"
      echo "  - nikto -h http://${target_ip}"
      echo "  - enum4linux -a ${target_ip}"
      ;;
    *gobuster*|*nikto*)
      echo "  - nmap -sC -sV -p<port> ${target_ip}"
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
      echo "  - docker exec -it <container> /bin/bash"
      echo "  - docker logs -f <container>"
      ;;
  esac

  echo -e "\n\033[38;2;255;255;0m📚 Most Frequent in This Directory:\033[0m"
  grep "^$PWD|" "$_ZSH_AI_HISTORY_FILE" 2>/dev/null | cut -d'|' -f2 | \
    sort | uniq -c | sort -nr | head -n 5 | awk '{ $1="  - "; print }'
}

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 24: CLOUD & CONTAINER OPERATIONS (RESTORED)
# ═══════════════════════════════════════════════════════════════════════════

docker_status() {
  if [[ "$ENABLE_CLOUD_MONITORING" != true ]]; then
    echo "⚠️ Cloud monitoring disabled. Enable ENABLE_CLOUD_MONITORING in config."
    return 1
  fi

  if command -v docker &>/dev/null; then
    echo -e "\033[38;2;0;255;255m🐳 Docker Container Status:\033[0m"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
  else
    echo "⚠️ Docker not installed"
  fi
}

kube_status() {
  if [[ "$ENABLE_CLOUD_MONITORING" != true ]]; then
    echo "⚠️ Cloud monitoring disabled. Enable ENABLE_CLOUD_MONITORING in config."
    return 1
  fi

  if command -v kubectl &>/dev/null; then
    echo -e "\033[38;2;0;255;255m☸️ Kubernetes Cluster Status:\033[0m"
    kubectl get nodes -o wide
    echo -e "\n\033[38;2;255;255;0mPods by Namespace:\033[0m"
    kubectl get pods --all-namespaces -o wide
  else
    echo "⚠️ kubectl not installed"
  fi
}

aws_status() {
  if [[ "$ENABLE_CLOUD_MONITORING" != true ]]; then
    echo "⚠️ Cloud monitoring disabled. Enable ENABLE_CLOUD_MONITORING in config."
    return 1
  fi

  if command -v aws &>/dev/null; then
    echo -e "\033[38;2;0;255;255m☁️ AWS EC2 Instances:\033[0m"
    aws ec2 describe-instances \
      --query 'Reservations[*].Instances[*].[InstanceId,State.Name,InstanceType,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' \
      --output table
  else
    echo "⚠️ AWS CLI not installed"
  fi
}

az_status() {
  if [[ "$ENABLE_CLOUD_MONITORING" != true ]]; then
    echo "⚠️ Cloud monitoring disabled. Enable ENABLE_CLOUD_MONITORING in config."
    return 1
  fi

  if command -v az &>/dev/null; then
    echo -e "\033[38;2;0;255;255m☁️ Azure Virtual Machines:\033[0m"
    az vm list --show-details --output table
  else
    echo "⚠️ Azure CLI not installed"
  fi
}

gcp_status() {
  if [[ "$ENABLE_CLOUD_MONITORING" != true ]]; then
    echo "⚠️ Cloud monitoring disabled. Enable ENABLE_CLOUD_MONITORING in config."
    return 1
  fi

  if command -v gcloud &>/dev/null; then
    echo -e "\033[38;2;0;255;255m☁️ GCP Compute Instances:\033[0m"
    gcloud compute instances list
  else
    echo "⚠️ gcloud not installed"
  fi
}

alias docker-stats='docker_status'
alias k8s='kube_status'
alias cloud-aws='aws_status'
alias cloud-azure='az_status'
alias cloud-gcp='gcp_status'

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 25: LIVE THREAT INTELLIGENCE (RESTORED)
# ═══════════════════════════════════════════════════════════════════════════

fetch_threats() {
  if [[ "$ENABLE_THREAT_INTEL" != true ]]; then 
    echo "⚠️ Threat intelligence disabled. Enable ENABLE_THREAT_INTEL in config."
    return 1
  fi

  if ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
    echo "❌ Error: 'curl' and 'jq' required"
    return 1
  fi

  echo -e "\033[38;2;255;255;0m🔍 Fetching latest CVEs from cve.circl.lu...\033[0m"

  local cve_data
  cve_data=$(curl -s --max-time 5 "https://cve.circl.lu/api/last/5")

  if [[ -z "$cve_data" || "$cve_data" == "null" ]]; then
    echo "❌ Failed to fetch threat intelligence"
    return 1
  fi

  echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "\033[38;2;255;0;255m🚨 LATEST 5 PUBLISHED CVEs 🚨\033[0m"
  echo -e "\033[38;2;0;255;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
  
  echo "$cve_data" | jq -r '.[] | 
    "\n\u001b[1;33mCVE-ID:\u001b[0m \(.id)
\u001b[1;31mCVSS:\u001b[0m \(.cvss // "N/A")
\u001b[1;36mPublished:\u001b[0m \(.Published // "Unknown")
\u001b[1;35mSummary:\u001b[0m \(.summary | gsub("\\n"; " ") | .[0:200])...
\u001b[38;2;100;100;100m─────────────────────────────────────────\u001b[0m"'
  
  echo -e "\n\033[38;2;0;255;0m✅ Threat intelligence updated\033[0m"
}

alias threat-intel='fetch_threats'
alias cve='fetch_threats'
alias threats='fetch_threats'

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 26: LIVE DASHBOARD & MONITORING (RESTORED)
# ═══════════════════════════════════════════════════════════════════════════

live_system_monitor() {
  if [[ "$ENABLE_LIVE_DASHBOARD" != true ]]; then
    echo "⚠️ Live dashboard disabled. Enable ENABLE_LIVE_DASHBOARD in config."
    return 1
  fi

  local cpu_usage=$(_zsh_get_cpu_usage)
  local mem_info=$(free -b 2>/dev/null | awk 'NR==2{printf "%.2f%%", $3*100/$2}' || echo "N/A")
  local disk_usage=$(df -h / 2>/dev/null | awk 'NR==2{print $5}' || echo "N/A")
  
  local net_rx="N/A"
  local net_tx="N/A"
  if [[ -r /proc/net/dev ]]; then
    local net_stats=$(awk 'NR>2 {if(sub(":","",$1)) {rx+=$2; tx+=$10}} END {print rx, tx}' /proc/net/dev)
    net_rx=$(format_bytes $(echo $net_stats | cut -d' ' -f1))
    net_tx=$(format_bytes $(echo $net_stats | cut -d' ' -f2))
  fi
  
  local threat_level=$((RANDOM % 5))
  local threat_color=$(threat_color $threat_level)
  local threat_text=$(threat_level_to_text $threat_level)
  
  echo -e "CPU: ${cpu_usage}% | MEM: ${mem_info} | DISK: ${disk_usage} | NET: ↓${net_rx} ↑${net_tx} | THREAT: \033[${threat_color};1m${threat_text}\033[0m"
}

live_dashboard() {
  if [[ "$ENABLE_LIVE_DASHBOARD" != true ]]; then
    echo "⚠️ Live dashboard disabled. Enable ENABLE_LIVE_DASHBOARD in config."
    return 1
  fi

  echo -e "\033[38;2;255;0;255m🚀 Shadow@Bhanu Live Dashboard\033[0m"
  echo -e "\033[38;2;255;255;0m⚡ Press Ctrl+C to exit\033[0m\n"
  
  trap 'tput cnorm; echo -e "\n\033[38;2;0;255;0m✅ Dashboard closed\033[0m"; return' INT
  tput civis
  
  while true; do
    printf "\033[2J\033[H"
    echo -e "\033[38;2;255;0;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo -e "\033[38;2;0;255;255m          🚀 SHADOW@BHANU LIVE DASHBOARD 🚀\033[0m"
    echo -e "\033[38;2;255;0;255m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
    
    show_system_info
    echo -e "\n\033[38;2;255;255;0m📊 LIVE METRICS:\033[0m"
    live_system_monitor
    
    echo -e "\n\033[38;2;100;100;100mLast updated: $(date '+%H:%M:%S')\033[0m"
    sleep 2
  done
}

alias dashboard='live_dashboard'
alias live='live_dashboard'

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 27: GIT INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 28: ENHANCED ALIASES
# ═══════════════════════════════════════════════════════════════════════════

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

alias apt='nocorrect apt'
alias update="sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean"
alias sysinfo="show_system_info"
alias netstat="ss -tuln"
alias ports="ss -tulpn"
alias process="ps aux | head -20"
alias memory="free -h && echo && ps aux --sort=-%mem | head -10"
alias disk="df -h && echo && du -sh * 2>/dev/null | sort -hr | head -10"
alias kubectl='minikube kubectl --'

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 29: WELCOME SCREEN
# ═══════════════════════════════════════════════════════════════════════════

post_init_display() {
  if [[ -z "$WELCOME_DISPLAYED" ]]; then
    export WELCOME_DISPLAYED=1
    command clear

    if [[ "$ENABLE_GREETING_BANNER" == true ]]; then
      show_system_info
      time_based_greeting

      if command -v fastfetch &>/dev/null; then
        echo
        fastfetch
      fi
    fi
  fi
}

add-zsh-hook precmd post_init_display

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 30: PATH CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

export WORKON_HOME="$HOME/.virtualenvs"
export GOPATH="$HOME/go"
export PNPM_HOME="${PNPM_HOME:-$HOME/.local/share/pnpm}"

path=(
  "$HOME/.local/bin"
  "$HOME/bin"
  "$GOPATH/bin"
  "$HOME/.cargo/bin"
  "$HOME/.local/share/npm/bin"
  "$PNPM_HOME"
  $path
)
typeset -U path
export PATH

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 31: SECURITY & PERMISSIONS
# ═══════════════════════════════════════════════════════════════════════════

ulimit -c 0
umask 022
alias chmod='command chmod'

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 32: POWERLEVEL10K CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 33: LOCAL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

[[ -f "$HOME/.zshrc.local" ]] && source "$HOME/.zshrc.local"

# ═══════════════════════════════════════════════════════════════════════════
# END OF CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
