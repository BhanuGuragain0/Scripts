
#!/usr/bin/env zsh
# ═══════════════════════════════════════════════════════════════════════════════
# Shadow@Bhanu Advanced Zsh Configuration - ELITE EDITION (OPTIMIZED)
# Production-Grade Ethical Hacker Terminal Environment
# ═══════════════════════════════════════════════════════════════════════════════

# === PERFORMANCE OPTIMIZATION ===
setopt NO_HASH_CMDS
setopt NO_BEEP
setopt INTERACTIVE_COMMENTS
autoload -U zmv
zmodload zsh/zpty 2>/dev/null
zmodload zsh/system 2>/dev/null
zmodload zsh/datetime 2>/dev/null
zmodload zsh/mathfunc 2>/dev/null
zmodload zsh/stat 2>/dev/null
zmodload zsh/files 2>/dev/null

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

# === PLUGINS ===
# Powerlevel10k theme
zinit ice depth=1; zinit light romkatv/powerlevel10k

# Essential plugins
zinit light zsh-users/zsh-syntax-highlighting
zinit light zsh-users/zsh-autosuggestions
zinit light zsh-users/zsh-completions
zinit light zsh-users/zsh-history-substring-search

# Productivity plugins
zinit light Aloxaf/fzf-tab
zinit light MichaelAquilina/zsh-auto-notify
zinit light MichaelAquilina/zsh-you-should-use

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

# === OPTIMIZED ANIMATION FUNCTIONS ===
# Cached color arrays for performance
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

# Fast random color generator
random_color() {
  echo "${CYBER_COLORS[$((RANDOM % ${#CYBER_COLORS[@]} + 1))]}"
}

# Optimized gradient text with reduced loops
gradient_text() {
  local text="$1"
  local output=""
  local len=${#text}
  local color_count=${#GRADIENT_COLORS[@]}

  for ((i=0; i<len; i++)); do
    local char="${text:$i:1}"
    local color="${GRADIENT_COLORS[$((i % color_count + 1))]}"
    output+="\033[${color}m${char}\033[0m"
  done
  echo -e "$output"
}

# Lightweight matrix rain effect
matrix_rain() {
  local width=$((${COLUMNS:-80} / 2))  # Reduced width for performance
  local height=$((${LINES:-24} / 4))   # Reduced height for performance
  local chars="ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ0123456789"
  local color="${CYBER_COLORS[3]}"  # Matrix green (fixed index)

  echo -e "\033[${color}m"
  for ((row=0; row<height; row++)); do
    local line=""
    for ((col=0; col<width; col++)); do
      if [[ $((RANDOM % 100)) -lt 20 ]]; then
        line+="${chars:$((RANDOM % ${#chars})):1}"
      else
        line+=" "
      fi
    done
    echo -e "$line"
    sleep 0.03  # Reduced sleep time
  done
  echo -e "\033[0m"
}

# Optimized loading animation with better performance
loading_animation() {
  local message="${1:-Loading terminal...}"  # Default message
  local duration=${2:-0.5}                  # Reduced default duration for speed
  local width=20                            # Reduced width for faster animation
  local color=$(random_color)               # Get random color
  local step_sleep=0.05                     # Faster sleep time

  echo -e "\033[${color}m${message}\033[0m"

  for ((i=0; i<=width; i++)); do
    local progress=$((i * 100 / width))
    local filled=$((i))
    local empty=$((width - filled))

    printf "\r\033[${color}m[\033[0m"
    printf "%*s" $filled | tr ' ' '█'
    printf "%*s" $empty | tr ' ' '░'
    printf "\033[${color}m] %d%%\033[0m" $progress

    sleep $step_sleep
  done
  printf "\r\033[K"  # Clear the line after animation
  echo
}

# Enhanced system information with animations
show_system_info() {
  local primary_color=$(random_color)
  local secondary_color=$(random_color)
  local accent_color=$(random_color)

  # Animated banner
  echo -e "\033[${primary_color}m"
  if command -v figlet &>/dev/null; then
    echo "Shadow@Bhanu" | figlet -f slant 2>/dev/null | while IFS= read -r line; do
      echo "$line"
      sleep 0.05
    done
  else
    gradient_text "Shadow@Bhanu"
  fi
  echo -e "\033[0m"

  # System info grid
  echo -e "\033[${secondary_color}m╔═══════════════════════════════════════════════════════════════════════╗\033[0m"
  echo -e "\033[${secondary_color}m║\033[0m \033[${accent_color}m🧠 ⟨ 👀 This ain't a shell 😒😏 it's a weaponized brain 💀😈 ⟩ 🧠\033[0m     \033[${secondary_color}m║\033[0m"
  echo -e "\033[${secondary_color}m╠═══════════════════════════════════════════════════════════════════════╣\033[0m"

  # System metrics
  local hostname=$(hostname 2>/dev/null || echo "UNKNOWN")
  local kernel=$(uname -r 2>/dev/null || echo "UNKNOWN")
  local os_info=$(lsb_release -d 2>/dev/null | cut -f2 || uname -o 2>/dev/null || echo "UNKNOWN")

  echo -e "\033[${secondary_color}m║\033[0m \033[38;2;0;255;255m🌐 HOST:\033[0m $hostname \033[38;2;255;0;255m⚡ KERNEL:\033[0m $kernel"
  echo -e "\033[${secondary_color}m║\033[0m \033[38;2;0;255;127m🖥️  OS:\033[0m $os_info"

  # Uptime and load
  if command -v uptime &>/dev/null; then
    local uptime_info=$(uptime -p 2>/dev/null | sed 's/up //' || echo "UNKNOWN")
    local load_avg=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | sed 's/^ *//' || echo "N/A")
    echo -e "\033[${secondary_color}m║\033[0m \033[38;2;255;255;0m⏱️  UPTIME:\033[0m $uptime_info"
    echo -e "\033[${secondary_color}m║\033[0m \033[38;2;255;127;0m📊 LOAD:\033[0m $load_avg"
  fi

  # Memory usage with visual bar
  if command -v free &>/dev/null; then
    local memory_info=$(free -m 2>/dev/null | awk 'NR==2{printf "%.1f%% (%dMB/%dMB)", $3*100/$2, $3, $2}' || echo "N/A")
    local memory_percent=$(free -m 2>/dev/null | awk 'NR==2{printf "%.0f", $3*100/$2}' || echo "0")
    local memory_bar=""
    for ((i=0; i<20; i++)); do
      if [[ $i -lt $((memory_percent/5)) ]]; then
        memory_bar+="█"
      else
        memory_bar+="░"
      fi
    done
    echo -e "\033[${secondary_color}m║\033[0m \033[38;2;127;0;255m🧠 MEMORY:\033[0m $memory_info \033[38;2;0;255;255m[$memory_bar]\033[0m"
  fi

  # Storage usage with visual bar
  if command -v df &>/dev/null; then
    local disk_info=$(df -h / 2>/dev/null | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}' || echo "N/A")
    local disk_percent=$(df / 2>/dev/null | awk 'NR==2{print $5}' | sed 's/%//' || echo "0")
    local disk_bar=""
    for ((i=0; i<20; i++)); do
      if [[ $i -lt $((disk_percent/5)) ]]; then
        disk_bar+="█"
      else
        disk_bar+="░"
      fi
    done
    echo -e "\033[${secondary_color}m║\033[0m \033[38;2;0;127;255m💾 STORAGE:\033[0m $disk_info \033[38;2;255;255;0m[$disk_bar]\033[0m"
  fi

  # CPU information
  if command -v lscpu &>/dev/null; then
    local cpu_info=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | sed 's/^ *//' | cut -c1-40 || echo "N/A")
    local cpu_temp=""
    if command -v sensors &>/dev/null; then
      cpu_temp=$(sensors 2>/dev/null | grep -i 'core 0' | awk '{print $3}' | head -1 || echo "")
      [[ -n "$cpu_temp" ]] && cpu_temp=" 🌡️$cpu_temp"
    fi
    echo -e "\033[${secondary_color}m║\033[0m \033[38;2;255;0;127m⚙️  CPU:\033[0m $cpu_info$cpu_temp"
  fi

  # Network interface
  if command -v ip &>/dev/null; then
    local ip_addr=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || echo "N/A")
    local interface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || echo "N/A")
    echo -e "\033[${secondary_color}m║\033[0m \033[38;2;0;255;191m🌍 IP:\033[0m $ip_addr \033[38;2;255;191;0m📡 INTERFACE:\033[0m $interface"
  fi

  # Current time and date
  local current_time=$(date '+%H:%M:%S %Z' 2>/dev/null || echo "N/A")
  local current_date=$(date '+%Y-%m-%d %A' 2>/dev/null || echo "N/A")
  echo -e "\033[${secondary_color}m║\033[0m \033[38;2;191;255;0m🕐 TIME:\033[0m $current_time \033[38;2;255;63;191m📅 DATE:\033[0m $current_date"

  # System stats
  local processes=$(ps aux 2>/dev/null | wc -l || echo "N/A")
  local users=$(who 2>/dev/null | wc -l || echo "N/A")
  echo -e "\033[${secondary_color}m║\033[0m \033[38;2;255;255;127m⚡ PROCESSES:\033[0m $processes \033[38;2;127;255;255m👥 USERS:\033[0m $users"

  echo -e "\033[${secondary_color}m╚═══════════════════════════════════════════════════════════════════════╝\033[0m"
}

# Enhanced dynamic greeting
time_based_greeting() {
  local hour=$(date +"%H")
  local day=$(date +"%A")
  local greeting
  local options=()
  local color=$(random_color)

  # Weather info (optional)
  local weather_info=""
  if command -v curl &>/dev/null && [[ -n "$DISPLAY" ]]; then
    weather_info=$(timeout 3 curl -s "wttr.in/?format=1" 2>/dev/null | head -1 || echo "")
  fi

  if [[ $hour -ge 5 && $hour -lt 12 ]]; then
    options=(
      "🌅 Morning, ⚔️ Shadow 😈 — time to hunt. ☕️"
      "🔥 Wake up, 👻 Shadow 😈 — systems ready, targets live. 🚀"
      "🌄 Good morning, 🛡️ Operator 😈 — AI agents waiting. 🕶️"
      "☀️ Dawn hits, 💀 Shadow 😈 — breach mode armed. ⚡"
      "🛠️ Morning ops online, 👁️ Shadow 😈 — let's break things."
      "🌞 Rise and shine, 💣 Shadow 😈 — $day domination begins!"
    )
  elif [[ $hour -ge 12 && $hour -lt 17 ]]; then
    options=(
      "🌞 Afternoon, 🚀 Shadow 😈 — kill protocols green. 💥"
      "💣 High noon, 👻 Shadow 😈 — swarm AI online. 🔥"
      "⚙️ Midday check, Shadow 😈 — cyber weapons hot. 🛡️"
      "🔓 Targets exposed, ⚡ Operator Shadow 😈 — hit hard."
      "💀 Afternoon ops ready, 😈 Shadow — time to hunt."
      "🌅 $day afternoon, 🗡️ Shadow 😈 — stealth mode active!"
    )
  elif [[ $hour -ge 17 && $hour -lt 21 ]]; then
    options=(
      "🌆 Evening, 💣 Shadow 😈 — ghosts in the wire. 👻"
      "⚡ Dusk falls, 😈 Shadow — time to breach. 🗡️"
      "🌇 Shadow 😈, targets in the dark — strike fast. 🔥"
      "🚨 Nightfall, Shadow 😈 — black ops mode. 💀"
      "🌌 Dark sky, 👁️ Shadow 😈 — infiltration started. 🚀"
      "🌙 $day evening, 🔥 Shadow 😈 — hunt in the shadows!"
    )
  else
    options=(
      "🌙 Midnight, 💀 Shadow 😈 — silent C2 linked. 🕶️"
      "🌃 Shadow 😈, night mode — hunt in silence. 🗡️"
      "💣 Zero hour, Shadow 😈 — time to attack. ⚡"
      "🛡️ No sleep, 👻 Shadow 😈 — systems watching. 👁️"
      "🕛 Late night, Shadow 😈 — kill chain active. 🚨"
      "🌌 $day night, 💀 Shadow 😈 — darkness is your ally!"
    )
  fi

  greeting="${options[$((RANDOM % ${#options[@]} + 1))]}"
  echo -e "\033[${color}m$greeting\033[0m"

  # Add weather info if available
  if [[ -n "$weather_info" ]]; then
    echo -e "\033[$(random_color)m🌤️  Weather: $weather_info\033[0m"
  fi

  echo -e "\033[$(random_color)m⚙️ AI Red Team Ops — Always Ready.\033[0m"
  echo
}

# Optimized clear function
clear() {
  command clear
  loading_animation "Initializing terminal..."

  if [[ -n "$WELCOME_DISPLAYED" ]]; then
    show_system_info
    time_based_greeting
  fi
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

  # Enhanced FZF configuration
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

# ===============================
# 💀 Welcome Display Function 💀
# ===============================
post_init_display() {
  if [[ -z "$WELCOME_DISPLAYED" ]]; then
    export WELCOME_DISPLAYED=1
    command clear

    # Show banner + system info
    show_system_info
    time_based_greeting

    # Load system visual tool (with loading fx)
    if command -v fastfetch &>/dev/null; then
      echo
      fastfetch
    elif command -v neofetch &>/dev/null; then
      loading_animation "🛰️ Gathering system info..."
      echo
      neofetch
    else
      echo "🚨 No system info tool (fastfetch/neofetch) found!"
    fi
  fi
}

add-zsh-hook precmd post_init_display

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
  typeset -g POWERLEVEL9K_CONTEXT_DEFAULT_FOREGROUND=196
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
