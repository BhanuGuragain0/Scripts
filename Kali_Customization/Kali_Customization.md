

# Shadow@Bhanu KALI Customization Setup

This repository contains a collection of commands, aliases, functions, and environment customizations to enhance your Kali Linux experience. The setup includes improvements for file listings, system updates, boot aesthetics, shell enhancements for both Zsh and Bash, and even a cool hacker banner for root sessions.

---

## Table of Contents

- [Better Directory Listing with eza](#better-directory-listing-with-eza)
- [System Update Alias](#system-update-alias)
- [Enhanced Search and File Commands](#enhanced-search-and-file-commands)
- [Plymouth Themes for Boot Customization](#plymouth-themes-for-boot-customization)
- [Fastfetch Installation](#fastfetch-installation)
- [Custom MOTD and Issue Messages](#custom-motd-and-issue-messages)
- [TLDR for Simplified Man Pages](#tldr-for-simplified-man-pages)
- [GRUB2 Themes](#grub2-themes)
- [Shell Enhancements for Zsh](#shell-enhancements-for-zsh)
  - [Powerlevel10k Setup](#powerlevel10k-setup)
  - [Autosuggestions & Syntax Highlighting](#zsh-autosuggestions-and-syntax-highlighting)
  - [Additional LS & Script Aliases](#additional-ls--script-aliases)
  - [Dynamic Terminal Message Functions](#dynamic-terminal-message-functions)
  - [Prompt Customization](#prompt-customization)
- [Bash Specific Customizations](#bash-specific-customizations)
- [Additional Environment Variables](#additional-environment-variables)
- [Root and System-Wide Customizations](#root-and-system-wide-customizations)
  - [PATH and PS1 Setup](#path-and-ps1-setup)
  - [Hacker Banner](#hacker-banner)

---

## Better Directory Listing with eza

**Purpose:** Replace the default `ls` with [eza](https://github.com/eza-community/eza) for a modern, icon-supported, long-format directory listing.

```bash
# Install eza
sudo apt install eza -y

# Alias ls to use eza with icons, long listing, and directories-first sorting
alias ls='eza --icons --long --group-directories-first'

# To persist this change, add the alias to your shell configuration (e.g., ~/.zshrc)
sudo nano ~/.zshrc
```

---

## System Update Alias

**Purpose:** Create a single command to perform a comprehensive system update and upgrade.

```bash
alias update="sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt dist-upgrade -y && sudo apt update --fix-missing -y && sudo apt upgrade --fix-missing -y"

# Append the alias to your shell configuration:
echo 'alias update="sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt dist-upgrade -y && sudo apt update --fix-missing -y && sudo apt upgrade --fix-missing -y"' >> ~/.zshrc
```

---

## Enhanced Search and File Commands

**Purpose:** Use faster, color-enhanced utilities for searching text and locating files.

```bash
# Use ripgrep for faster, colored grep output
alias grep='rg --color=auto'

# Use fd for an improved find experience
alias find='fd'
```

---

## Plymouth Themes for Boot Customization

**Purpose:** Customize your boot splash screen with Plymouth themes.

```bash
# Install Plymouth and its themes
sudo apt install plymouth plymouth-themes -y

# List available themes
plymouth-set-default-theme --list

# Set a default theme (example: spinfinity)
sudo plymouth-set-default-theme -R spinfinity

# Optional: To try another theme (e.g., script)
cd /usr/share/plymouth/themes/
sudo plymouth-set-default-theme -R script
```

---

## Fastfetch Installation

**Purpose:** Install [fastfetch](https://github.com/fastfetch-cli/fastfetch) to display system information on terminal startup.

```bash
sudo apt install fastfetch
echo "fastfetch" >> ~/.zshrc
```

---

## Custom MOTD and Issue Messages

**Purpose:** Personalize login messages by customizing the system’s MOTD and issue files.

```bash
# Edit /etc/issue for login messages
sudo nano /etc/issue
# Add:
# 🔥 WELCOME TO Shadow@Bh4nu KALI 😈🔥

# Edit /etc/motd to set the welcome message
sudo nano /etc/motd
# Add:
# 🔥 WELCOME TO Shadow@Bh4nu KALI 😈🔥
```

---

## TLDR for Simplified Man Pages

**Purpose:** Install TLDR pages for concise command usage examples.

```bash
sudo apt install tldr -y

# Example usage:
tldr find
tldr nmap
```

---

## GRUB2 Themes

**Purpose:** Apply a custom theme to the GRUB bootloader for a sleek boot menu.

```bash
# Clone the GRUB2 themes repository
git clone https://github.com/vinceliuice/grub2-themes.git
cd grub2-themes

# Install the 'tela' theme in batch mode
sudo ./install.sh -b -t tela

# Optionally set the GRUB theme path if needed
GRUB_THEME="/boot/grub/themes/tela/theme.txt"

# Update GRUB and reboot to see the changes
sudo update-grub
reboot
```

---

## Shell Enhancements for Zsh

### Powerlevel10k Setup

**Purpose:** Install Zsh and configure the [Powerlevel10k](https://github.com/romkatv/powerlevel10k) theme for a customizable and visually appealing prompt.

```bash
sudo apt install zsh git -y
chsh -s $(which zsh)
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/.powerlevel10k
echo 'source ~/.powerlevel10k/powerlevel10k.zsh-theme' >> ~/.zshrc
exec zshchsh -s $(which zsh)

p10k configure
```

### Zsh Autosuggestions and Syntax Highlighting

**Purpose:** Enhance your command-line experience with real-time suggestions and syntax highlighting.

```bash
sudo apt install zsh-autosuggestions zsh-syntax-highlighting -y
echo 'source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh' >> ~/.zshrc
echo 'source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh' >> ~/.zshrc
source ~/.zshrc
```

### Additional LS & Script Aliases

**Purpose:** Define extra aliases for listing directories and launching your custom scripts. These are common to both Zsh and Bash.

```bash
# Enhanced ls aliases
alias ls='eza --icons --long --group-directories-first'
alias ll='ls -l'
alias la='ls -A'
alias l='ls -CF'

# Custom script aliases
alias setup="python3 ~/Scripts/wifi_auto_login.py"
alias server="bash /home/bhanu/Scripts/server.sh"
```

> *Note:* Some of these aliases might already be set in your configuration. Adjust paths as needed.

### Dynamic Terminal Message Functions

**Purpose:** Display a dynamic, colorized welcome message with a typewriter effect each time the terminal starts or is cleared.

```bash
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
  typewriter_effect "Shadow@Bhanu" 0.1 | figlet -f slant
  echo -e "\033[0m"
}

# Time-based function to display the welcome message (customize by time if desired)
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
```

### Prompt Customization

**Purpose:** Set a personalized, colorized prompt for Zsh.

```bash
export PS1="%F{green}Shadow@Bhanu%f:%F{red}%~%f ~ "
```

---

## Bash Specific Customizations

If you use Bash instead of Zsh, consider these additional tweaks:

- **Additional LS & Script Aliases:**  
  (Same as in the Zsh section; add these to your `~/.bash_aliases` or `~/.bashrc`.)

- **Bash Aliases Sourcing:**  
  To automatically load your aliases if stored in `~/.bash_aliases`:
  ```bash
  if [ -f ~/.bash_aliases ]; then
      . ~/.bash_aliases
  fi
  ```

- **Programmable Completion:**  
  Enable bash completion if not already active:
  ```bash
  if ! shopt -oq posix; then
    if [ -f /usr/share/bash-completion/bash_completion ]; then
      . /usr/share/bash-completion/bash_completion
    elif [ -f /etc/bash_completion ]; then
      . /etc/bash_completion
    fi
  fi
  ```

- **Dynamic Terminal Message Functions:**  
  You can also add the same functions for a dynamic welcome in your `~/.bashrc`.

- **Bash Prompt Customization:**  
  Example prompt settings (adjust as needed):
  ```bash
  export PS1="\[\e[1;32m\]\u@\h:\w# \[\e[0m\]"
  ```
  *(Note: The provided prompt lines may include duplicate or misencoded characters. Adjust them to suit your preferences.)*

---

## Additional Environment Variables

**Purpose:** Set variables to optimize application performance. For example, this setting improves PyTorch CUDA memory allocation:

```bash
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
```

---

## Root and System-Wide Customizations

These settings apply to system-wide profiles (typically in `/etc/profile`) or for the root user.

### PATH and PS1 Setup

**Purpose:**  
Ensure the correct PATH is set for root versus non-root users and define a default prompt.

```bash
if [ "$(id -u)" -eq 0 ]; then
  PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
else
  PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
fi
export PATH

if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  else
    if [ "$(id -u)" -eq 0 ]; then
      PS1='# '
    else
      PS1='$ '
    fi
  fi
fi

if [ -d /etc/profile.d ]; then
  for i in $(run-parts --list --regex '^[a-zA-Z0-9_][a-zA-Z0-9._-]*\.sh$' /etc/profile.d); do
    if [ -r $i ]; then
      . $i
    fi
  done
  unset i
fi
```

### Hacker Banner

**Purpose:**  
Display a fun, “hacker-style” banner on terminal start for root sessions using the `toilet` command.

```bash
toilet -f mono12 -F metal "Shadow"
```

---

## Usage

1. **Backup:** Always back up your existing configuration files (like `~/.zshrc` or `~/.bashrc`) before making changes.
2. **Apply:** Copy the relevant sections into your configuration files.
3. **Reload:** Run `source ~/.zshrc` or `source ~/.bashrc` (or restart your terminal) to apply the changes.

---
