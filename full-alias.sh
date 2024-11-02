# alias_m0h3b.zsh


# Some useful nmap aliases for scan modes

# Nmap options are:
#  -sS - TCP SYN scan
#  -v - verbose
#  -T1 - timing of scan. Options are paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5)
#  -sF - FIN scan (can sneak through non-stateful firewalls)
#  -PE - ICMP echo discovery probe
#  -PP - timestamp discovery probe
#  -PY - SCTP init ping
#  -g - use given number as source port
#  -A - enable OS detection, version detection, script scanning, and traceroute (aggressive)
#  -O - enable OS detection
#  -sA - TCP ACK scan
#  -F - fast scan
#  --script=vuln - also access vulnerabilities in target

alias nmap_open_ports="nmap --open"
alias nmap_list_interfaces="nmap --iflist"
alias nmap_slow="sudo nmap -sS -v -T1"
alias nmap_fin="sudo nmap -sF -v"
alias nmap_full="sudo nmap -sS -T4 -PE -PP -PS80,443 -PY -g 53 -A -p1-65535 -v"
alias nmap_check_for_firewall="sudo nmap -sA -p1-65535 -v -T4"
alias nmap_ping_through_firewall="nmap -PS -PA"
alias nmap_fast="nmap -F -T5 --version-light --top-ports 300"
alias nmap_detect_versions="sudo nmap -sV -p1-65535 -O --osscan-guess -T4 -Pn"
alias nmap_check_for_vulns="nmap --script=vuln"
alias nmap_full_udp="sudo nmap -sS -sU -T4 -A -v -PE -PS22,25,80 -PA21,23,80,443,3389 "
alias nmap_traceroute="sudo nmap -sP -PE -PS22,25,80 -PA21,23,80,3389 -PU -PO --traceroute "
alias nmap_full_with_scripts="sudo nmap -sS -sU -T4 -A -v -PE -PP -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -PO --script all "
alias nmap_web_safe_osscan="sudo nmap -p 80,443 -O -v --osscan-guess --fuzzy "
alias nmap_ping_scan="nmap -n -sP"




alias-finder() {
  local cmd=" " exact="" longer="" cheaper="" wordEnd="'{0,1}$" finder="" filter=""

  # build command and options
  for c in "$@"; do
    case $c in
      # TODO: Remove backward compatibility (other than zstyle form)
      # set options if exist
      -e|--exact) exact=true;;
      -l|--longer) longer=true;;
      -c|--cheaper) cheaper=true;;
      # concatenate cmd
      *) cmd="$cmd$c " ;;
    esac
  done

  zstyle -t ':omz:plugins:alias-finder' longer && longer=true
  zstyle -t ':omz:plugins:alias-finder' exact && exact=true
  zstyle -t ':omz:plugins:alias-finder' cheaper && cheaper=true

  # format cmd for grep
  ## - replace newlines with spaces
  ## - trim both ends
  ## - replace multiple spaces with one space
  ## - add escaping character to special characters
  cmd=$(echo -n "$cmd" | tr '\n' ' ' | xargs | tr -s '[:space:]' | sed 's/[].\|$(){}?+*^[]/\\&/g')

  if [[ $longer == true ]]; then
    wordEnd="" # remove wordEnd to find longer aliases
  fi

  # find with alias and grep, removing last word each time until no more words
  while [[ $cmd != "" ]]; do
    finder="'{0,1}$cmd$wordEnd"

    # make filter to find only shorter results than current cmd
    if [[ $cheaper == true ]]; then
      cmdLen=$(echo -n "$cmd" | wc -c)
      filter="^'{0,1}.{0,$((cmdLen - 1))}="
    fi

    alias | grep -E "$filter" | grep -E "=$finder"

    if [[ $exact == true ]]; then
      break # because exact case is only one
    elif [[ $longer = true ]]; then
      break # because above grep command already found every longer aliases during first cycle
    fi

    cmd=$(sed -E 's/ {0,}[^ ]*$//' <<< "$cmd") # remove last word
  done
}

preexec_alias-finder() {
  # TODO: Remove backward compatibility (other than zstyle form)
  zstyle -t ':omz:plugins:alias-finder' autoload && alias-finder $1 || if [[ $ZSH_ALIAS_FINDER_AUTOMATIC = true ]]; then
    alias-finder $1
  fi
}

autoload -U add-zsh-hook
add-zsh-hook preexec preexec_alias-finder


alias apache2start='sudo /opt/local/etc/LaunchDaemons/org.macports.apache2/apache2.wrapper start'
alias apache2stop='sudo /opt/local/etc/LaunchDaemons/org.macports.apache2/apache2.wrapper stop'
alias apache2restart='sudo /opt/local/etc/LaunchDaemons/org.macports.apache2/apache2.wrapper restart'




# VS Code (stable / insiders) / VSCodium zsh plugin
# Authors:
#   https://github.com/MarsiBarsi (original author)
#   https://github.com/babakks
#   https://github.com/SteelShot
#   https://github.com/AliSajid

# Verify if any manual user choice of VS Code exists first.
if [[ -n "$VSCODE" ]] && ! which $VSCODE &>/dev/null; then
  echo "'$VSCODE' flavour of VS Code not detected."
  unset VSCODE
fi

# Otherwise, try to detect a flavour of VS Code.
if [[ -z "$VSCODE" ]]; then
  if which code &>/dev/null; then
    VSCODE=code
  elif which code-insiders &>/dev/null; then
    VSCODE=code-insiders
  elif which codium &>/dev/null; then
    VSCODE=codium
  else
    return
  fi
fi

function vsc {
  if (( $# )); then
    $VSCODE $@
  else
    $VSCODE .
  fi
}

alias vsca="$VSCODE --add"
alias vscd="$VSCODE --diff"
alias vscg="$VSCODE --goto"
alias vscn="$VSCODE --new-window"
alias vscr="$VSCODE --reuse-window"
alias vscw="$VSCODE --wait"
alias vscu="$VSCODE --user-data-dir"
alias vscp="$VSCODE --profile"

alias vsced="$VSCODE --extensions-dir"
alias vscie="$VSCODE --install-extension"
alias vscue="$VSCODE --uninstall-extension"

alias vscv="$VSCODE --verbose"
alias vscl="$VSCODE --log"
alias vscde="$VSCODE --disable-extensions"



#
# Defines Docker aliases.
#
# Author:
#   François Vantomme <akarzim@gmail.com>
#

#
# Aliases
#

# Docker
alias dk='docker'
alias dka='docker attach'
alias dkb='docker build'
alias dkd='docker diff'
alias dkdf='docker system df'
alias dke='docker exec'
alias dkE='docker exec -e COLUMNS=`tput cols` -e LINES=`tput lines` -i -t'
alias dkh='docker history'
alias dki='docker images'
alias dkin='docker inspect'
alias dkim='docker import'
alias dkk='docker kill'
alias dkkh='docker kill -s HUP'
alias dkl='docker logs'
alias dkL='docker logs -f'
alias dkli='docker login'
alias dklo='docker logout'
alias dkls='docker ps'
alias dkp='docker pause'
alias dkP='docker unpause'
alias dkpl='docker pull'
alias dkph='docker push'
alias dkps='docker ps'
alias dkpsa='docker ps -a'
alias dkr='docker run'
alias dkR='docker run -e COLUMNS=`tput cols` -e LINES=`tput lines` -i -t --rm'
alias dkRe='docker run -e COLUMNS=`tput cols` -e LINES=`tput lines` -i -t --rm --entrypoint /bin/bash'
alias dkRM='docker system prune'
alias dkrm='docker rm'
alias dkrmi='docker rmi'
alias dkrn='docker rename'
alias dks='docker start'
alias dkS='docker restart'
alias dkss='docker stats'
alias dksv='docker save'
alias dkt='docker tag'
alias dktop='docker top'
alias dkup='docker update'
alias dkV='docker volume'
alias dkv='docker version'
alias dkw='docker wait'
alias dkx='docker stop'

## Container (C)
alias dkC='docker container'
alias dkCa='docker container attach'
alias dkCcp='docker container cp'
alias dkCd='docker container diff'
alias dkCe='docker container exec'
alias dkCE='docker container exec -e COLUMNS=`tput cols` -e LINES=`tput lines` -i -t'
alias dkCin='docker container inspect'
alias dkCk='docker container kill'
alias dkCl='docker container logs'
alias dkCL='docker container logs -f'
alias dkCls='docker container ls'
alias dkCp='docker container pause'
alias dkCpr='docker container prune'
alias dkCrn='docker container rename'
alias dkCS='docker container restart'
alias dkCrm='docker container rm'
alias dkCr='docker container run'
alias dkCR='docker container run -e COLUMNS=`tput cols` -e LINES=`tput lines` -i -t --rm'
alias dkCRe='docker container run -e COLUMNS=`tput cols` -e LINES=`tput lines` -i -t --rm --entrypoint /bin/bash'
alias dkCs='docker container start'
alias dkCss='docker container stats'
alias dkCx='docker container stop'
alias dkCtop='docker container top'
alias dkCP='docker container unpause'
alias dkCup='docker container update'
alias dkCw='docker container wait'

## Image (I)
alias dkI='docker image'
alias dkIb='docker image build'
alias dkIh='docker image history'
alias dkIim='docker image import'
alias dkIin='docker image inspect'
alias dkIls='docker image ls'
alias dkIpr='docker image prune'
alias dkIpl='docker image pull'
alias dkIph='docker image push'
alias dkIrm='docker image rm'
alias dkIsv='docker image save'
alias dkIt='docker image tag'
alias dkIf='function dkIf_(){ docker images -f "reference=*/*/$1*" -f "reference=*$1*" }; dkIf_'

## Volume (V)
alias dkV='docker volume'
alias dkVin='docker volume inspect'
alias dkVls='docker volume ls'
alias dkVpr='docker volume prune'
alias dkVrm='docker volume rm'

## Network (N)
alias dkN='docker network'
alias dkNs='docker network connect'
alias dkNx='docker network disconnect'
alias dkNin='docker network inspect'
alias dkNls='docker network ls'
alias dkNpr='docker network prune'
alias dkNrm='docker network rm'

## System (Y)
alias dkY='docker system'
alias dkYdf='docker system df'
alias dkYpr='docker system prune'

## Stack (K)
alias dkK='docker stack'
alias dkKls='docker stack ls'
alias dkKps='docker stack ps'
alias dkKrm='docker stack rm'

## Swarm (W)
alias dkW='docker swarm'

## CleanUp (rm)
# Clean up exited containers (docker < 1.13)
alias dkrmC='docker rm $(docker ps -qaf status=exited)'

# Clean up dangling images (docker < 1.13)
alias dkrmI='docker rmi $(docker images -qf dangling=true)'

# Pull all tagged images
alias dkplI='docker images --format "{{ .Repository }}" | grep -v "^<none>$" | xargs -L1 docker pull'

# Clean up dangling volumes (docker < 1.13)
alias dkrmV='docker volume rm $(docker volume ls -qf dangling=true)'

# Docker Machine (m)
alias dkm='docker-machine'
alias dkma='docker-machine active'
alias dkmcp='docker-machine scp'
alias dkmin='docker-machine inspect'
alias dkmip='docker-machine ip'
alias dkmk='docker-machine kill'
alias dkmls='docker-machine ls'
alias dkmpr='docker-machine provision'
alias dkmps='docker-machine ps'
alias dkmrg='docker-machine regenerate-certs'
alias dkmrm='docker-machine rm'
alias dkms='docker-machine start'
alias dkmsh='docker-machine ssh'
alias dkmst='docker-machine status'
alias dkmS='docker-machine restart'
alias dkmu='docker-machine url'
alias dkmup='docker-machine upgrade'
alias dkmv='docker-machine version'
alias dkmx='docker-machine stop'

# Docker Compose (c)
if [[ $(uname -s) == "Linux" ]]; then
  alias dkc='docker-compose'
  alias dkcb='docker-compose build'
  alias dkcB='docker-compose build --no-cache'
  alias dkccf='docker-compose config'
  alias dkccr='docker-compose create'
  alias dkcd='docker-compose down'
  alias dkce='docker-compose exec -e COLUMNS=`tput cols` -e LINES=`tput lines`'
  alias dkcev='docker-compose events'
  alias dkci='docker-compose images'
  alias dkck='docker-compose kill'
  alias dkcl='docker-compose logs'
  alias dkcL='docker-compose logs -f'
  alias dkcls='docker-compose ps'
  alias dkcp='docker-compose pause'
  alias dkcP='docker-compose unpause'
  alias dkcpl='docker-compose pull'
  alias dkcph='docker-compose push'
  alias dkcpo='docker-compose port'
  alias dkcps='docker-compose ps'
  alias dkcr='docker-compose run -e COLUMNS=`tput cols` -e LINES=`tput lines`'
  alias dkcR='docker-compose run -e COLUMNS=`tput cols` -e LINES=`tput lines` --rm'
  alias dkcrm='docker-compose rm'
  alias dkcs='docker-compose start'
  alias dkcsc='docker-compose scale'
  alias dkcS='docker-compose restart'
  alias dkct='docker-compose top'
  alias dkcu='docker-compose up'
  alias dkcU='docker-compose up -d'
  alias dkcv='docker-compose version'
  alias dkcx='docker-compose stop'
else
  alias dkc='docker compose'
  alias dkcb='docker compose build'
  alias dkcB='docker compose build --no-cache'
  alias dkccp='docker compose copy'
  alias dkccr='docker compose create'
  alias dkccv='docker compose convert'
  alias dkcd='docker compose down'
  alias dkce='docker compose exec -e COLUMNS=`tput cols` -e LINES=`tput lines`'
  alias dkcev='docker compose events'
  alias dkci='docker compose images'
  alias dkck='docker compose kill'
  alias dkcl='docker compose logs'
  alias dkcL='docker compose logs -f'
  alias dkcls='docker compose ls'
  alias dkcp='docker compose pause'
  alias dkcP='docker compose unpause'
  alias dkcpl='docker compose pull'
  alias dkcph='docker compose push'
  alias dkcpo='docker compose port'
  alias dkcps='docker compose ps'
  alias dkcr='docker compose run -e COLUMNS=`tput cols` -e LINES=`tput lines`'
  alias dkcR='docker compose run -e COLUMNS=`tput cols` -e LINES=`tput lines` --rm'
  alias dkcrm='docker compose rm'
  alias dkcs='docker compose start'
  alias dkcsc='docker-compose scale'
  alias dkcS='docker compose restart'
  alias dkct='docker compose top'
  alias dkcu='docker compose up'
  alias dkcU='docker compose up -d'
  alias dkcv='docker-compose version'
  alias dkcx='docker compose stop'
fi

# Mutagen
alias mg='mutagen'
alias mgc='mutagen compose'
alias mgcb='mutagen compose build'
alias mgcB='mutagen compose build --no-cache'
alias mgcd='mutagen compose down'
alias mgce='mutagen compose exec -e COLUMNS=`tput cols` -e LINES=`tput lines`'
alias mgck='mutagen compose kill'
alias mgcl='mutagen compose logs'
alias mgcL='mutagen compose logs -f'
alias mgcls='mutagen compose ps'
alias mgcp='mutagen compose pause'
alias mgcP='mutagen compose unpause'
alias mgcpl='mutagen compose pull'
alias mgcph='mutagen compose push'
alias mgcps='mutagen compose ps'
alias mgcr='mutagen compose run -e COLUMNS=`tput cols` -e LINES=`tput lines`'
alias mgcR='mutagen compose run -e COLUMNS=`tput cols` -e LINES=`tput lines` --rm'
alias mgcrm='mutagen compose rm'
alias mgcs='mutagen compose start'
alias mgcsc='mutagen compose scale'
alias mgcS='mutagen compose restart'
alias mgcu='mutagen compose up'
alias mgcU='mutagen compose up -d'
alias mgcv='mutagen compose version'
alias mgcx='mutagen compose stop'


# ------------------------------------
# Docker alias and function
# ------------------------------------

# Get latest container ID
alias dl="docker ps -l -q"

# Get container process
alias dps="docker ps"

# Get process included stop container
alias dpa="docker ps -a"

# Get images
alias di="docker images"

# Get container IP
alias dip="docker inspect --format '{{ .NetworkSettings.IPAddress }}'"

# Run deamonized container, e.g., $dkd base /bin/echo hello
alias dkd="docker run -d -P"

# Run interactive container, e.g., $dki base /bin/bash
alias dki="docker run -i -t -P"

# Execute interactive container, e.g., $dex base /bin/bash
alias dex="docker exec -i -t"

# Stop all containers
dstop() { docker stop $(docker ps -a -q); }

# Remove all containers
drm() { docker rm $(docker ps -a -q); }

# Stop and Remove all containers
alias drmf='docker stop $(docker ps -a -q) && docker rm $(docker ps -a -q)'

# Remove all images
dri() { docker rmi $(docker images -q); }

# Dockerfile build, e.g., $dbu tcnksm/test 
dbu() { docker build -t=$1 .; }

# Show all alias related docker
dalias() { alias | grep 'docker' | sed "s/^\([^=]*\)=\(.*\)/\1 => \2/"| sed "s/['|\']//g" | sort; }

# Bash into running container
dbash() { docker exec -it $(docker ps -aqf "name=$1") bash; }



# WP-CLI
# A command line interface for WordPress
# https://wp-cli.org/

# Core
alias wpcc='wp core config'
alias wpcd='wp core download'
alias wpci='wp core install'
alias wpcii='wp core is-installed'
alias wpcmc='wp core multisite-convert'
alias wpcmi='wp core multisite-install'
alias wpcu='wp core update'
alias wpcudb='wp core update-db'
alias wpcvc='wp core verify-checksums'

# Cron
alias wpcre='wp cron event'
alias wpcrs='wp cron schedule'
alias wpcrt='wp cron test'

# Db
alias wpdbe='wp db export'
alias wpdbi='wp db import'
alias wpdbcr='wp db create'
alias wpdbs='wp db search'
alias wpdbch='wp db check'
alias wpdbr='wp db repair'

# Menu
alias wpmc='wp menu create'
alias wpmd='wp menu delete'
alias wpmi='wp menu item'
alias wpml='wp menu list'
alias wpmlo='wp menu location'

# Plugin
alias wppa='wp plugin activate'
alias wppda='wp plugin deactivate'
alias wppd='wp plugin delete'
alias wppg='wp plugin get'
alias wppi='wp plugin install'
alias wppis='wp plugin is-installed'
alias wppl='wp plugin list'
alias wppp='wp plugin path'
alias wpps='wp plugin search'
alias wppst='wp plugin status'
alias wppt='wp plugin toggle'
alias wppun='wp plugin uninstall'
alias wppu='wp plugin update'

# Post
alias wppoc='wp post create'
alias wppod='wp post delete'
alias wppoe='wp post edit'
alias wppogen='wp post generate'
alias wppog='wp post get'
alias wppol='wp post list'
alias wppom='wp post meta'
alias wppou='wp post update'
alias wppourl='wp post url'

# Sidebar
alias wpsbl='wp sidebar list'

# Theme
alias wpta='wp theme activate'
alias wptd='wp theme delete'
alias wptdis='wp theme disable'
alias wpte='wp theme enable'
alias wptg='wp theme get'
alias wpti='wp theme install'
alias wptis='wp theme is-installed'
alias wptl='wp theme list'
alias wptm='wp theme mod'
alias wptp='wp theme path'
alias wpts='wp theme search'
alias wptst='wp theme status'
alias wptu='wp theme update'

# User
alias wpuac='wp user add-cap'
alias wpuar='wp user add-role'
alias wpuc='wp user create'
alias wpud='wp user delete'
alias wpugen='wp user generate'
alias wpug='wp user get'
alias wpui='wp user import-csv'
alias wpul='wp user list'
alias wpulc='wp user list-caps'
alias wpum='wp user meta'
alias wpurc='wp user remove-cap'
alias wpurr='wp user remove-role'
alias wpusr='wp user set-role'
alias wpuu='wp user update'

# Widget
alias wpwa='wp widget add'
alias wpwda='wp widget deactivate'
alias wpwd='wp widget delete'
alias wpwl='wp widget list'
alias wpwm='wp widget move'
alias wpwu='wp widget update'


# Completion for wp
autoload -U +X bashcompinit && bashcompinit
_wp_complete() {
	local cur=${COMP_WORDS[COMP_CWORD]}

	IFS=$'\n';  # want to preserve spaces at the end
	local opts="$(wp cli completions --line="$COMP_LINE" --point="$COMP_POINT")"

	if [[ "$opts" =~ \<file\>\s* ]]
	then
		COMPREPLY=( $(compgen -f -- $cur) )
	elif [[ $opts = "" ]]
	then
		COMPREPLY=( $(compgen -f -- $cur) )
	else
		COMPREPLY=( ${opts[*]} )
	fi
}
complete -o nospace -F _wp_complete wp

alias sv="snap version"
alias sf="snap find"
alias si="snap install"
alias sin="snap info"
alias sr="snap remove"
alias sref="snap refresh"
alias srev="snap revert"
alias sl="snap list"
alias sd="snap disable"
alias se="snap enable"

alias pipi="pip install"
alias pipu="pip install --upgrade"
alias pipun="pip uninstall"
alias pipgi="pip freeze | grep"
alias piplo="pip list -o"

# Create requirements file
alias pipreq="pip freeze > requirements.txt"

# Install packages from requirements file
alias pipir="pip install -r requirements.txt"

# Find python file
alias pyfind='find . -name "*.py"'

# Share local directory as a HTTP server
alias pyserver="python3 -m http.server"
