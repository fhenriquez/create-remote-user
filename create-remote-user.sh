#!/usr/bin/env bash
#################################################################################
# Name: create-remote-user.sh                                                   #
# Author: Franklin Henriquez                                                    #
# Date: 16Dec2015                                                               #
# Description: Creates user on servers from a file. It will also copy the .ssh  #
# directory and lock the password of the given users. The scrip has some error  #
# handling, it checks if it can ssh into the host, if it can ping it and        #
# there is a dns entry, outputting it's findings to a file.                     #
#                                                                               #
#################################################################################

# Required binaries:
# - bash v4+
# - ping
# - nslookup
# - getopt
#

# Notes:
# This script uses assossiated arrays which were introduce in bash v4.
#
__version__="2.2.0"
__author__="Franklin Henriquez"
__email__="franklin.a.henriquez@gmail.com"

# Set magic variables for current file & dir
__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[0]}")"
__base="$(basename ${__file} .sh)"
__root="$(cd "$(dirname "${__dir}")" && pwd)"

# Color Codes
# Reset
Color_Off='\033[0m'       # Text Reset
NC='\e[m'                 # Color Reset
# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White
# High Intensity
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White


# DESC: What happens when ctrl-c is pressed
# ARGS: None
# Trap ctrl-c and call ctrl_c()
trap ctrl_c INT


function ctrl_c() {
    info "Trapped CTRL-C signal, terminating script"
    logger "\n================== $(date +'%Y-%m-%d %H:%M:%S'): Run Interrupted  ==================\n"
    rm -f ${TEMP_FILE}
    exit 2
}


# Setting up logging
exec 3>&2 # logging stream (file descriptor 3) defaults to STDERR
verbosity=3 # default to show warnings
silent_lvl=0
crt_lvl=1
err_lvl=2
wrn_lvl=3
inf_lvl=4
dbg_lvl=5
bash_dbg_lvl=6

notify() { log $silent_lvl "${Cyan}NOTE${Color_Off}: $1"; } # Always prints
critical() { log $crt_lvl "${IRed}CRITICAL:${Color_Off} $1"; }
error() { log $err_lvl "${Red}ERROR:${Color_Off} $1"; }
warn() { log $wrn_lvl "${Yellow}WARNING:${Color_Off} $1"; }
info() { log $inf_lvl "${Blue}INFO:${Color_Off} $1"; } # "info" is already a command
debug() { log $dbg_lvl "${Purple}DEBUG:${Color_Off} $1"; }
log() {
    if [ "${verbosity}" -ge "${1}" ]; then
        datestring=$(date +'%Y-%m-%d %H:%M:%S')
        # Expand escaped characters, wrap at 70 chars, indent wrapped lines
        echo -e "$datestring - __${FUNCNAME[2]}__  - $2" >&3 #| fold -w70 -s | sed '2~1s/^/  /' >&3
    fi
}


logger() {
    if [ -n "${LOG_FILE}" ]
    then
        echo -e "$1" >> "${log_file}"
        #echo -e "$1" >> "${LOG_FILE/.log/}"_"$(date +%d%b%Y)".log
    fi
}


# DESC: Usage help
# ARGS: None
usage() {
    echo -e "\
    \rUsage: $0 -u <user_file> -s <server_file>
    \rDescription: Checks if user from file exist in a list of servers.

    \rrequired arguments:
    \r-u, --user <file>\t User credential file, see file example below.
    \r-s, --server <file>\t List of server, see file example below.

    \roptional arguments:
    \r-a, --auth-keys <file>\t Add public ssh key to authorized_keys file.
    \r-c, --check \t\t Check if user exist on the remote servers.
    \r-d, --disable \t\t Delete user.
    \r-e, --enable \t\t Create user.
    \r-h, --help\t\t Show this help message and exit.
    \r-k, --key\t\t Create user with password.
    \r-l, --log <file>\t Log file.
    \r-p, --ping\t\t Ping remote server if you cannot ssh into it.
    \r-r, --remote-user\t Check if remote user can login to remote servers.
    \r-w, --password\t\t Server file contian's password instead of key.
    \r-x, --exmaple\t\t Show example of User credential and Server file.
    \r-v, --verbose\t\t Verbosity.
    \r             \t\t -v info
    \r             \t\t -vv debug
    \r             \t\t -vvv bash debug"

    return 0
}


# DESC: File Example
# ARGS: None
example_file () {

    echo -e "\
    \r###################################################################
    \r# User credentail file example                                    #
    \r# ----------------------------------------------------------------#
    \r# <UID>  <username> <password>  <GID>  <group_name>               #
    \r# <username> ALL=(ALL) NOPASSWD: ALL                              #
    \r# ----------------------------------------------------------------#
    \r# 1234 bestuser bestpassword 5678 bestgroup                       #
    \r# bestuser ALL=(ALL) NOPASSWD: ALL                                #
    \r###################################################################

    \r###################################################################
    \r# Server file example                                             #
    \r# ----------------------------------------------------------------#
    \r# <host>,<ssh_username>,<ssh_key_path>                            #
    \r# ----------------------------------------------------------------#
    \r# 192.168.1.19,cloud-user,/path/to/ssh_key                        #
    \r# bestinstance,cloud-user,/path/to/ssh_key2                       #
    \r###################################################################
    "

    return 0
}


# DESC: Parse arguments
# ARGS: main args
function parse_args() {

    local short_opts='a:,c,d,e,h,k,l:,p,r,s:,u:,v,w,x'
    local long_opts='auth-keys:,check,enable,example,disable,help,key,log:,password,ping,remote-user,server:,user:,verbose'

    # -use ! and PIPESTATUS to get exit code with errexit set
    # -temporarily store output to be able to check for errors
    # -activate quoting/enhanced mode (e.g. by writing out “--options”)
    # -pass arguments only via   -- "$@"   to separate them correctly
    ! PARSED=$(getopt --options=${short_opts} --longoptions=${long_opts} --name "$0" -- "$@")
    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        # e.g. return value is 1
        #  then getopt has complained about wrong arguments to stdout
        debug "getopt has complained about wrong arguments"
        exit 2
    fi
    # read getopt’s output this way to handle the quoting right:
    eval set -- "$PARSED"

    if [[ "${PARSED}" == " --" ]]
    then
        debug "No arguments were passed"
        usage
        exit 1
    fi

    # extract options and their arguments into variables.
    while true ; do
        case "$1" in

            -a | --auth-keys)
                add_ssh_pub="true"
                ssh_pub_key_file="$2"
                shift 2
                ;;
            -c | --check )
                CHECK_USER="true"
                shift
                ;;
            -e | --enable )
                ADD_USER="true"
                CHECK_USER="true"
                shift
                ;;
            -d | --disable )
                RM_USER="true"
                CHECK_USER="true"
                shift
                ;;
            -h | --help )
                # Display usage.
                usage
                exit 1;
                ;;
            -k | --key)
                ADD_USER="true"
                CHECK_USER="true"
                ADD_USER_WITH_PASSWD="true"
                shift
                ;;
            -l | --log)
                LOG_FILE="$2"
                log_file="${LOG_FILE/.log/}"_"$(date +%d%b%Y)".log
                shift 2
                ;;
            -p | --ping)
                CHECK_REMOTE_SERVER="true"
                shift
                ;;
             -r | --remote_user )
                CHECK_REMOTE_USER="true"
                CHECK_USER="false"
                shift
                ;;
            -s | --server )
                server_list_file="$2"
                shift 2
                ;;
            -v | --verbose)
                (( verbosity = verbosity + 1 ))
                if [ $verbosity -eq $bash_dbg_lvl ]
                then
                    DEBUG="true"
                fi
                shift
                ;;
            -u | --user)
                user_file="$2"
                shift 2
                ;;
            -w | --password)
                server_file_password="true"
                shift
                ;;
            -x | --example)
                # Display exmaple.
                example_file
                exit 1;
                ;;
            -- )
                shift
                break ;;
            * )
                usage
                exit 3
        esac
    done

    return 0
}


# DESC: Checks if remote server availability.
# ARGS: <server> <user> <ssh_key>
function check_remote_server() {

    local server="$1"
    local user="$2"
    local ssh_key="$3"

    # Since the ssh_test response is a string grab all
    # of it to parse later.
    local ssh_test="${*:4}"

    info "Validating ${server} availability"

    debug "ping -c 3 ${server}"
    local ping_result
    ping_result=$(ping -c 3 ${server})
    local ping_test_exit="$?"
    debug "ping result ${ping_test_exit}"
    debug "ping result ${ping_result}"

    dns_look_up=$(nslookup ${server} | grep can)
    debug "dns response: ${dns_look_up}"

    if (( "${ssh_test_exit}" == 255 ))
    then
        error "${ssh_test}"
        echo "${ssh_test}"
    # If ping_test_exit is 1, server cannot be ping.
    elif [[ "${ping_test_exit}" -gt 0 ]]
    then
        error "Unable to ping ${server}"
        echo "unable to ping"
   elif [[ "$dns_look_up" == *"server can"* ]]
   then
        error "${dns_look_up}"
        echo "${dns_look_up}"
    elif [[ "${ping_test_exit}" -eq 0 ]]
    then
        error "Can ping ${server}, login error"
        echo "login error"
    else
        error "${server}: unknown error"
        echo "${server}: ssh timedout"
    fi

    return 0
}


# DESC: Checks if remote user already exist.
# ARGS: Array of remote server info.
function check_remote_user() {

    eval "declare -A local server_array="${1#*=}
    for key in "${!server_array[@]}"
    do
        debug "key: ${key}  value: ${server_array[${key}]}"
    done

    local remote_server=${server_array[remote_server]}
    debug "Remote server ${remote_server}"
    local remote_username=${server_array[remote_username]}
    debug "Remote user ${remote_username}"
    local ssh_id_file=${server_array[ssh_id_file]}
    debug "ssh key ${ssh_id_file}"

    # Check if SSH key is available.
    if [[ "${server_array[ssh_test]}" == *"No such file or directory"* ]]
    then
            error "${ssh_id_file} not found"
            local resp=$(echo -e "${server_array[ssh_test]}" | head -1)
            echo "${remote_server}: ${resp}"
            return 4
    fi

    info "Validating ${remote_user} user is able to connect to ${remote_server} using ${ssh_id_file} file"
    local ssh_test="${server_array[ssh_test]}"
    local ssh_test_exit="${server_array[ssh_test_exit]}"
    debug "ssh exit code: ${ssh_test_exit}"
    debug "ssh test response: ${ssh_test}"
    #ssh_test_exit=123

    # If ssh_test_exit is 0 are you able to ssh, if it returns greater than 1 there is a problem
    if (( "${ssh_test_exit}" >= 1 ))
    then
        error "Unable to login to ${remote_server}"
        debug "check remote server: ${CHECK_REMOTE_SERVER}"
        if [[ "${CHECK_REMOTE_SERVER}" == "true" ]]
        then
            response=$(check_remote_server ${remote_server} ${remote_username} ${ssh_id_file} ${ssh_test})
            echo "${remote_server}: ${response}"
        else
            echo "${remote_server}: ${ssh_test}"
        fi
    elif [[ "${CHECK_USER}" == "true" ]]
    then
        debug "check_user "${line[@]}""
        check_user "$(declare -p line)"
    else
        echo "${remote_server}: ${remote_username} | ${ssh_id_file} | successfully login"
    fi

   return 0
}


# DESC: Checks if user already exist on remote.
# ARGS: Array of remote server info.
function check_user() {

    # This gets server info from array.
    debug "server info array"
    eval "declare -A local server_array="${1#*=}
    for key in "${!server_array[@]}"
    do
        if [[ "${server_file_password}" == "true" && "${key}" == "ssh_id_file" ]]
        then
            debug "Using password: "${IYellow}REDACTED${Color_Off}""
        else
            debug "key: ${key}  value: ${server_array[${key}]}"
        fi
    done

    local remote_server=${server_array[remote_server]}
    debug "Remote server ${remote_server}"
    local remote_username=${server_array[remote_username]}
    debug "Remote user ${remote_username}"
    local ssh_id_file=${server_array[ssh_id_file]}
    if [ "${server_file_password}" != "true" ]
    then
        debug "ssh key ${ssh_id_file}"
    fi

    # Check if SSH key is available.
    if [ "${server_file_password}" == "true" ]
    then
        debug "Logging with password instead of ssh key"
    elif [[ "${server_array[ssh_test]}" == *"No such file or directory"* ]]
    then
            error "${ssh_id_file} not found"
            local resp=$(echo -e "${server_array[ssh_test]}" | head -1)
            echo "${remote_server}: ${resp}"
            return 4
    fi

    info "Validating user exist in remoter server:: ${remote_server}"
    info "Gathering user credentials to create on remote server"

    # Searching for user's existance on remote server and
    # checking to see if they are in the sudoers file.
    # Note the redirection to stderr to stdout.
    # To catch any permissions errors.
    local ssh_cmd1
    local ssh_cmd2

    # Creates user.
    ssh_cmd1="if (grep -q -e '^${USER_INFO[user_name]}\|${USER_INFO[user_id]}\|${USER_INFO[user_home]}' /etc/passwd)
            then
              grep -o -e '^${USER_INFO[user_name]}\|${USER_INFO[user_id]}\|${USER_INFO[user_home]}' /etc/passwd | uniq
            else
              echo 'user does not exist'
            fi"
    # Appends sudoer's file.
    ssh_cmd2="if (sudo grep -q -o '"${USER_INFO[user_sudo]}"' /etc/sudoers)
            then
                sudo grep -o '"${USER_INFO[user_sudo]}"' /etc/sudoers
            else
                echo 'sudoer is not valid'
            fi 2>&1"

    echo -e "#!/bin/bash
            ${ssh_cmd1}
            ${ssh_cmd2}
            exit" > ${TEMP_FILE}
    local ssh_cmd="${ssh_cmd1}; ${ssh_cmd2}"
    local ssh_cmd_response

    #ssh_cmd_response=$(ssh ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} "${ssh_cmd}"; echo $?)
    if [ "${server_file_password}" == "true" ]
    then
        debug "cat ${TEMP_FILE} | sshpass -p "${IYellow}REDACTED${Color_Off}" ssh -t -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${remote_username}@${remote_server}"
        ssh_cmd_response=$(cat ${TEMP_FILE} | sshpass -p "${ssh_id_file}" ssh -t -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${remote_username}@${remote_server} 'bash -s' 2> /dev/null)
    else
        debug "cat ${TEMP_FILE} | ssh -vvv -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server}"
        ssh_cmd_response=$(cat ${TEMP_FILE} | ssh -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} 'bash -s' 2> /dev/null)
    fi

    local ssh_cmd_exit="$?"
    debug "ssh exit code: ${ssh_cmd_exit}"
    debug "ssh response\n ${ssh_cmd_response}"


    # Redacting password.
    if [ "${server_file_password}" == "true" ]
    then
        ssh_id_file="REDACTED"
    fi

    # If ssh_cmd_exit is 0 are you able to ssh, if it returns greater than 1 there is a problem
    if [[ "${ssh_cmd_exit}" -ne 0 ]]
    then
        if (( "${ssh_cmd_exit}" == 255 ))
        then
            error "Invalid SSHKey(${ssh_id_file}) for ${remote_server}"
            # Testing is ssh cmd response is blank,
            # look back to the first ssh test and
            # take that output.
            if [ " " == "${ssh_cmd_response}" ]
            then
                echo "${ssh_cmd_response}"
                return 1
            else
                echo "${server_array[ssh_test]}"
                return 1
            fi
        elif (( "${ssh_cmd_exit}" > 1 ))
        then
            error "Unable to login to ${remote_server}"
            echo "${remote_server}: unable to login"
            return 1
        fi
    elif [[ "${ssh_cmd_response}" == *"not exist"* ]]
    then
        # Parsing the extra stderr lines.
        fix_output=$(echo ${ssh_cmd_response//sudo*/} | head -n 1)
        warn "${fix_output}"
        #warn "${ssh_cmd_response}"
        echo "${remote_server}: user does not exist"
        return 0
    else
        info "${USER_INFO[user_name]} exist on ${remote_server}"

        # Validate that the user has the exact setting per user_file.
        info "Validating ${USER_INFO[user_name]}"

        # Modified IFS to newline in order to parse ssh_cmd_response,
        # otherwise output would be a single line.
        OLD_IFS="${IFS}"
        IFS=$'\n'
        local query_term=("${USER_INFO[user_name]}" "${USER_INFO[user_id]}"
                        "${USER_INFO[user_home]}" "${USER_INFO[user_sudo]}")

        local valid_user=()
        local turn=0
        for value in ${ssh_cmd_response}
        do
            debug "query: ${query_term[${turn}]}, value: ${value}"
            if [[ "${value}" == *"sorry"* ]]
            then
                IFS="${OLD_IFS}"
                local ssh_cmd3
                local ssh_sudo_cmd_resp
                local ssh_cmd3="sudo grep '${USER_INFO[user_sudo]}' /etc/sudoers"

                # This to bypass a TTY bug, it will send a easier command to get sudoer line.
                debug "Re-checking sudoers"
                ssh_sudo_cmd_resp=$(ssh -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} "${ssh_cmd3}" 2> /dev/null)
                debug "${ssh_cmd3}"
                debug "re-check sudoers file response: ${ssh_sudo_cmd_resp}"
                value=${ssh_sudo_cmd_resp}
            fi

            if ! [[ "${query_term[${turn}]}" ==  "" ]]
            then
                if [[ "${query_term[${turn}]}" ==  "${value}" ]]
                then
                    debug "${remote_server}: ${value} is valid"
                    valid_user[${turn}]+="${value} is valid,"
                else
                    if [[ "${turn}" -eq  3 ]]
                    then
                        debug "${remote_server}: ${value} not is valid"
                        valid_user[${turn}]+="${value} not is valid,"
                    else
                        valid_user[${turn}]+="${value} undetermined"
                    fi
                fi
            fi

            turn=$((turn + 1))
        done

        # Checking sudoer file validiy, we dont want the log
        # file containing excessive information.
        if [[ "${valid_user[3]}" == *"is not"* ]]
        then
            valid_user[3]="sudoers file is not valid, user not found,"
        elif [[ "${valid_user[3]}" == *"is valid"* ]]
        then
            valid_user[3]="sudoers file is valid,"
        else
            debug "${valid_user[3]}"
            valid_user[3]="sudoer file is not valid, unknown reason,"
        fi

        # Remove the last char which is a comma
        local log_str=$(echo ${valid_user[*]})

        echo "${remote_server}: ${log_str::-1}."
    fi

    # Make sure IFS returns to original value.
    IFS="${OLD_IFS}"

    return 0
}


# DESC: Create user on remote.
# ARGS: Array of remote server info.
function create_user() {

    info "Creating user ${USER_INFO[user_name]} on ${server_array[remote_username]}"
    info "Gathering user credentials to create on remote server"

    # This gets server info from array.
    debug "server info array"
    eval "declare -A local server_array="${1#*=}
    for key in "${!server_array[@]}"
    do
        debug "key: ${key}  value: ${server_array[${key}]}"
    done

    local remote_server=${server_array[remote_server]}
    debug "Remote server ${remote_server}"
    local remote_username=${server_array[remote_username]}
    debug "Remote user ${remote_username}"
    local ssh_id_file=${server_array[ssh_id_file]}
    debug "ssh key ${ssh_id_file}"

    # Creating user on remote server and
    # adding to the sudoers file.
    # Note the redirection to stderr to stdout.
    # To catch any permissions errors.
    #local ssh_cmd1="grep -o -e '^${USER_INFO[user_name]}\|${USER_INFO[user_id]}\|${USER_INFO[user_home]}' /etc/passwd | uniq"

    if [ "${ADD_USER_WITH_PASSWD}" == "true" ]
    then
        info "Creating user with password"
        local ssh_create_user_cmd="sudo groupadd -g ${USER_INFO[group_id]} ${USER_INFO[group_name]};
                    sudo useradd -u ${USER_INFO[user_id]} -G ${USER_INFO[group_name]} -s /bin/bash -c '${USER_INFO[msg]}' -m -k /etc/skel/ ${USER_INFO[user_name]};
                    echo ${USER_INFO[user_pass]} | sudo passwd --stdin ${USER_INFO[user_name]};
                    echo '${USER_INFO[user_sudo]}' | sudo tee -a /etc/sudoers"
    else
        info "Creating user without password"
        local ssh_create_user_cmd="sudo groupadd -g ${USER_INFO[group_id]} ${USER_INFO[group_name]};
                    sudo useradd -u ${USER_INFO[user_id]} -G ${USER_INFO[group_name]} -s /bin/bash -c '${USER_INFO[msg]}' -m -k /etc/skel/ ${USER_INFO[user_name]};
                    echo '${USER_INFO[user_sudo]}' | sudo tee -a /etc/sudoers"
    fi

    if [ "${add_ssh_pub}" == "true" ]
    then
        info "Adding ssh key ${ssh_key_file}"
        local ssh_key=$(cat ${ssh_pub_key_file})
        local mk_ssh_dir="sudo mkdir ${USER_INFO[user_home]}/.ssh;
                    sudo touch ${USER_INFO[user_home]}/.ssh/authorized_keys;
                    sudo chmod 600 ${USER_INFO[user_home]}/.ssh/authorized_keys;
                    sudo chown -R ${USER_INFO[user_name]}:${USER_INFO[user_name]} ${USER_INFO[user_home]}/.ssh"
        local add_ssh_key_cmd="echo -e '# ECM ssh key\n${ssh_key}' | sudo tee -a ${USER_INFO[user_home]}/.ssh/authorized_keys"
        local ssh_cmd="${ssh_create_user_cmd}; ${mk_ssh_dir}; ${add_ssh_key_cmd}"
    else
        local ssh_cmd="${ssh_create_user_cmd}"
    fi

    #local ssh_cmd="${ssh_create_user_cmd}"
    # Redacting password.
    if [ "${server_file_password}" == "true" ]
    then
        debug "cat ${TEMP_FILE} | sshpass -p "${IYellow}REDACTED${Color_Off}" ssh -vvv -t ${SSH_OPTS} ${remote_username}@${remote_server}"
    else
        debug "ssh -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} \'${ssh_cmd//${USER_INFO[user_pass]}/${IYellow}REDACTED${Color_Off}}\'"
    fi
    local ssh_cmd_response

    # For testing
    #ssh_cmd_response=$(ssh -v -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} "${ssh_cmd}"; echo $?)

    # if statement for password auth instead of keys
    if [ ${server_file_password} == "true" ]
    then
        # sshpass -p "EXAMPLE" ssh -o StrictHostKeyChecking=no root@HOST
        # the ssh_key_file is in the same place was where the password would be
        ssh_cmd_response=$(sshpass -p "${ssh_id_file}" ssh -t ${SSH_OPTS} ${remote_username}@${remote_server} "${ssh_cmd}")
    else
        ssh_cmd_response=$(ssh -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} "${ssh_cmd}")
    fi

    local ssh_cmd_exit="$?"
    debug "ssh exit code:${ssh_cmd_exit}"
    debug "ssh response\n${ssh_cmd_response}"

    #echo "${ssh_cmd_response}"
   return 0
}


# DESC: Deletes user on remote.
# ARGS: Array of remote server info.
function delete_user() {
    info "Deleting user ${USER_INFO[user_name]} on ${USER_INFO[remote_server]}"
    info "Gathering user info to remove on remote server"

    # This gets server info from array.
    debug "server info array"
    eval "declare -A local server_array="${1#*=}
    for key in "${!server_array[@]}"
    do
        debug "key: ${key}  value: ${server_array[${key}]}"
    done

    local remote_server=${server_array[remote_server]}
    debug "Remote server ${remote_server}"
    local remote_username=${server_array[remote_username]}
    debug "Remote user ${remote_username}"
    local ssh_id_file=${server_array[ssh_id_file]}
    debug "ssh key ${ssh_id_file}"

    # Delete user on remote server,
    # group and remove from the sudoers file.
    local ssh_delete_user_cmd="sudo groupdel ${USER_INFO[group_name]};
                sudo userdel -rf ${USER_INFO[user_name]};
                sudo sed -i '/${USER_INFO[user_sudo]}/d' /etc/sudoers"
    local ssh_cmd="${ssh_delete_user_cmd}"
    debug "ssh -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} \'${ssh_cmd}\'"
    local ssh_cmd_response
    ssh_cmd_response=$(ssh -t ${SSH_OPTS} -i ${ssh_id_file} ${remote_username}@${remote_server} "${ssh_cmd}")
    local ssh_cmd_exit="$?"

    # For testing
    debug "ssh exit code:${ssh_cmd_exit}"
    debug "ssh response\n${ssh_cmd_response}"

    echo "${ssh_cmd_response}"
    return 0
}


# DESC: main
# ARGS: None
function main() {

    CHECK_USER="true"
    CHECK_REMOTE_SERVER="false"
    CHECK_REMOTE_USER="false"
    ADD_USER="false"
    ADD_USER_WITH_PASSWD="false"
    RM_USER="false"
    DEBUG="false"
    server_file_password="false"
    TEMP_FILE=/var/tmp/${__base}_$(date +%d%b%Y).tmp

    SSH_OPTS="-o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no"

    parse_args "$@"

    debug "Starting main script"

    if [ -z "${BASH_VERSINFO}" ] || [ -z "${BASH_VERSINFO[0]}" ] || [ ${BASH_VERSINFO[0]} -lt 4 ]
    then
        echo "This script requires Bash version >= 4"
        exit 3
    elif [[ -z "${server_list_file:-}" ]] || [[ -z "${user_file:-}" ]]
    then
        debug "Required arguments not pass"
        usage
        exit 3
    elif [ "${ADD_USER}" == "true" ] && [ "${RM_USER}" == "true" ]
    then
        critical "You cannot both and remove the user"
        usage
        echo -e "\n!!!!!!!! You cannot both add and remove the user !!!!!!!!"
        exit 4
    fi

    debug "
    check_user : ${CHECK_USER}
    check_remote_server: ${CHECK_REMOTE_SERVER}
    check_remote_user: ${CHECK_REMOTE_USER}
    add_user: ${ADD_USER}
    rm_user: ${RM_USER}
    debug: ${DEBUG}
    "

    # Run in debug mode, if set
    if [ "${DEBUG}" == "true" ]; then
        set -o noclobber
        set -o errexit          # Exit on most errors (see the manual)
        set -o errtrace         # Make sure any error trap is inherited
        set -o nounset          # Disallow expansion of unset variables
        set -o pipefail         # Use last non-zero exit code in a pipeline
        set -o xtrace           # Trace the execution of the script (debug)
    fi

    # Check if file exist
    info "Validating server and user file"
    if [[ ! -f "${server_list_file}" ]]
    then
        echo "Cannot find file ${server_list_file}"
    elif [[ ! -f "${user_file}" ]]
    then
        echo "Cannot find file ${user_file}"
    else
        info "Gathering user credentials to create on remote server"
        declare -A USER_INFO
        USER_INFO[user_id]=$(awk -F " " 'NR==1{print $1 }' "${user_file}")
        debug "UID is ${USER_INFO[user_id]}"
        USER_INFO[group_id]=$(awk -F " " 'NR==1{print $4 }' "${user_file}")
        debug "GID is ${USER_INFO[group_id]}"
        USER_INFO[group_name]=$(awk -F " " 'NR==1{print $5 }' "${user_file}")
        debug "Group name is ${USER_INFO[group_name]}"
        USER_INFO[user_name]=$(awk -F " " 'NR==1{print $2 }' "${user_file}")
        debug "Username is ${USER_INFO[user_name]}"
        USER_INFO[user_pass]=$(awk -F " " 'NR==1{print $3 }' "${user_file}")
        debug "Password is ${IYellow}REDACTED${Color_Off}"
        #debug "Password is ${USER_INFO[user_pass]}"
        USER_INFO[user_home]="/home/${USER_INFO[user_name]}"
        debug "Home directory is ${USER_INFO[user_home]}"
        USER_INFO[user_sudo]=$(awk 'NR==2' "${user_file}") # parse line for etc/sudoers
        debug "User sudoers line ${IYellow}REDACTED${Color_Off}"
        #debug "User sudoers line ${USER_INFO[user_sudo]}"
        USER_INFO[msg]=$(awk -F '"' 'NR==1{print $2 }' "${user_file}")
        debug "User message: ${USER_INFO[msg]}"

    fi

    info "Cycling through server list"
    logger "\n=========================================== $(date +'%Y-%m-%d %H:%M:%S'): Starting Run ===========================================\n"
    for server_line in $(cat ${server_list_file})
    do
        declare -A line
        # Redacting password from log.
        if [ ${server_file_password} == "true" ]
        then
            debug "line `echo ${server_line} | awk -F, '$3="*********"'`"
        else
            debug "line ${server_line}"
        fi
        line[remote_server]=$(echo "${server_line}" | cut -d ',' -f 1) # Parse Hostname from Input file
        debug "Remote server ${line[remote_server]}"
        info "Processing remote server:: ${line[remote_server]}"
        line[remote_username]=$(echo "${server_line}" | cut -d ',' -f 2) #parse Username from Input file
        debug "Remote user ${line[remote_username]}"
        line[ssh_id_file]=$(echo "${server_line}" | cut -d ',' -f 3)  # parse Specific Identity file
        line[ssh_id_file]="${line[ssh_id_file]/#\~/${HOME}}"  # parse Specific Identity file
        if [ ${server_file_password} == "true" ]
        then
            debug "Password is ${IYellow}REDACTED${Color_Off}"
        else
            debug "ssh key ${line[ssh_id_file]}"
        fi

        # Are you able to connect get exit code
        info "Checking ssh connection remote server:: ${line[remote_server]}"
        #debug "${line[*]}"
        if [ ${server_file_password} == "true" ]
        then
            debug "ssh command: sshpass -p "${IYellow}REDACTED${Color_Off}" ssh -t -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${line[remote_username]}@${line[remote_server]} 'ls'"
            line[ssh_test]=$(sshpass -p "${IYellow}REDACTED${Color_Off}" ssh -t -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${line[remote_username]}@${line[remote_server]} "ls" 2>&1 </dev/null)
            line[ssh_test_exit]="$?"
        else
            debug "ssh command: ssh ${SSH_OPTS} -i ${line[ssh_id_file]} ${line[remote_username]}@${line[remote_server]} 'ls'"
            line[ssh_test]=$(ssh ${SSH_OPTS} -i ${line[ssh_id_file]} ${line[remote_username]}@${line[remote_server]} "ls" 2>&1 </dev/null)
            line[ssh_test_exit]="$?"
        fi
        debug "ssh exit code: ${line[ssh_test_exit]}"
        debug "ssh test: ${line[ssh_test]}"

        if [[ "${CHECK_REMOTE_USER}" == "true" ]]
        then
            debug "check_remote_user "${line[*]}""
            local resp=$(check_remote_user "$(declare -p line)")
            info "${resp}"
            logger "${resp}"
        elif [[ "${CHECK_USER}" == "true" ]]
        then
            debug "check_user "${line[*]}""
            local resp
            local resp_exit
            resp=$(check_user "$(declare -p line)")
            resp_exit="$?"
            debug "response: ${resp}
                    response exit code: ${resp_exit}"
            local already_valid
            already_valid=$(echo "${resp}" | grep -o "valid" | wc -l | xargs)
            debug "already_valid: ${already_valid}"
            if [ ${already_valid} -ne 4 ] && [ ${resp_exit} -eq 0 ]
            then
                if [[ "${ADD_USER}" == "true" ]]
                then
                    debug "**************** ADDING USER ***********************"
                    resp=$(create_user "$(declare -p line)")
                    resp_exit="$?"
                    debug "create_user result:
                            ${resp}
                            response exit code: ${resp_exit}"
                    resp=$(check_user "$(declare -p line)")
                    resp_exit="$?"
                    debug "response: ${resp}
                            response exit code: ${resp_exit}"
                    if [[ "${resp_exit}" -ne 0 ]]
                    then
                        resp="failed to add user: ${resp}"
                        debug "${resp}"
                    else
                        resp="added user successfully: ${resp}"
                        debug "${resp}"
                    fi
                    #logger "${resp}"
                fi
            elif [[ "${RM_USER}" == "true" ]]
            then
                debug "**************** REMOVING USER ***********************"
                resp=$(delete_user "$(declare -p line)")
                resp_exit="$?"
                debug "delete_user result:
                        ${resp}
                        response exit code: ${resp_exit}"
                resp=$(check_user "$(declare -p line)")
                resp_exit="$?"
                debug "response: ${resp}
                        response exit code: ${resp_exit}"
                if [[ "${resp_exit}" -ne 0 ]]
                then
                    resp="failed to remove user: ${resp}"
                    debug "${resp}"
                else
                    resp="removed user successfully: ${resp}"
                    debug "${resp}"
                fi
            else
                if [[ "${ADD_USER}" == "true" ]]
                then
                    warn "skipping adding user: ${resp}"
                    resp="skipping adding user: ${resp}"
                elif [[ "${RM_USER}" == "true" ]]
                then
                    warn "skipping removing user: ${resp}"
                    resp="skipping removing user: ${resp}"
                fi
            fi
            # This is the end to the check_user section.
            info "${resp}"
            logger "${resp}"
        fi

        debug "Gets here"
    done

    # Clean up tmp file
    rm -f "${TEMP_FILE}"
    return 0
}

# make it rain
debug "Starting script"
main "$@"
debug "Script is complete"
logger "\n=========================================== $(date +'%Y-%m-%d %H:%M:%S'): Run Complete ===========================================\n"
exit 0
