# create-remote-user 
Checks if user from file exist in a list of servers.
Can creates/delete user on servers from a file. The script has some error
handling, it checks if it can ssh into the host, if it can ping it and
there is a dns entry, outputting it's findings to a file.

## Usage
```
Usage: ./create-remote-user -u <user_file> -s <server_file>
Description: Checks if user from file exist in a list of servers.

required arguments:
-u, --user <file>	 User credential file, see file example below.
-s, --server <file>	 List of server, see file example below.

optional arguments:
-c, --check 		 Check if user exist on the remote servers.
-d, --disable 		 Delete user.
-e, --enable 		 Create user.
-h, --help		     Show this help message and exit.
-l, --log <file>	 Log file.
-p, --ping		     Ping remote server if you cannot ssh into it.
-r, --remote-user	 Check if remote user can login to remote servers.
-x, --exmaple		 Show example of User credential and Server file.
-v, --verbose		 Verbosity.
             		 -v info
             		 -vv debug
             		 -vvv bash debug
```

## Example User File
```
# ----------------------------------------------------------------#
# Variable format                                                 #
# ----------------------------------------------------------------#
<UID>  <username> <password>  <GID>  <group_name>
<username> ALL=(ALL) NOPASSWD: ALL

# ----------------------------------------------------------------#
# Example format                                                  #
# ----------------------------------------------------------------#
1234 bestuser bestpassword 5678 bestgroup
bestuser ALL=(ALL) NOPASSWD: ALL
```

## Server file example
```
# ----------------------------------------------------------------#
# Variable format                                                 #
# ----------------------------------------------------------------#
<host>,<ssh_username>,<ssh_key_path>

# ----------------------------------------------------------------#
# Example format                                                  #
# ----------------------------------------------------------------#
192.168.1.19,cloud-user,/path/to/ssh_key
bestinstance,cloud-user,/path/to/ssh_key2
```

## Required binaries:
 - bash v4+
 - ping
 - nslookup
 - getopt
 - sed

## To do
- [ ] add user created ssh key to authorized_keys file.
