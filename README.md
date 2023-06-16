# SMBAT - Finally the AIO SMB Tool
SMBAT merges the features implemented for SMBSR (find secrets in shares) and RSMBI (assess the RW permission that a user has among all the target shares). 
USing the **-mode** parameter it is possible to run SMBAT as SMBSR,RSMBI or as full power SMBSR/RSMBI. 
As its "parents", this tool works in two phases: 

* Enumeration: basing on the target (CIDR, Computer Objects from AD, IP list, ...), SMBAT uses the provided credentials to enumerate the available shares and build a dictionary of target (server:list(shares)). For this pysmb library is used
* Action: Basing on the **-mode** parameter SMBAT starts to its main duties, during this phases the SMB shares are mounted in a temp folder and accessed "locally", finally those are unmounted and deleted. 

Results are saved in a sqlite database but also exported in CSV. 

## SMBSR Brain

SMBSR considers someting interesting basing on its: 

* Content
* Exstension 
* Name

The interesting keywords the tool should look for are defined via the command line as well as: 

* File extension blacklist 
* Shares blacklist
* Folder blacklist (Watch out, also subfolders are gone)
* Number of Threads
* Should i masscan or not?
* Interesting file extensions (I guess something like ppk, kdbx, ...)
* Maximum file size (Bytes) allowed to be checked (Believe me, too big might take some time) 
* Should i export the results in two nice CSV files? 
* How deep should i look into subfolders?
* Wordlist of regular expression to match 
* Domain Controller IP for ldap bind 
* Other common ones and required 

The database containes one table for all the matches called smbsr, made of the following columns: 

* file
* share
* ip 
* position
* matchedWith
* Creation Date
* Last Modified Date
* Last Accessed Date
* First Time found date
* Last Time Found Date
* runTag of the session
* Extract of the text matched (25 chars before and after the interesting match)
* Clickable finding to manually check the result

And also another table for the interesting file list containing the following columns: 

* file 
* share
* ip
* Creation Date
* Last Modified Date
* Last Accessed Date
* First Time found date
* Last Time Found Date
* runTag of the session
* Clickable finding to manually check the result


## RSMBI Brain 

## Usage 

```text
usage: smbat.py [-h] [-username USERNAME] [-password PASSWORD] [-domain DOMAIN] [-fake-hostname FAKE_HOSTNAME] [-multithread] [-logfile LOGFILE] [-dbfile DBFILE]
                [-share-black SHARE_BLACK] [-local-path LOCAL_PATH] [-debug] [-target TARGET] [-target-list TARGET_LIST] [-tag TAG] [-ldap] [-dc-ip DC_IP] [-T T]
                [-masscan] [-smbcreds SMBCREDS] [-uncpaths UNCPATHS] [-csv] [-mode MODE] [-regulars REGULARS] [-wordlist WORDLIST] [-hits HITS]
                [-file-interesting FILE_INTERESTING] [-max-size MAX_SIZE] [-file-extensions-black FILE_EXTENSIONS_BLACK] [-regular-exp REGULAR_EXP]

SMB @udit Tool

optional arguments:
  -h, --help            show this help message and exit
  -username USERNAME    Username for authenticated scan
  -password PASSWORD    Password for authenticated scan
  -domain DOMAIN        Domain for authenticated scan, please use FQDN
  -fake-hostname FAKE_HOSTNAME
                        Computer hostname SMB connection will be from
  -multithread          Assign a thread to any share to check
  -logfile LOGFILE      Log file path
  -dbfile DBFILE        DB file path
  -share-black SHARE_BLACK
                        Blacklist of shares
  -local-path LOCAL_PATH
                        Path to folder where to mount the shares, default set to /tmp
  -debug                Verbose logging debug mode on
  -target TARGET        IP address, CIDR or hostname
  -target-list TARGET_LIST
                        Path to file containing a list of targets
  -tag TAG              Label the run
  -ldap                 Query LDAP to retrieve the list of computer objects in a given domain
  -dc-ip DC_IP          DC IP of the domain you want to retrieve computer objects from
  -T T                  Define the number of thread to use, default set to 10
  -masscan              Scan for 445 before trying to analyze the target
  -smbcreds SMBCREDS    Path to the file containing the SMB credential
  -uncpaths UNCPATHS    Path to the file containing the list of UNCPATHS you want to scan
  -csv                  Export results to CSV files in the project folder
  -mode MODE            Choose between SMBSR,RSMBI and Both
  -regulars REGULARS    File containing regex expression to match [SMBSR]
  -wordlist WORDLIST    File containing the string to look for [SMBSR]
  -hits HITS            Max findings per file [SMBSR]
  -file-interesting FILE_INTERESTING
                        Comma separated file extensions you want to be notified about [SMBSR]
  -max-size MAX_SIZE    Maximum size of the file to be considered for scanning (bytes) [SMBSR]
  -file-extensions-black FILE_EXTENSIONS_BLACK
                        Comma separated file extensions to skip while secrets harvesting [SMBSR]
  -regular-exp REGULAR_EXP
                        File containing regex expression to match [SMBSR]

```