# Surikatz
Surikatz is a powerful tool for searching informations before pentest. It can be used in three different ways :
- Passive     : Only search on public sources (Shodan, TheHarvester, Wappalyzer...)
- Discrete    : Use Passsive technics and soft nmap scan, soft HTTrack...
- Aggressive  : Use Passive and Discrete technics but more ... aggressive. Use nmap NSE scrips, Dirsearch, Nikto, ...

# How to install ?
You can download the release at : https://github.com/Projet-AKKA-E4/Surikatz/releases/ and do :
`sudo pip3 install file.whl`

Then, pip will take care of installing all the dependencies. An executable will be created in the current folder. 

Next you need to provide the API keys for the different APIs used. The configuration file can be found in : `/home/${USER}/.config/surikatz/.env`

Here is a list of software you need to install in order to make surikatz work :
* TheHarvester
* nmap
* WPScan
* HTTrack
* Nikto
* WafW00f
* Dirsearch

*Nb : you may find it easier to install those software in a Kali Linux Distribution*

# How to use ?
You have 4 options :
```
$ surikatz --help

Usage: surikatz [OPTIONS] TARGET

Options:
  -a, --aggressive  Use Passive and Discrete technics but more ... aggressive.
                   Use nmap NSE scrips, Dirsearch, Nikto, ...
  -d, --discret    Use Passsive technics and soft nmap, soft HTTrack, ...
  -p, --passive    Only search on public sources (Shodan, TheHarvester,
                   Wappalyzer...)
  --help           Show this message and exit.
         Show this message and exit.
```
*Nb : The default one is aggressive.*

The target can either be a domain name or an IP address.

Notice that discret and aggresive mode may take a while to finish depending on the size of the target.
Also notice that you should not launch Surikatz on a target neither in discret nor in aggressive without the owner's permission on the target.  
                                                                                                                        
## Collaborators
Surikatz has been made by M1 students of ESIEE Paris in collaboration with AKKA Technologies.
  - **Nathan SAUCET** _alias_ [@NathanSaucet](https://github.com/wwwGeneral)
  - **Théo PERESSE-GOURBIL** _alias_ [@blackjack-nix](https://github.com/blackjack-nix)
  - **Laurent DELATTE** _alias_ [@alphae-nix](https://github.com/alphae-nix)
  - **Abdelmalik KERBADOU** _alias_ [@Anemys](https://github.com/Anemys)
  - **Manon HERMANN** _alias_ [@CappiLucky](https://github.com/CappiLucky)
  - **Rayane BOUDJEMAA** _alias_ [@Mogulzz](https://github.com/Mogulzz)

                                             ,/****/*,,                                                                 
                                          (#%%%/,,,#%%##/*                                                              
                                       %(#%&@@@#*,,%&&&&(*/(&                                                           
                                      .&&,,(&(/(%*#**,#(,.,&%.                                                          
                                       ,#/(*/#%&&&&(//*,*.,.,                                                           
                                         (##(%%%&%((%####((,                                                            
                                         .(##%%###%%&%%#((/                                                             
                                          ,(###%%%&%%%#(///                                                             
                                          .#%%%%%%%&%*,/,...                                                            
                                         *##%%%%&%%%/,.......                                                           
                                        /##%#%#&&%**/**....,..                                                          
                                      .,*/%%#%(*,,,,,,,,,***,,..                                                        
                                      **/(#%/**,**.,,,*,,..,*,*,.                                                       
                                      ****(*,/%(*,,,,,,.,,.*/,*,.                                                       
                                      ****,/(#/*,,*,,,*,...**/*,..                                                      
                                     .,**,*(##**/******/*,,,/,* ...                                                     
                                     .,.,, ..***//////#((/*,*.,...*.                                                    
                                      ,*,.....,*/*****/((//,,... ...                                                    
                                      *//*,.....*//*,,,,,**/,. . .,                                                     
                                      /#%%(*,,.. */*,,*/**/*#.....,                                                     
                                      #(&%%%*,*,..*,*,*/**/,/,......                                                    
                                    .#(((%%#(**....,,**,***/,,,. ,*..                                                   
                                    **,,*/&%%%(,*...**/**,,#,*.,,**...                                                  
                                   .**(*/#%#%%%&%((*/,,,/**%%/*/**,...                                                  
                                  ,./*/,**#(%%%&@&&(**,*,,/%###(,**/**,.                                                
                                 */*/,,,**#(%#%%&%%///****(%%%#,.,,***...                                               
                                 .***,,,,*((%%%%%&////,*((#%&%,..,,,/,,*,                                               
                                  */***,,,,#%%%&&%/#%((##/((#*,..,,...,*.                                               
                                  .*/(/....,*(#(%%#(//((*,,*((****,...**,                                               
                                   *((**,,,,,,,/(/#//*((/((/(((,,,.,,,,/.                                               
                                   ,///%(*,,*..(((##(*(%%###.*,*,,*,****                                                
                                    (%(/%%@@&&(/..(%##%%%/,/*///*//***/*/%&*,*                                          
                               ,&&&&&##(%%&&@@(%&&*(,(%@(,..,, (/*/(((#&&(%@###(                                        
                             @@@@&#*(%%(&&@@&&@%%#/,**/**@&&%/,.,###(%#%/&&#/%&&&%/                                     
                            /&@&#@&%%%&@(&&&&&&@%/,*,/(##@&@&@&(#%&%%.,,##&&&&&&,@@&((                                  
                            .@@&%@@&&&&%&&&@&&&&(%&#(*%%/&%@@@@@#/%%//#*,....*@@@@&@&@&%(,.                             
                            *&@@&@@@&(&&&&&&&@@%&%%%&/(#(&&@&@@&&(((#*****/**...,%&@@@@&@/#,/*/*.                       
                             #@@&@@@@@&@@&@@@@&&&&&&&&(**%&&&&@&&&/(/(/#(%/,/#//**,*,%&@@@@%#%/&&&*.                    
                             .@&&@@@@@@@@@@@&&&&&&&&&(#*#(&&&&#(,*/(*///*&#(//*/*(/**#%%%&&&@@@@@@&&                    
                               &&&&@@&@@@@@@&&@@&@&&&#%#*%%&(&(#((@&%(/(%((#(%,#//*(//#*&@&#(**(@@@@                    
                                .&(&&@&@&&&&@@@@@@@@&&&&@/#//(#(%(%@&%(##////%((#/((//**/***(@%%%@@@                    
                                 &&&@&@&&@@@@@@@@@@@@&&&@&%((//#%&%((/@(%((//((/(#/%(#///#/////&@@&@                    
                                .&&&&&@@@#%#&@@@@@@@@@&&(@@&/(*(*(,**#/*(/##(((((##/((((/*/%#(#/((/&                    

_____
