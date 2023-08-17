# stainql

Testing tool for graphql api

## what's stainql

Stainql is a simple graphql api testing tool. 


Features provided by stainql are :
- Introspection query check.
- Graphql endpoint detection using inbuild wordlist.
- CSRF(Cross-Site Request Forgery) check
- Query based Batching attack check.
- Executing custom query.

## Installation

clone the repo.  
`git clone https://github.com/sumeet-darekar/stainql.git`  

requirements.txt  
`pip install -r requirements.txt`  

## Usage

 #### Endpoint detection
`python3 graphql.py -t https://graphql-example.com -f`  
#### introspection query   
`python3 graphql.py -t https://graphql-example.com/graphql -i -s`  
#### csrf  
`python3 graphql.py -t https://graphql-example.com/graphql -c`  
#### batching
`python3 graphql.py -t https://graphql-example.com/graphql -q`
#### all options together
`python3 graphql.py -t https://graphql-example.com/graphql -a`


## Help Menu
`python3 graphql.py -h`  
```
[ Tool for graphql Testing ] - v1.0.1  
  
  -------------------------------------------------------------  
  |         _        _             _                          |            
  |     ___| |_ __ _(_)_ __   __ _| |                         |                                           
  |    / __| __/ _` | | '_ \ / _` | |                         |                                           
  |    \__ | || (_| | | | | | (_| | |                         |                                           
  |    |___/\__\__,_|_|_| |_|\__, |_|                         |                                      
  |                             |_|                           |                                        
  |                                                           |  
  |                                      By:- Sumeet Darekar  |  
  -------------------------------------------------------------  

usage: graphql.py [-h] [-i [INTROSPECTION]] [-t TARGET] [-f [FUZZ]] [-s [SHOW]] [-c [CHECKCSRF]] [-q [QUERY]] [-cq [CUSTOM_QUERY]] [-a [ALL]]

options:
  -h, --help            show this help message and exit
  -i [INTROSPECTION], --introspection [INTROSPECTION]
                        run introspection query
  -t TARGET, --target TARGET
                        specify the target [format : https://example.com/graphql ]
  -f [FUZZ], --fuzz [FUZZ]
                        fuzzing graphql endpoints [wordlist : graphql-wordlist.txt (default)]
  -s [SHOW], --show [SHOW]
                        show the output of introspection query
  -c [CHECKCSRF], --checkcsrf [CHECKCSRF]
                        check for CSRF
  -q [QUERY], --query [QUERY]
                        check for query based batching
  -cq [CUSTOM_QUERY], --custom_query [CUSTOM_QUERY]
                        send the custom query
  -a [ALL], --all [ALL]
                        Scan all vulnerabilities[ csrf, batching, introspection query ] present on tool.

EXAMPLE USAGE : 
      --> Scanning all vulnerabilities in tools.
            python3 graphql.py -t <your_target> -a
      
      --> For Introspection query [use -s if you want to see the output]
            python3 graphql.py -t <your_target> -i 
            python3 graphql.py -t <your_target> -i -s  [dumps the information]
      
      --> For fuzzing for endpoints. it will use Default worldlist[graphql-wordlist.txt] you can add yours endpoints also.
            python3 graphql.py -t <your_target> -f
    
      --> For excuting your custom query. Can change the query from custom-query.txt
            python3 graphql.py -t <your_target> -cq

```
## References
- [yeswehack](https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/)
