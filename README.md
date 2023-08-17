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
