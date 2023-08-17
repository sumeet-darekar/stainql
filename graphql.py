import argparse
import sys
import urllib3
import requests
from urllib.parse import urlparse
import json
import time

def logo():
    print(f"""
    [ Tool for graphql Testing ] - v1.0.1

  {"-"*61}
  |         _        _             _                          |          
  |     ___| |_ __ _(_)_ __   __ _| |                         |                                         
  |    / __| __/ _` | | '_ \ / _` | |                         |                                         
  |    \__ | || (_| | | | | | (_| | |                         |                                         
  |    |___/\__\__,_|_|_| |_|\__, |_|                         |                                    
  |                             |_|                           |                                    
  |                                                           |
  |                                      By:- Sumeet Darekar  |
  {"-"*61}
""")


parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,epilog="""

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

""")
parser.add_argument('-i','--introspection', action='append',nargs='?',help=' run introspection query')
parser.add_argument('-t','--target',help=' specify the target [format : https://example.com/graphql ]')
parser.add_argument('-f','--fuzz', action='append',nargs='?',help=' fuzzing graphql endpoints [wordlist : graphql-wordlist.txt (default)]')
parser.add_argument('-s','--show', action='append',nargs='?',help=' show the output of introspection query')
parser.add_argument('-c','--checkcsrf', action='append',nargs='?',help=' check for CSRF')
parser.add_argument('-q','--query', action='append',nargs='?',help=' check for query based batching')
parser.add_argument('-cq','--custom_query', action='append',nargs='?',help=' send the custom query')
parser.add_argument('-a','--all', action='append',nargs='?',help=' Scan all vulnerabilities[ csrf, batching, introspection query ] present on tool. ')
logo()
args=parser.parse_args()


if args.target is None:
    print(f"provide target")
    sys.exit()

print("-"*65)
print(f"| :: URL : {args.target}          ")
print("-"*65)

def intropection_query():
    intro_query = """
        query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        locations
        args {
          ...InputValue
        }
      }
    }
  }
  fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
      name
      description
      args {
        ...InputValue
      }
      type {
        ...TypeRef
      }
      isDeprecated
      deprecationReason
    }
    inputFields {
      ...InputValue
    }
    interfaces {
      ...TypeRef
    }
    enumValues(includeDeprecated: true) {
      name
      description
      isDeprecated
      deprecationReason
    }
    possibleTypes {
      ...TypeRef
    }
  }
  fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
  }
  fragment TypeRef on __Type {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
    }"""
    inter_query=False
    try:
        print("Checking if introspection query is allowed...")
        if(inter_query==False):
            response = requests.post(args.target, json=dict(query=intro_query), verify=False)
            json_response = response.json()
            #print(json_response['data'])
            print("\033[A\033[K", end="")
            if(response.json().get("data")):
                inter_query = True
                print("\n--> introspection query allowed\n")
                if(args.show):
                    print(json_response['data'])
                    #print(response.request.body)
            else:
                print("introspection query not allowed")
    except:
        print("Error while getting the schema...")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)            # disable the warning
def fuzzing_graphql():
    try:
        with open('graphql-wordlist.txt', "r") as f:
            words = [line.strip() for line in f.readlines()]
            #print(words)
            print(f"Scanning the graphql endpoints/directories... \n")
            for word in words:
                print(f": {word}")
                response = requests.get(url=f"{args.target}/{word}", verify=False)
                #print(response.url)
                #print(response.status_code)
                if(response.status_code == 200 or response.status_code==301 or response.status_code==400):
                    print(f"\n --> Endpoint : {word} [ Response code : {response.status_code} ]")
                    print(f"       URL : {response.url} \n\n")
                print("\033[A\033[K", end="")
    except :
        print("Interruption Occur during scanning...")

def csrf():
    result = False
    try:
        try:
            print("\nChecking GET based CSRF...")
            payload = {"query":"{ a }"}
            response = requests.get(args.target, verify=False, params=payload)
            json_response = response.json()
            #print(response.url)
            error_list = response.json()["errors"]
            #print(error_list)
            #print(response.json()["errors"])
            print("\033[A\033[K", end="")
            for error in response.json()["errors"]:
                #print(error)
                if "Cannot query field" in error['message']:
                    print("-"*80)
                    print("--> [ GET based CSRF might be present ] ")
                    print("-"*80)
                    result = True
            words = error_list
            sample1 = "undefined"
            sample2 = "error"
            for word in words:
                if(word == sample1 or word == sample2):
                    print("-"*80)
                    print("--> [ GET based CSRF might be present ]" )
                    print("-"*80)
                    result = True
            
            
        except:
            print("Error during scnning")
        try:
            print("\nChecking POST based CSRF...")
            response1 = requests.post(args.target, data=payload, verify=False)
           # print(response1.url)
            errors = response1.json().get("errors")
            print("\033[A\033[K", end="")
            for error in errors:
                #print(error)
                
                if "Cannot query field" in error['message']:
                    print("-"*80)
                    print("--> [ POST based CSRF might be present ] ")
                    print("-"*80)
                    result = True
            words = errors
            sample1 = "undefined"
            sample2 = "error"
            for word in words:
                if(word == sample1 or word == sample2):
                    print("-"*80)
                    print("--> [ POST based CSRF might be present ]")
                    print("-"*80)
                    result = True
            
            
        except:
            print("Error during scanning")
        print("Checking if x-www-urlencoded is accepted...")
        payload = {"query":"{ a }"}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        r = requests.post(args.target, data=payload, headers=headers)
        print("\033[A\033[K", end="")
        if r.status_code == 200:
            print("-"*80)
            print("--> [ Server accept x-www-form-urlencoded data might be vulnerable to CSRF ]")
            print("-"*80)
            result = True
    except Exception as e:
      print("Error due to : ",e)
    if result == False:
      print(f"--> CSRF might not be present in [{response1.url}]\n")

def query_batching():
    
    
    payload = """[
        {
            "query":"..."
        },{
            "query":"..."
        }
        ,{
            "query":"..."
        }
        ,{
            "query":"..."
        }
        ]
        """
    try:
        print("Scanning query based batching attack...")
        time.sleep(2)
        headers = {'content-type': 'application/json'}
        response = requests.post(args.target, data=payload, headers=headers, verify=False)
        errors = response.json()
        #print(errors)
        #print(response.json()['errors'])
        print("\033[A\033[K", end="")
        if(len(response.json()['errors'])>1):
            print("-"*80)
            print("\n--> [ Query based batching vulnerability is present ]\n")
            print(f"payload is : {payload}\n")
            print("-"*80)
        else:
            print("\n--> Not vulnerable to query based batching attack \n")
    except Exception as e:
        print(f"\nSomething went wrong error : [ {e} ] \n")
def customquery():
    print("Excuting your query...")
    with open('custom-query.txt', "r") as f:
        user_input = f.read()
        print("\033[A\033[K", end="")
        print("Done.\n")
        print(f"payload given :  {user_input}")
        headers = {'content-type': 'application/json'}
        print("-"*80)
        print("Fetching data...")
        try:
            response = requests.post(args.target, json=dict(query=user_input), headers=headers,verify=False)

            print("\033[A\033[K", end="")
            print("Done.\n")
            if(response.status_code == 200):
                print(f"\n --> {response.json()}\n")
            else:
                print(f"Something went wrong status code : [ {response.status_code} ]\n")
        except Exception as e:
            print("Error : {e}")


if(args.introspection and args.checkcsrf):
  intropection_query()
  csrf()
elif(args.checkcsrf and args.query):
  query_batching()
  csrf()
elif(args.introspection):
    print(intropection_query())
elif(args.fuzz):
    fuzzing_graphql()
elif(args.checkcsrf):
  csrf()
elif(args.query):
  query_batching()
elif(args.custom_query):
  customquery()
elif(args.all):
  intropection_query()
  csrf()
  query_batching()