import requests

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

pay = """{
"query":"query{
  country(code:"IN"){
  	currency
    emoji
    phone
    name
  states{
			code
  }
  }
}
"}"""

payload = """query {
      post(id: 5) {
            id
                title
                  
                  }
                  }"""

headers = {'content-type': 'application/json'}
response = requests.post("https://graphqlzero.almansi.me/api", json=dict(query=payload), proxies=proxies,headers=headers,verify=False)
print(response)
print(response.request.headers)
print(response.request.body)