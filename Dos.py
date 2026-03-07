import requests

url=input("put url")
while True:
    t=requests.get(url)
    print(t.status_code)