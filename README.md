# Autoperimeter
Software for automatic building of system perimeter 

## Dependencies

The script uses Python 3.x with libraries: netlas, networkx, urlextract, pyvis  
You need to install them before running the script:

```sh
$ pip3 install netlas networkx urlextract pyvis
```


## Usage
Before using the program you need to register in Netlas application (https://netlas.io/) to get your own Netlas API key. Then you need to enter the key via:
```sh
$ python3 main.py -c 'Your API key (without brackets)'
```
After that you'll be able to use script as usual.    
Input:    
2-nd level domain or IP (domain with form a.b.ru can not be parsed correctly)    
Output:    
IPs, Domains and URIs that are in scope for sure than IPs, Domains and URIs that are possibly in scope    
```
python3 main.py [flags] [target]
Target specification: Domain names or IP-addresses
Flags:
    -h: Print this page
    -c: Enter Netlas API key: main.py -c 'API key'
```
