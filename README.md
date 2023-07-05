# Sadeed-TraceRouter
Traceroutes to a target IP address or domain, showing each hop along the route with its corresponding IP address, hostname (if available), and the average round-trip time. Works on Linux.

## Compilation
Use GCC (the GNU Compiler Collection).
```
gcc ./Sadeed_TraceRouter.cpp -o ./Sadeed_TraceRouter
```

## Usage
Give the domain or IP address of the target server as an argument.
```
sudo ./Sadeed_TraceRouter localhost
```
```
sudo ./Sadeed_TraceRouter example.com
```
```
sudo ./Sadeed_TraceRouter 103.108.140.126
