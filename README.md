# SmartClient

SmartClient is a simple python script that can connect to a webserver and collect information about it's available connections and cookies.

Given a host, SmartClient will display

- whether or not the web server supports http2
- the cookies used by the web server
- whether or not the requested page is password-protected

## Usage

Run the SmartClient using the following code, where `www.uvic.ca` is the desired web server.

```bash
python3 SmartClient.py www.uvic.ca
```
