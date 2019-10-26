# ngx_http_uri_whitelist_module
An nginx module that allows access to URI based on a whitelist. 

## Introduction
This nginx module blocks access to URLs that are not in a whitelist, it displays HTTP 404 error. It can be used to protect website, 
web application and api endpoint by restricting access to only specific URL. 

Vulnerabilities that arise from misconfiguration of application framework that exposes sensitive administrative interface 
can be mitigated through the use of this module. 

The module can be used directly on a site hosted by nginx or with nginx as a reverse proxy. 

## Installation

Obtain a copy of the module source. To verify the signature of the module source, refer to the Source signature section below.

    git clone https://github.com/ngchianglin/ngx_http_uri_whitelist_module.git
    
Download the latest stable version of nginx 1.16.1 from the https://nginx.org. Verify the integrity using the pgp signature 
provided by Nginx. 

Build nginx with the module using the option

    --add-module=<Path to>/ngx_http_uri_whitelist_module
    
## Module Directives

**wh_list**

* syntax: wh_list [on|off]
* default: off
* context: Location

Specifies whether the uri whitelist module is enabled or disabled. Example, 

    wh_list on; 

**wh_list_bypass**

* syntax: wh_list_bypass [space seperated list of extensions]
* default: none
* context: Location

Specifies file extensions that will bypass the whitelisting. For example, 

    wh_list_bypass jpg png gif;

This example will allow access to all URLs that end with .jpg, .png, .gif. Basically image files with such extensions will be 
accessible without whitelisting. 

**wh_list_uri**

* syntax: wh_list_uri [URL to be whitelisted]
* default: none
* context: Location

Specifies the URL to be whitelisted. The directive can be specified multiple times for different URLs. Each URL must start with 
a "/" and is relative the web document root. Example, 

    wh_list_uri /
    wh_list_uri /index.html
    wh_list_uri /myapplication/index.php
 
Assuming the web application is hosted on domain, nighthour.sg, with default index pages configured as index.html and index.php.
The above setting will allow access to https://nighthour.sg, https://nighthour.sg/, https://nighthour.sg/index.html, 
https://nighthour.sg/myapplication/index.php. Note that quotation marks can be used as a delimiter for each URL.  

It will however block access to https://nighthour.sg/myapplication and https://nighthour.sg/myapplication/ and shows HTTP 404 
error. This is because /myapplication/ is not explicitly whitelisted. 

Another example, 

    wh_list_uri "/index.html"

This will allows access to https://nighthour.sg/index.html but https://nighthour.sg and https://nighthour.sg/ will be blocked with
HTTP 404 error. This is because / is not explicitly whitelisted. 

If you have a long list of URLs to be whitelisted. To avoid cluttering the nginx location context, the nginx include directive can
be used to specify another file holding the listing of whitelisted URLs. 

Example, 

    include mywhitelist.conf

Inside mywhitelist.conf 

    wh_list_uri /
    wh_list_uri /index.html
    wh_list_uri "/mysecondfile.php"
    wh_list_uri /apps/myfile.php
    ...


## Example Configuration Reverse Proxy

The following is a simple example for a simple reverse proxy setup with no caching, for nginx location context. 

    location / {
            wh_list on;
            wh_list_uri "/";
            wh_list_uri "/index.html";
            
            wh_list_bypass jpg png gif; 
            include mywhitelist.conf; 

            proxy_set_header HOST $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_pass http://127.0.0.1:8080;
    }


## Usage Warning and Disclaimer

The module is released under the BSD license (same as Nginx) and there are no warranties of any kinds. 
Basically use it at your own risk ! Read and understand the License carefully.

## Source signature
Gpg Signed commits are used for committing the source files.

> Look at the repository commits tab for the verified label for each commit, or refer to [https://www.nighthour.sg/git-gpg.html](https://www.nighthour.sg/git-gpg.html) for instructions on verifying the git commit.
>
> A userful link on how to verify gpg signature is available at [https://github.com/blog/2144-gpg-signature-verification](https://github.com/blog/2144-gpg-signature-verification)


