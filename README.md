# dnsr

## What is dnsr?

`dnsr` is an authoritative DNS server written in Rust. It is intended to be used to ease the creation of wildcards certificates using the ACME protocol and the [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136).

## How to use it?

In order to use the `dnsr` you have to create some configuration files and a folder to store the TSIG keys generated.

`dnsr` is deployed as a Docker container. You can use the following command to run it:

```bash
docker run -d -p 8053:8053/udp -v ./config.yml:/etc/dnsr/config.yml -v ./domains.yml:/etc/dnsr/domains.yml -v ./keys:/etc/dnsr/keys dnsr:latest
```

### Configuration files

#### config.yml

The `config.yml` file is used to configure the `dnsr server. The following is the default configuration file:

```yaml
---
# This file is located at the path in the `DNSR_CONFIG` environment variable or in the `config.yml` file in the current directory.

# The path to the folder containing the private keys for the domains.
tsig_folder: /etc/dnsr/keys
# The path to the file containing the domains to handle.
domain_file: /etc/dnsr/domains.yml

# The log configuration.
log:
  # The log level. This can be one of the following: trace, debug, info, warn, error, or off.
  level: info
  # Enable the udp metrics.
  enable_udp_metrics: true
  # Enable the tcp metrics.
  enable_tcp_metrics: true
```

#### domains.yml

The `domains.yml` file is used to configure the domains that the `dnsr` server will handle. In the following example, the `dnsr` server will handle the `example1.com`, `example2.com`, and `example3.com` domains:

```yaml
---
domains:
  - example1.com
  - name: example2.com
  - name: example3.com
    # The file name of the TSIG key for the domain.
    # The file is located in the `tsig_folder` folder.
    # This is optional. If not provided, the key file will be named after the domain name in snake case.
    tsig_file_name: example3.key
```

**Note:** The `dnsr` server constantly whatches the `domains.yml` file for changes. If the file is modified, the server will reload the domains (e.g. add or remove domains).

### TSIG keys

The `dnsr` server generates the TSIG keys for the domains that it handles. The keys are stored in the `tsig_folder` folder. The keys are generated in a file named after the domain name in snake case. For example, the key for the `example.com` domain will be stored in the `example.com` file.
The TSIG keys are deleted when a domain is removed from the `domains.yml` file.
