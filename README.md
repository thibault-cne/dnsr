# dnsr

## What is dnsr?

`dnsr` is an authoritative DNS server written in Rust. It is intended to be used to ease the creation of wildcards certificates using the ACME protocol and the [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136).

## How to use it?

In order to use the `dnsr` you have to create a configuration file and a folder to store the TSIG keys generated.

`dnsr` is deployed as a Docker container. You can use the following command to run it:

```bash
docker run -d -p 8053:8053/udp -v ./config.yml:/etc/dnsr/config.yml -v ./keys:/etc/dnsr/keys ghrc.io/thibault-cne/dnsr:latest
```

### Configuration files

#### config.yml

The `config.yml` file is used to configure the `dnsr server. The following is the default configuration file:

```yaml
---
# This file is located at the path in the `DNSR_CONFIG` environment variable or in the `/etc/dnsr/config.yml` file.

# The log configuration.
log:
  # The log level. This can be one of the following: trace, debug, info, warn, error, or off.
  level: info
  # Enable the udp metrics.
  enable_udp_metrics: true
  # Enable the tcp metrics.
  enable_tcp_metrics: true

# The keys and domains configuration
keys:
  - key1:
      - domain1
      - domain2
  - key2:
      - domain3
      - domain4
```

In the previous example, the `dnsr` server will handle the domain1, domain2, domain3 and domain4 domains.
The key1 will be used to handle the domain1 and domain2 domains and the key2 will be used to handle the domain3 and domain4 domains.

**Note**: The dnsr server constantly whatches the `config.yml` file for changes.
If the file is modified, the server will reload the domains (e.g. add or remove domains).

### TSIG keys

The `dnsr` server generates the TSIG keys for the domains that it handles. The keys are stored in the `/etc/dnsr/keys` folder. The keys are generated in a file named after the domain name in snake case. For example, the key for the `example.com` domain will be stored in the `example.com` file except if the `tsig_file_name` is provided in the `domains.yml` file.
The TSIG keys are deleted when a domain is removed from the `domains.yml` file.
