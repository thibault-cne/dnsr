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
# This part is optional and every field is optional.
# If not present, the values below are used as defaults.
log:
  # The log level. This can be one of the following: trace, debug, info, warn, error, or off.
  level: info
  # Enable the metrics.
  enable_metrics: true
  # Enable thread ID in logs.
  enable_thread_id: false
  # Log on stderr.
  stderr: false

# The keys and domains configuration
keys:
  key1:
    sub.example.fr:
      mname: ns-acme.example.fr.
      rname: postmaster.example.fr.
    example.fr:
      mname: ns-acme.example.fr.
      rname: postmaster.example.fr.
  key2:
    another-example.fr:
      mname: ns-acme.another-example.fr.
      rname: postmaster.another-example.fr.
    fake.another-example.fr:
      mname: ns-acme.another-example.fr.
      rname: postmaster.another-example.fr.
```

In the previous example, the `dnsr` server will handle the `sub.example.fr`, `example.fr`, `another-example.fr` and `fake.another-example.fr` domains.
The key1 will be used to handle the `sub.example.fr` and `example.fr` domains and the key2 will be used to handle the `another-example.fr` and `fake.another-example.fr` domains.

The record created is the following for the `sub.example.fr` domain:

```text
_acme-challenge.sub.example.fr.    3600 IN    SOA    ns-acme.example.fr. postmaster.example.fr. 1722353587 10800 3600 605800 3600
```

**Note**: The prefix `_acme-challenge` is automatically added to the domain name.

**Note**: The dnsr server constantly whatches the `config.yml` file for changes.
If the file is modified, the server will reload the domains (e.g. add or remove domains).

### TSIG keys

The `dnsr` server generates the TSIG keys for the domains that it handles. The keys are stored in the `/etc/dnsr/keys` folder. The keys are generated in a file named after the domain name in snake case. For example, the key for the `example.com` domain will be stored in the `example.com` file except if the `tsig_file_name` is provided in the `domains.yml` file.
The TSIG keys are deleted when a domain is removed from the `domains.yml` file.
