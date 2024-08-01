FROM rust:alpine3.19 AS builder

ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add --no-cache musl-dev

WORKDIR /usr

# Create the all architecture tree
RUN cargo new --bin dnsr

WORKDIR /usr/dnsr

# Copy the Cargo.toml files
COPY Cargo.toml Cargo.toml

# Compile the dependencies
RUN cargo build --release

RUN rm -rf src

COPY src src

# Build the project
RUN touch src/main.rs
RUN cargo build --release
RUN strip target/release/dnsr

FROM alpine:3.19 AS runtime

RUN apk add --no-cache libgcc

# Create the configuration directory
RUN mkdir -p /etc/dnsr

LABEL maintainer="Thibault C. <thibault.chene23@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/thibault-cne/dnsr"

COPY --from=builder /usr/dnsr/target/release/dnsr /usr/local/bin

EXPOSE 53/udp

ENTRYPOINT ["/usr/local/bin/dnsr"]
