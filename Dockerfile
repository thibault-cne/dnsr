FROM rust:alpine3.19 AS chef

RUN apk add --no-cache musl-dev

RUN cargo install cargo-chef

WORKDIR /usr

# Create the all architecture tree
RUN cargo new --bin dnsr

WORKDIR /usr/dnsr

# Copy the Cargo.toml files
COPY Cargo.toml Cargo.toml

FROM chef AS planner

RUN cargo chef prepare  --recipe-path recipe.json

FROM planner AS builder

COPY --from=planner /usr/dnsr/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

RUN rm -rf src

COPY src src

RUN cargo build --release

FROM alpine:3.19 AS runtime

LABEL maintainer="Thibault C. <thibault.chene23@gmail.com>"

COPY --from=builder /usr/dnsr/target/release/dnsr /usr/local/bin

CMD ["/usr/local/bin/dnsr"]
