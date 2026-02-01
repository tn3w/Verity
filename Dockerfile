FROM rust:alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/verity /verity
COPY lists.json sources.json /

EXPOSE 3000

CMD ["/verity"]
