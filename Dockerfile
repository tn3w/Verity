FROM rust:alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/verity /verity
COPY lists.json sources.json /

EXPOSE 3000

CMD ["/verity"]
