FROM rust:1.83.0 AS builder
USER 0:0
WORKDIR /usr/app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN apt update && apt install -y libssl-dev pkg-config && cargo install --locked --path .

FROM debian:bookworm-slim
WORKDIR /usr/app
RUN apt update && apt install -y ca-certificates
COPY --from=builder /usr/local/cargo/bin/sso-system ./
CMD ["./sso-system"]
