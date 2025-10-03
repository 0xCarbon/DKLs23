FROM --platform=linux/amd64 rust

RUN rustup toolchain install nightly
RUN rustup component add rustfmt clippy --toolchain nightly
RUN rustup default nightly