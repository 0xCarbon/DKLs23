# DKLs23

## Table of Contents
![image](.assets/dkls23-banner.png)

## Table of Contents
- [Overview](#overview)
- [Getting Started](#getting-started)
- [Installation](#installation)
- [Contributing](#contributing)
- [Security](#security)
- [Code of Conduct](#code-of-conduct)
- [License](#license)
- [Authors](#authors)

## Overview
DKLs23 is an advanced open-source implementation of the Threshold ECDSA method. The primary goal of DKLs23 is to compute a secret key without centralizing it in a single location. Instead, it leverages multiple parties to compute the secret key, with each party receiving a key share. This approach enhances security by eliminating single points of failure.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Installation
A step-by-step guide to installing the project.

1. **Install Rust using `rustup`**
``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. **Clone the repository:**
```bash
git clone https://github.com/0xCarbon/DKLs23 cd DKLs23
```

3. **Install dependencies:**
```bash
cargo build
```

## Contributing
We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

## Security
For information on how to report security vulnerabilities, please see our [SECURITY.md](SECURITY.md).

## Code of Conduct
Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.


## License
This project is licensed under either of
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Authors
See the list of [contributors](https://github.com/0xCarbon/DKLs23/contributors) who participated in this project.
