# Secure Transaction Processing with Crypto
This C++ code demonstrates a secure transaction processing system using cryptographic techniques. It employs ZeroMQ for communication, OpenSSL for cryptography, and showcases storing, retrieving, and processing transactions.

## Features
- Defines a `Transaction` struct to hold transaction details.
- Provides functions to store and retrieve transactions locally.
- Implements RSA key pair generation and signature verification.
- Demonstrates AES encryption and decryption for transaction data.
- Utilizes ZeroMQ for communication setup.

## Usage
1. Ensure that the required libraries (ZeroMQ and OpenSSL) are installed.
2. Run the code to generate an RSA key pair, establish ZeroMQ communication, and process transactions.
3. The code includes placeholders for implementing cryptographic logic, transaction processing, and handling synchronization requests.

## Description
The code defines a `Transaction` struct to represent transactions, with fields for sender, receiver, amount, timestamp, and additional data. It provides functions to locally store and retrieve transactions, simulating a storage mechanism with a vector.

The `Crypto` namespace includes placeholders for implementing cryptographic logic. It covers RSA decryption, signature verification, RSA key pair generation, AES encryption, and decryption. Actual logic should replace these placeholders.

The main function generates an RSA key pair, initializes ZeroMQ communication, and processes incoming messages. Transactions can be decrypted and stored locally. The code includes placeholders for handling synchronization requests.

## Disclaimer
This code is intended for educational purposes only and should not be used for actual security-sensitive applications without extensive review and proper security measures.

# Secure Transaction Processing with Crypto
This C++ code demonstrates a secure transaction processing system using cryptographic techniques. It employs ZeroMQ for communication, OpenSSL for cryptography, and showcases storing, retrieving, and processing transactions.

## Features
- Defines a `Transaction` struct to hold transaction details.
- Provides functions to store and retrieve transactions locally.
- Implements RSA key pair generation and signature verification.
- Demonstrates AES encryption and decryption for transaction data.
- Utilizes ZeroMQ for communication setup.

## Installation
1. **Install Required Libraries**
    - Ensure that you have the ZeroMQ library and OpenSSL installed on your system.
    - For Debian-based systems (e.g., Ubuntu), you can use the following commands:
      ```shell
      sudo apt-get update
      sudo apt-get install libzmq3-dev libssl-dev
      ```

2. **Compile the Code**
    - Compile the code using a C++ compiler such as g++:
      ```shell
      g++ -o secure_transactions secure_transactions.cpp -lzmq -lssl -lcrypto
      ```

3. **Run the Code**
    - Execute the compiled binary to run the program:
      ```shell
      ./secure_transactions
      ```
    - The code will generate an RSA key pair, set up ZeroMQ communication, and process transactions. Note that placeholders exist for implementing cryptographic logic, transaction processing, and handling synchronization requests.

## Usage
1. Run the compiled executable (`secure_transactions`).
2. The program will generate an RSA key pair, establish ZeroMQ communication, and begin processing transactions.
3. Placeholder logic for cryptographic operations and transaction processing should be replaced with actual implementations for real-world use cases.

## Disclaimer
This code is intended for educational purposes only and should not be used for actual security-sensitive applications without extensive review and proper security measures.













# Proof-of-Non-Tamper (Partially Deprecated)

Proof of Non-Tampering is a consensus algorithm concept whereby the ballooning ledger is replaced with more of a conduit style of propagation. The responsibility of the nodes is to keep a self-trimming record, as it were, of the validity or integrity of the network as a whole in more of a stateless way, the term stateless borrowed and modified slightly to define the network as carrying over the validity of the network as a whole as distinct from keeping a ballooning record. The network continuously self-trims but the validity of the information, stored both globally and in more detail inside of our ABI's, is guaranteed network-wide by tamper-evidence cryptography. So we perform a continuous integrity check on each new transaction while the private transactions, being not really anyone's business, remain private, verified, and containing the traditional ledger's information.

Future development plans include transposing this with existing internetwork ABI so as to permit mutating ABI's, which have some exciting prospects for internetwork EVM's. We have existing interoperability tech which I will incorporate soon to permit mass adoption of this consensus algorithm when it is finalized sometime after I am able to secure more funding.

https://zchg.org
Written by Josef Kulovany

Full Changelog: https://github.com/stealthmachines/Proof-of-Non-Tamper/commits/V0.0.1
