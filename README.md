# Onion Routing

## Overview
This repository contains a basic implementation of Onion Routing, a technique for anonymous communication over a computer network. The project includes multiple Python scripts that simulate the core components of an onion routing system, including client, server, and relay functionalities.

## Features
- **Client-Server Communication**: Establishes secure communication channels between clients and servers.
- **Encryption & Decryption**: Utilizes custom cryptographic functions to ensure data privacy and integrity.
- **Relay Servers**: Implements multiple relay layers to anonymize the traffic origin.

## Getting Started
### Prerequisites
- Python 3.8 or higher
- Pip for Python package management

### Installation
1. Clone the repository:
```
git clone https://github.com/AnasMohammad4321/Onion-Routing.git
```
2. Move to project's directory
```
cd Onion-Routing
```
3. Activate the virtual environment
```
source dev/bin/activate
```
4. Install the required packages:
```
pip install -r requirements.txt
```


### Running the Application
To start the system, run the following scripts in separate terminals:
1. `python directory.py` - Starts the directory server.
2. `python relay_server.py` - Initializes the first relay server.
3. `python relay_server1.py` and `python relay_server2.py` - Additional relay servers.
4. `python client_server.py https://www.DUMMY.com` - Launches the client application.

## Contributing
We welcome contributions from the community. If you wish to contribute to the project, please follow these steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## Contact
For any queries, you can reach out: mohammadanas702@gmail.com.
