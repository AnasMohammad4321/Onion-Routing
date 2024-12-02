# Onion Routing

## Overview
This repository contains a basic implementation of Onion Routing, a technique for anonymous communication over a computer network. The project includes multiple Python scripts that simulate the core components of an onion routing system, including client, server, and relay functionalities.

## Features
- **Client-Server Communication**: Establishes secure communication channels between clients and servers.
- **Encryption & Decryption**: Utilizes cryptographic functions from the `cryptography` library to ensure data privacy and integrity.
- **Relay Servers**: Implements multiple relay layers to anonymize the traffic origin.
- **Modular Structure**: The project is organized into distinct directories for better maintainability and scalability.

## Project Structure
```
Onion-Routing/
├── README.md              # Project documentation
├── requirements.txt       # Python dependencies
├── .gitignore             # Files and directories to ignore in version control
├── venv/                  # Virtual environment (auto-generated)
├── src/                   # Source code
│   ├── __init__.py        # Marks this directory as a Python package
│   ├── client_server.py   # Client-side application script
│   ├── crypt.py           # Cryptographic functions for encryption/decryption
│   ├── directory.py       # Directory server script
│   ├── logger.py          # Logging utilities
│   ├── network.py         # Networking utilities
│   ├── relay_server.py    # Primary relay server script
│   ├── relay_server1.py   # Additional relay server script
│   └── relay_server2.py   # Additional relay server script
├── templates/             # HTML templates
│   └── response.html      # Sample HTML response template
└── logs/                  # Logs for the application
    └── app.log            # Example log file
```

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Pip for Python package management

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/AnasMohammad4321/Onion-Routing.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Onion-Routing
   ```
3. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
To start the system, execute the following scripts in separate terminals:

1. Run the directory server:
   ```bash
   python3 src/directory.py
   ```
2. Initialize the primary relay server:
   ```bash
   python3 src/relay_server.py
   ```
3. Start additional relay servers:
   ```bash
   python3 src/relay_server1.py
   python3 src/relay_server2.py
   ```
4. Launch the client application:
   ```bash
   python3 src/client_server.py https://www.DUMMY.com
   ```

## Contributing
We welcome contributions from the community. If you'd like to contribute:
1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature-branch
   ```
3. Make your changes.
4. Commit your changes:
   ```bash
   git commit -am 'Add some feature'
   ```
5. Push to your branch:
   ```bash
   git push origin feature-branch
   ```
6. Open a pull request.

## Contact
For queries, feel free to reach out:
- **Email**: mohammadanas702@gmail.com
