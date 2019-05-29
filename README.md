# Distributed random number generation based on homomorphic encryption
This repo is a proof of concept of our work on scalable distributed random number generation based on 
ElGamal homomorphic encryption on Elliptic Curves (ECC)

## Setup
The project was written using Python 3 To install dependencies (prcryptodome for windows or pycrypto for ubuntu, etc), change to root project directory (the one containing _requirements.txt_) and run:

```bash
pip3 install -r requirements.txt
```

**Note:** To install _pycryptodome_ on Windows (follow this [link](https://pycryptodome-master.readthedocs.io/en/latest/src/installation.html#windows-from-sources-python-3-5-and-newer)), make sure that you have Microsoft Visual C++ build tools available on your machine. If not, install them by getting Microsoft Visual Studio or simply installing the need packages.

### How to Run

**Note:** You can modify the number of parties, expected number of contributors and other information in `config.py`.

1. Run PDL, Requester and Party in respective order.

    ```bash
    # in Terminal 1 (PDL)
    python3 PDL.py
    ```
    
    ```bash
    # in Terminal 2 (Requester)
    python3 Requester.py
    ```
    
    ```bash
    # in Terminal 3 (Party)
    python3 Party.py
    ```

## Authors
* Lampard (lnhatthanh.nguyen@gmail.com)

## References
