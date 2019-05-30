# Distributed random number generation based on homomorphic encryption
This repo is a proof of concept of our work on scalable distributed random number generation based on 
ElGamal homomorphic encryption on Elliptic Curves (ECC). Please follow this [link](https://github.com/LampardNguyen234/drng) to get the latest update about the project.
This proposed protocol is the very first one that utilizes homomorphic encryption as the building block for generating random numbers on distributed environments.
The protocol operates in rounds, each round will produce a random beacon (with high probability). Each round consists of the following stages (we assume that all parties are known beforehand):

1.  **Initialization** <br/>
In this stage, the **Requester** who is in need of random numbers sends a requester containing his `public key` and a `nonce` to the **PDL** (message type: **ReqGenTick**). A ticket `T` is the created by hashing the `public key` and the `nonce`; and sent back to the **Requester** (message type: **RespGenTick**). This marks the beginning of the round.

2. **Eligibility Checking:** <br/>
In this stage, each **Party** checks his eligibility for contributing to generating the random number with respect to the ticket `T`. Each **Party** runs the VRF `Proving` function and compares the output `y` to the globally-predetermined threshold `Th`. If `y < Th`, he generates a proof for his eligibility `PoE = <T, y , pi>` (see `Party_interface.py`) and proceeds to the next stage (after publishing the `PoE` onto the **PDL**).

3. **Contribution Making** <br/>
An eligible **Party**, also called a **Contributor**, chooses a point `M` on the elliptic curve of his choice to contribute. Then he encrypts this `M` (and gets the ciphertex `(C, D)`) using the public key of the **Requester** (see `Party.py`). He also generates a proof for his contribution consisting of the form `PoC = <T, C, D, sigma>` where `(C, D) = Enc(M)` and `sigma` is the signature of the party on `Hash(C,D)`. This `PoC` is the publicized onto the **PDL**. (message type: **ReqContribution**).

4. **Contribution Tallying** <br/>
The **PDL** keeps track of all contributions from the **Parties**. When the **PDL** receives a contribution from a **party**, it will automatically add this contribution to the total sum (after verifying the correctness of the received `PoC`). This is possible thanks to the homomorphic property of the ElGamal encryption on Elliptic Curves. When all **party** have finished the third stage, the **PDL** sends a request to the **Requster** along with the final tallied contribution for decryption. (message type: **ReqDecryption**).

5. **Result Decryption** <br/>
In this stage, the **Requester** uses his `private key` to decrypt the tallied contribution and gets `M` as the sum of all contributions. He also generates a proof for his proper decrytion `(c, z)` using Zero-knowledge proof technique. He then publicizes `(M, c, z)` onto the **PDL**. (message type: **RespDecryption**).


## Setup
The project was written using Python 3 To install dependencies (*prcryptodome* for windows or *pycrypto* for ubuntu, etc), change to root project directory (the one containing _requirements.txt_) and run:

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

## Message Type
**1. ReqGenTick:** request for generating new ticket `T`. <br/>
This message is sent from the **Requester** to the **PDL**. The message consists of a public key `Y` and a `nonce`. If the current ticket is expired or has not been created yet, a new ticket will be created.

**2. RespGenTick:** response to the **ReqGenTick** <br/>
This message is sent from the **PDL** to the **Requester** in reply to the request from the **Requester** for generating new ticket. This message consists of the newly-created ticket.

**3. ReqThreshold:** request for the current threshold<br/>
This message is sent from either the **Requester** or a **Party** to the **PDL** in requesting for the value of the current threshold `Th`. The message has no parameter.

**4. RespThreshold** <br/>
**5. ReqTicket** <br/>
**6. RespTicket** <br/>
**7. ReqPubKey** <br/>
**8. RespPubKey** <br/>
**9. ReqContribution** <br/>
**10. RespContribution** <br/>
**11. ReqDecryption** <br/>
**12. RespDecryption** <br/>

## Authors
* Lampard (lnhatthanh.nguyen@gmail.com)

## Assumptions
1.  The number of parties is known beforehand as shown in the `config.py` file. In practice, there should be an initialization stage for parties to register. For the sake of implementation convenience, we discard this phase.
2.  The **Requester** will publish the final random beacon `M` and the corresponding proof `(c, z)` onto the **PDL**. In practice, this is not required.
