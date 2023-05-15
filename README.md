# merkle-tree-storage
Peer-to-peer storage system based on Merkle-Tree concept for confirming correctness of data. <br>
Here we have an example where a client wants to store some text on it's peer's computer. In order to prevent data modification by the peer, we use a Merkle Tree to store the data. The client in this example only needs to store the hash of the root of the tree.
At any point the client can just request the peer to send over the proof of specific data requested by the client. Client can then easily verify if that data had been mindled with by the peer.


## How to Run
If you would like to run the simulation of storing some data on a peer's computer, follow these instructions:
1. Navigate into the *server* folder and execute the command *cargo run*.
2. Navigate into the *client* folder and execture the command *cargo run*.

Note: Before you run the *cargo run* command, try running *cargo build* to make sure dependancies and crates are all set!
