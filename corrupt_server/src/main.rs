use std::net::{TcpListener, TcpStream};
use std::thread;
use std::io::{Read, Write};
use rs_merkle::{Hasher, MerkleTree, MerkleProof};
use sha2::{Sha256, Digest, digest::FixedOutput};
use serde::{Serialize, Deserialize};
use rand::prelude::SliceRandom;

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize_fixed())
    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

    println!("Server listening on port 8080");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("New connection: {}", stream.peer_addr().unwrap());
                thread::spawn(move|| {
                    // connection succeeded
                    handle_client(stream)
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                /* connection failed */
            }
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    // 1. Receive the data from the client
    let message = receive_message(&mut stream);
    println!("Received message: {}", message);

    // 2. Compute Leaves
    let mut new_leaf_values_vec = compute_leaves(&message);
    println!("Leaves: {:?}", new_leaf_values_vec);

    // 3. Hash Leaves
    let leaves = hash_leaves(&new_leaf_values_vec);

    // 4. Compute Merkle Tree
    let merkle_tree = compute_merkle_tree(&leaves);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root").unwrap();

    // X. Change the Data
    new_leaf_values_vec.shuffle(&mut rand::thread_rng());
    let leaves_changed_hashed = hash_leaves(&new_leaf_values_vec);

    // 5. Send the Merkle Root to the client
    send_root(&mut stream, merkle_root);

    // 6. Receive the indices to check
    let indices_to_prove = receive_message(&mut stream);
    println!("Received indices to prove: {:?}", indices_to_prove);
    let indices_to_prove_converted = convert_indices(&indices_to_prove);
    

    // 7. Compute Merkle Proof
    // let indices_to_prove = vec![3, 4];
    let first_index = indices_to_prove_converted[0];
    let second_index = indices_to_prove_converted[1];
    let leaves_to_prove = leaves_changed_hashed.get(first_index..second_index+1).ok_or("can't get leaves to prove").unwrap();
    
    let merkle_proof = merkle_tree.proof(&indices_to_prove_converted);
    
    // 8. Send the leaves to the client
    // print_leaves(&leaves_to_prove);
    send_leaves_to_prove(&mut stream, &leaves_to_prove);

    // 9. Send the Merkle Proof to the client
    send_proof(&mut stream, &merkle_proof);


    print_root(merkle_root);
    verify_merkle_proof(merkle_proof, merkle_root, indices_to_prove_converted, &leaves_to_prove, leaves.len());

}

// ==================== HELPER FUNCTIONS RECEIVIGN ====================

fn receive_message(stream: &mut TcpStream) -> String {
    const HEADER_SIZE: usize = 4;
    let mut header = [0 as u8; HEADER_SIZE];

    match stream.read_exact(&mut header) {
        Ok(_) => {
            let message_len = u32::from_be_bytes(header);
            let mut buffer = vec![0 as u8; message_len as usize];

            match stream.read_exact(&mut buffer) {
                Ok(_) => {
                    let message = String::from_utf8(buffer).unwrap();
                    return message;
                },
                Err(e) => {
                    println!("Failed to receive data: {}", e);
                    return String::from("");
                }
            }

        },
        Err(e) => {
            println!("Failed to receive data: {}", e);
            return String::from("");
        }
    }
}

fn convert_indices(indices_string: &String) -> Vec<usize> {
    let indices_split = indices_string.split(" ");
    let indices_vec: Vec<usize> = indices_split.map(|x| x.parse::<usize>().unwrap()).collect();
    indices_vec
}

// ==================== HELPER FUNCTIONS MERKLE ====================

fn compute_merkle_tree(hashed_leaves: &Vec<[u8;32]>) -> MerkleTree<Sha256Algorithm> {
    let merkle_tree = MerkleTree::<Sha256Algorithm>::from_leaves(&hashed_leaves);
    merkle_tree
}

fn hash_leaves(leaves: &Vec<&str>) -> Vec<[u8;32]> {
    let leaves: Vec<[u8; 32]> = leaves
    .iter()
    .map(|x| Sha256Algorithm::hash(x.as_bytes()))
    .collect();

    leaves
}

fn compute_leaves(message: &String) -> Vec<&str> {
    let split_values: Vec<&str> = message.split(' ').collect();
    let leaf_array: Vec<&str> = split_values.into_iter().collect();

    leaf_array
}

fn verify_merkle_proof(merkle_proof: MerkleProof<Sha256Algorithm>, merkle_root: [u8; 32], 
    indices_to_prove: Vec<usize>, leaves_to_prove: &[<Sha256Algorithm as Hasher>::Hash], leaves_len: usize) {
    let result = merkle_proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves_len);
    println!("Merkle Proof Result: {}", result);
}

// ==================== HELPER FUNCTIONS SENDING ====================

fn send_proof(stream: &mut TcpStream, proof: &MerkleProof<Sha256Algorithm>) {
    let proof_bytes = proof.to_bytes();
    let message_len = proof_bytes.len() as u32;

    let mut header = [0 as u8; 4];
    header.copy_from_slice(&message_len.to_be_bytes());

    stream.write_all(&header).unwrap();
    stream.write_all(&proof_bytes).unwrap();
}

fn send_root(stream: &mut TcpStream, merkle_root: [u8; 32]) {
    let message_len = merkle_root.len() as u32;

    let mut header = [0 as u8; 4];
    header.copy_from_slice(&message_len.to_be_bytes());

    stream.write_all(&header).unwrap();
    stream.write_all(&merkle_root).unwrap();
}

fn send_leaves_to_prove(stream: &mut TcpStream, leaves_to_prove: &[[u8;32]]) {
    // FIRST LEAF
    let item_ref: [u8; 32] = leaves_to_prove[0];
    let message_len = item_ref.len() as u32;

    let mut header = [0 as u8; 4];
    header.copy_from_slice(&message_len.to_be_bytes());

    stream.write_all(&header).unwrap();
    stream.write_all(&item_ref).unwrap();

    // SECOND LEAF
    let item_ref_2 = leaves_to_prove[1];
    let message_len_2 = item_ref_2.len() as u32;

    let mut header_2 = [0 as u8; 4];
    header_2.copy_from_slice(&message_len_2.to_be_bytes());

    stream.write_all(&header_2).unwrap();
    stream.write_all(&item_ref_2).unwrap();
}


// ==================== PRINTING FUNCTIONS ====================
#[allow(dead_code)]
fn print_root(merkle_root: [u8; 32]) {
    println!("Merkle root: {:?}", merkle_root);
}
#[allow(dead_code)]
fn print_vertices(vertices: &Vec<usize>) {
    for vertex in vertices {
        print!("{}", vertex);
        print!(" ");
    }
    println!();
}
#[allow(dead_code)]
fn print_leaves(leaves: &[<Sha256Algorithm as Hasher>::Hash]) {
    for leaf in leaves {
        print!("{:?}", leaf);
        print!(" ");
    }
    println!();
}


