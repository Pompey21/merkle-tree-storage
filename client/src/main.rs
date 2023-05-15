use std::{net::TcpStream, io::{Write, Read}};

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Serialize, Deserialize};
use rs_merkle::{Hasher, MerkleTree, MerkleProof};
use sha2::{Sha256, Digest, digest::FixedOutput};

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
    let message = "This is the data I want you to store and please do not mindle with it at any cost!".to_string();
    let len_message = message.split(" ").count();

    // send the message to server
    let stream_establish = TcpStream::connect("127.0.0.1:8080");
    match stream_establish {
        Ok(mut stream) => {
            println!("Successfully connected to server in port 8080");

            // send the message
            send_message(&mut stream, message);

            // receive the root from server
            let merkle_root = receive_root(&mut stream);
            print_root(merkle_root);

            // send chosen indices
            let chosen_indices = compute_random_index(len_message);
            let chosen_indices_clone = chosen_indices.clone();
            send_indices(&mut stream, chosen_indices);

            // receive leaves to prove from server
            let leaves_to_prove = receive_leaves_to_prove(&mut stream);
            print_leaves(&leaves_to_prove);

            // receive the proof from server
            let merkle_proof = receive_proof(&mut stream);

            // verify proof
            verify_merkle_proof(merkle_proof, merkle_root, chosen_indices_clone, &leaves_to_prove, len_message);

        }
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}

// ==================== HELPER FUNCTIONS SENDING ====================

fn send_message(stream: &mut TcpStream, message: String) {
    let serialised_message = message.as_bytes();
    let size_of_message: u32 = serialised_message.len() as u32;

    let mut header = [0 as u8; 4];
    header.copy_from_slice(&size_of_message.to_be_bytes());

    stream.write_all(&header).unwrap();
    stream.write_all(&serialised_message).unwrap();
}

fn send_indices(stream: &mut TcpStream, indices: Vec<usize>) {
    // convert to string
    let first_elem = indices[0].to_string();
    let second_elem = indices[1].to_string();
    let indices_string = first_elem + " " + &second_elem;
    let indices_bytes = indices_string.as_bytes();

    let size_of_indices: u32 = indices_bytes.len() as u32;

    let mut header = [0 as u8; 4];
    header.copy_from_slice(&size_of_indices.to_be_bytes());

    stream.write_all(&header).unwrap();
    stream.write_all(indices_bytes).unwrap();
}

// ==================== HELPER FUNCTIONS RECEIVING ====================

fn receive_root(stream: &mut TcpStream)  -> [u8; 32] {
    let mut buffer = [0 as u8; 4];
    stream.read_exact(&mut buffer).unwrap();
    let size_of_root = u32::from_be_bytes(buffer);

    let mut root_buffer = vec![0 as u8; size_of_root as usize];
    stream.read_exact(&mut root_buffer).unwrap();

    let slice = &root_buffer[..];
    let root = <[u8; 32]>::try_from(slice).unwrap();
    root
}

fn receive_proof(stream: &mut TcpStream) -> MerkleProof<Sha256Algorithm> {
    let mut buffer = [0 as u8; 4];
    stream.read_exact(&mut buffer).unwrap();
    let size_of_proof = u32::from_be_bytes(buffer);

    let mut proof_buffer = vec![0 as u8; size_of_proof as usize];
    stream.read_exact(&mut proof_buffer).unwrap();

    let proof = MerkleProof::<Sha256Algorithm>::from_bytes(&proof_buffer).unwrap();
    proof
}

fn receive_leaves_to_prove(stream: &mut TcpStream) -> [[u8; 32]; 2] {
    // FIRST LEAF
    let mut buffer = [0 as u8; 4];
    stream.read_exact(&mut buffer).unwrap();
    let size_of_leaf = u32::from_be_bytes(buffer);

    let mut leaf_buffer = vec![0 as u8; size_of_leaf as usize];
    stream.read_exact(&mut leaf_buffer).unwrap();

    let slice = &leaf_buffer[..];
    // Convert &[u8] to [u8; 32]
    let mut leaf: [u8; 32] = [0u8; 32];
    leaf.copy_from_slice(slice);
    // array

    // SECOND LEAF
    let mut buffer_2 = [0 as u8; 4];
    stream.read_exact(&mut buffer_2).unwrap();
    let size_of_leaf_2 = u32::from_be_bytes(buffer_2);

    let mut leaf_buffer_2 = vec![0 as u8; size_of_leaf_2 as usize];
    stream.read_exact(&mut leaf_buffer_2).unwrap();

    let slice_2 = &leaf_buffer_2[..];
    // Convert &[u8] to [u8; 32]
    let mut leaf_2: [u8; 32] = [0u8; 32];
    leaf_2.copy_from_slice(slice_2);
    
    // array: join leaf and leaf_2 of the type [[u8; 32]; 2]
    let leaves_to_prove: [[u8; 32]; 2] = [leaf, leaf_2];
    leaves_to_prove
}


// ==================== HELPER FUNCTIONS MERKLE ====================

#[allow(dead_code)]
fn compute_merkle_tree(hashed_leaves: &Vec<[u8;32]>) -> MerkleTree<Sha256Algorithm> {
    let merkle_tree = MerkleTree::<Sha256Algorithm>::from_leaves(&hashed_leaves);
    merkle_tree
}
#[allow(dead_code)]
fn hash_leaves(leaves: Vec<&str>) -> Vec<[u8;32]> {
    let leaves: Vec<[u8; 32]> = leaves
    .iter()
    .map(|x| Sha256Algorithm::hash(x.as_bytes()))
    .collect();

    leaves
}
#[allow(dead_code)]
fn compute_leaves(message: &String) -> Vec<&str> {
    let split_values: Vec<&str> = message.split(' ').collect();
    let leaf_array: Vec<&str> = split_values.into_iter().collect();

    leaf_array
}

fn verify_merkle_proof(merkle_proof: MerkleProof<Sha256Algorithm>, merkle_root: [u8; 32], indices_to_prove: Vec<usize>, leaves_to_prove: &[<Sha256Algorithm as Hasher>::Hash], leaves_len: usize) {
    let result = merkle_proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves_len);
    println!("Merkle Proof Result: {}", result);
}

fn compute_random_index(len_message: usize) -> Vec<usize> {
    let mut rng = rand::thread_rng();
    let mut indices_to_prove: Vec<usize> = Vec::new();
    let first = rng.gen_range(0..len_message-2);
    let second = first + 1;
    indices_to_prove.push(first);
    indices_to_prove.push(second);
    indices_to_prove
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

