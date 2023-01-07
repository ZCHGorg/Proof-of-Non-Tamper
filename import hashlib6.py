import base64
import json
import os
import hashlib
import random

from Crypto.PublicKey import RSA
from ed25519 import SigningKey, VerifyingKey
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Add import for RabbitMQ library
import pika

def broadcast_transaction(transaction, private_key, public_keys):
    # Generate a random key to encrypt the transaction data
    key = os.urandom(16)

    # Encrypt the transaction data using the key
    encrypted_transaction = encrypt_transaction_data(transaction, key)

    # Calculate the tamper-evident seal for the transaction data
    seal = calculate_seal(transaction)

    # Add the seal to the transaction data
    transaction['seal'] = seal

    # Encrypt the key using the public keys of the receiving nodes
    encrypted_key = encrypt_key(key, public_keys)

    with pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) as connection:
        channel = connection.channel()

        # Create a message queue for the blockchain data
        channel.queue_declare(queue='blockchain')

        # Send the encrypted transaction and key to the message queue as a JSON object
        data = {'transaction': encrypted_transaction, 'key': encrypted_key}
        channel.basic_publish(exchange='', routing_key='blockchain', body=json.dumps(data))
        print("Transaction broadcasted:", data)

def receive_transactions(private_key, public_key):
    with pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) as connection:
        channel = connection.channel()

        # Create a message queue for the blockchain data
        channel.queue_declare(queue='blockchain')

        # Define a callback function to process received messages
        def callback(ch, method, properties, body):
            # Parse the received data as a JSON object
            data = json.loads(body)

            # Extract the encrypted transaction and key from the data
            encrypted_transaction = data['transaction']
            encrypted_key = data['key']

            # Decrypt the key using the private key
            key = decrypt_key(encrypted_key, private_key)

            # Decrypt the transaction data using the key
            transaction = decrypt_transaction_data(encrypted_transaction, key)

            # Verify the tamper-evident seal on the transaction using the public key
            if verify_tamper_evident_seal(transaction, transaction['seal']):
                print("Transaction verified:", transaction)
            else:
                print("Transaction tampered with:", transaction)

    # Set up a message consumer and start listening for messages
    channel.basic_consume(queue='blockchain', on_message_callback=callback)
    channel.start_consuming()

def issue_reward(nodes, transaction):
    # Check that the sender has sufficient balance to make the transaction
    if transaction['sender']['balance'] < transaction['amount']:
        print("Transaction rejected: sender does not have sufficient balance")
        return

    # Calculate the reward amount (1% of the transaction value)
    reward_amount = transaction['amount'] * 0.01

    # Select a random node to receive the reward
    selected_node = random.choice(nodes)
    selected_node['balance'] += reward_amount

from Crypto.Cipher import AES

def encrypt_transaction_data(data, key):
    try:
        # Generate a random initialization vector (IV)
        iv = get_random_bytes(16)

        # Encrypt the data using the cipher object
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=256)
        encrypted_data = cipher.encrypt(data)

        # Encode the encrypted data and IV as base64 strings
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        # Concatenate the encrypted data and IV as a colon-separated string and return the result
        return f"{encrypted_data_b64}:{iv_b64}"
    except Exception as e:
        # Print an error message and return None if an exception is raised
        print(f"Error encrypting data: {e}")
        return None

def decrypt_transaction_data(encrypted_data, key):
    try:
        # Split the encrypted data and IV into separate strings
        encrypted_data_b64, iv_b64 = encrypted_data.split(':')

        # Decode the base64-encoded strings
        encrypted_data = base64.b64decode(encrypted_data_b64)
        iv = base64.b64decode(iv_b64)

        # Decrypt the data using the cipher object
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=256)
        data = cipher.decrypt(encrypted_data)

        # Return the decrypted data
        return data
    except Exception as e:
        # Print an error message and return None if an exception is raised
        print("Error decrypting transaction data:", e)
        return None

def encrypt_key(key, public_keys):
    try:
        # Encrypt the key using the public keys
        encrypted_keys = []
        for public_key in public_keys:
            encrypted_key = public_key.encrypt(key, 32)[0]
            encrypted_keys.append(encrypted_key)

        # Return the encrypted keys as a list
        return encrypted_keys
    except Exception as e:
        # Print an error message and return None if an exception is raised
        print(f"Error: {e}")
        return None

def decrypt_key(encrypted_key, private_key):
    try:
        # Decrypt the key using the private key
        decrypted_key = private_key.decrypt(encrypted_key)
        return decrypted_key
    except Exception as e:
        # Log the error or return an error message
        print("Error decrypting key:", e)

def calculate_seal(data):
    # Calculate the hash of the data
    data_hash = hashlib.sha256(data).hexdigest()

    # Generate a salt value
    salt = get_random_bytes(16)

    # Concatenate the salt and data hash, and calculate the hash of the result
    salted_hash = hashlib.sha256(salt + data_hash).hexdigest()

    # Encode the salt and salted hash as a colon-separated string
    seal = base64.b64encode(salt).decode('utf-8') + ':' + salted_hash

    return seal

def verify_tamper_evident_seal(data, seal):
    # Split the seal into its components
    salt_b64, salted_hash = seal.split(':')

    # Decode the salt from base64
    salt = base64.b64decode(salt_b64)

    # Calculate the hash of the data
    data_hash = hashlib.sha256(data).hexdigest()

    # Concatenate the salt and data hash, and calculate the hash of the result
    expected_salted_hash = hashlib.sha256(salt + data_hash).hexdigest()

    # Compare the calculated hash to the salted hash in the seal
    if salted_hash == expected_salted_hash:
        return True
   
def calculate_seal(data):
    # Generate a salt value
    salt = b'salt'  # Replace with a secure random salt value

    # Calculate the hash of the data and salt using SHA-256
    hash_value = hashlib.sha256(data + salt).hexdigest()

    # Encode the hash value as a base64 string
    seal = base64.b64encode(hash_value.encode('utf-8')).decode('utf-8')

    return seal

def receive_transactions(public_key):
    with pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) as connection:
        channel = connection.channel()

        # Create a message queue for the blockchain data
        channel.queue_declare(queue='blockchain')

        # Define a callback function to process received messages
        def callback(ch, method, properties, body):
        
        # Decrypt the transaction data using the shared key
            shared_key = b'key'  # Replace with a secure shared key
        transaction = decrypt_transaction_data(body, shared_key)

        if transaction is not None:
            # Verify the tamper-evident seal on the transaction using the public key
            if verify_tamper_evident_seal(transaction, transaction['seal']):
                print("Transaction verified:", transaction)
            else:
                print("Transaction tampered with:", transaction)
        else:
            print("Error parsing transaction data")

    # Set up a message consumer and start listening for messages
    channel.basic_consume(queue='blockchain', on_message_callback=callback, auto_ack=True)
    print('Listening for transactions...')
    channel.start_consuming()

def broadcast_transaction(transaction, private_key, public_keys):
    # Encrypt the transaction data using a shared key
    shared_key = b'key'  # Replace with a secure shared key
    encrypted_transaction = encrypt_transaction_data(transaction, shared_key)

    # Create a tamper-evident

# Connect to the RabbitMQ server
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    # Create a message queue for the blockchain data
    channel.queue_declare(queue='blockchain')

    # Send the transaction to the message queue
    channel.basic_publish(exchange='', routing_key='blockchain', body=encrypted_transaction)
    print("Transaction broadcasted:", encrypted_transaction)
    connection.close()

def receive_transactions(public_key):
    # Connect to the RabbitMQ server
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    # Create a message queue for the blockchain data
    channel.queue_declare(queue='blockchain')

    # Define a callback function to process received messages
    def callback(ch, method, properties, body):
    # Decrypt the transaction data using the shared key
        shared_key = b'key'  # Replace with a secure shared key
    transaction = decrypt_transaction_data(body, shared_key)

    # Verify the tamper-evident seal on the transaction using the public key
    if verify_tamper_evident_seal(transaction, public_key):
        # Add the transaction to the blockchain if the seal is valid
        add_transaction_to_blockchain(transaction)
    else:
        print("Invalid transaction received:", transaction)
        # Remove the node from the network if the tampering test fails
        remove_node_from_network()


    # Set up a consumer to receive messages from the message queue
    channel.basic_consume(queue='blockchain', on_message_callback=callback, auto_ack=True)
    print('Waiting for transactions...')
    channel.start_consuming()

def add_transaction_to_blockchain(transaction):
    # Add the transaction to the blockchain
    
    # Increment the confirmation count for the transaction
    transaction['confirmations'] += 1
    
    # Check if the transaction has been confirmed by all nodes
    if transaction['confirmations'] == len(list_of_nodes):
        # Calculate the reward amount as 1% of the transaction amount
        reward_amount = transaction['amount'] * 0.01
        
        # Deduct the reward amount from the transaction amount
        transaction['amount'] -= reward_amount
        
        # Randomly select a node from the list of nodes in the network
        random_node = random.choice(list_of_nodes)
        
        # Check if the selected node has a tamper-evident seal
        if 'signature' in random_node:
            # Verify the tamper-evident seal using the node's public key
            if verify_tamper_evident_seal(random_node, random_node['signature'], random_node['public_key']):
                # Add the reward to the selected node's balance if the tampering test passes
                random_node['balance'] += reward_amount
            else:
                # Remove the node from the network if the tampering test fails
                remove_node_from_network()
        else:
            # Remove the node from the network if it does not have a tamper-evident seal
            remove_node_from_network()

def add_transaction_to_blockchain(transaction):
    # Add the transaction to the blockchain
    
    # Increment the confirmation count for the transaction
    transaction['confirmations'] += 1
    
    # Check if the transaction has been confirmed by all nodes
    if transaction['confirmations'] == len(list_of_nodes):
        # Calculate the reward amount as 1% of the transaction amount
        reward_amount = transaction['amount'] * 0.01
        
        # Deduct the reward amount from the transaction amount
        transaction['amount'] -= reward_amount
        
        # Randomly select a node from the list of nodes in the network
        random_node = random.choice(list_of_nodes)
        
        # Check if the selected node has a tamper-evident seal
        if 'signature' in random_node:
            # Verify the tamper-evident seal using the node's public key
            if verify_tamper_evident_seal(random_node, random_node['signature'], random_node['public_key']):
                # Add the reward to the selected node's balance if the tampering test passes
                random_node['balance'] += reward_amount
                
                # Check if the transaction includes a new node
                if 'new_node' in transaction:
                    # Add the new node to the network if it is the only new node
                    if len(transaction['new_node']) == 1:
                        list_of_nodes.append(transaction['new_node'][0])
                    else:
                        # Remove the node from the network if there is more than one new node
                        remove_node_from_network()
        else:
            # Remove the node from the network if it does not have a tamper-evident seal
            remove_node_from_network()

def main():
    # Generate a private/public key pair
    key_pair = RSA.generate(2048)

# Broadcast the transaction to the network
    broadcast_transaction(transaction, private_key, public_keys)

def main():
    # Generate a private/public key pair
    key_pair = RSA.generate(2048)
    private_key = key_pair.export_key()
    public_key = key_pair.publickey().export_key()

    # Start a thread to receive transactions
    receive_thread = Thread(target=receive_transactions, args=(public_key,))
    receive_thread.start()

    # Test creating and broadcasting a transaction
    data = b'{"sender": "Alice", "receiver": "Bob", "amount": 10}'
    create_and_broadcast_transaction(data, private_key, [public_key])

if __name__ == '__main__':
    main()