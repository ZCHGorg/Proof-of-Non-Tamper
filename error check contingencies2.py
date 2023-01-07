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
    MAX_RETRIES = 5

    retries = 0
    while True:
        try:
            with pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) as connection:
                channel = connection.channel()

                # Create a message queue for the blockchain data
                channel.queue_declare(queue='blockchain')

                # Define a callback function to process received messages
                def callback(ch, method, properties, body):
                    try:
                        # Parse the received data as a JSON object
                        data = json.loads(body)
                    except ValueError:
                        print("Error: Invalid JSON data")
                        return

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
                break
        except pika.exceptions.ConnectionClosed:
            # Increment the retry count and try again if the maximum number of retries has not been reached
            retries += 1
            if retries < MAX_RETRIES:
                print("Error: Connection to RabbitMQ server closed. Retrying...")
            else:
                print("Error: Connection to RabbitMQ server closed. Max retries reached.")
                break

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
        try:
            encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
        except TypeError:
            print("Error: Failed to encode data as base64 string")
            return

        # Concatenate the encrypted data and IV as a colon-separated string and return the result
        return f"{encrypted_data_b64}:{iv_b64}"
    except Exception:
        print("Error: Failed to encrypt transaction data")
        return

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
        # Split the encrypted key into the encrypted data and IV
        encrypted_data_b64, iv_b64 = encrypted_key.split(":")

        # Decode the encrypted data and IV from base64 strings
        try:
            encrypted_data = base64.b64decode(encrypted_data_b64)
            iv = base64.b64decode(iv_b64)
        except TypeError:
            print("Error: Invalid base64 string")
            return

        # Decrypt the key using the private key
        cipher = PKCS1_OAEP.new(private_key)
        key = cipher.decrypt(encrypted_data)

        # Return the decrypted key
        return key
    except Exception:
        print("Error: Failed to decrypt key")
        return

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
   
def calculate_seal(transaction):
    try:
        # Calculate the hash of the transaction data
        transaction_hash = hashlib.sha256(json.dumps(transaction).encode('utf-8')).hexdigest()

        # Use the private key to sign the transaction hash
        private_key = RSA.importKey(transaction['sender']['private_key'])
        cipher = PKCS1_v1_5.new(private_key)
        seal = base64.b64encode(cipher.sign(transaction_hash)).decode('utf-8')

        return seal
    except Exception as e:
        print("Error: Failed to calculate tamper-evident seal")
        print(e)
        return None

def receive_transactions(public_key):
    MAX_RETRIES = 5

    retries = 0
    while True:
        try:
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
                        if verify_tamper_evident_seal(transaction, transaction['seal'], public_key):
                            print("Transaction verified:", transaction)
                        else:
                            print("Transaction tampered with:", transaction)
                    else:
                        print("Error parsing transaction data")

                # Set up a message consumer and start listening for messages
                channel.basic_consume(queue='blockchain', on_message_callback=callback, auto_ack=True)
                print('Listening for transactions...')
                channel.start_consuming()
                break
        except pika.exceptions.ConnectionClosed:
            # Increment the retry count and try again if the maximum number of retries has not been reached
            retries += 1
            if retries < MAX_RETRIES:
                print("Error: Connection closed. Retrying...")
            else:
                print("Error: Connection closed. Maximum number of retries exceeded.")
                break

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

def receive_transactions(private_key, public_key):
    MAX_RETRIES = 5

    retries = 0
    while True:
        try:
            with pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) as connection:
                channel = connection.channel()

                # Create a message queue for the blockchain data
                channel.queue_declare(queue='blockchain')

                # Define a callback function to process received messages
                def callback(ch, method, properties, body):
                    try:
                        # Parse the received data as a JSON object
                        data = json.loads(body)
                    except ValueError:
                        print("Error: Invalid JSON data")
                        return

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
                break
        except pika.exceptions.ConnectionClosed:
            # Increment the retry count and try again if the maximum number of retries has not been reached
            retries += 1
            if retries < MAX_RETRIES:
                print("Error: Connection to RabbitMQ server closed. Retrying...")
            else:
                print("Error: Connection to RabbitMQ server closed. Max retries reached.")
                break

def receive_transactions(private_key, public_key):
    MAX_RETRIES = 5

    retries = 0
    while True:
        try:
            with pika.BlockingConnection(pika.ConnectionParameters(host='localhost')) as connection:
                channel = connection.channel()

                # Create a message queue for the blockchain data
                channel.queue_declare(queue='blockchain')

                # Define a callback function to process received messages
                def callback(ch, method, properties, body):
                    try:
                        # Parse the received data as a JSON object
                        data = json.loads(body)
                    except ValueError:
                        print("Error: Invalid JSON data")
                        return

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
                break
        except pika.exceptions.ConnectionClosed:
            # Increment the retry count and try again if the maximum number of retries has not been reached
            retries += 1
            if retries < MAX_RETRIES:
                print("Error: Connection to RabbitMQ server closed. Retrying...")
            else:
                print("Error: Connection to RabbitMQ server closed. Max retries reached.")
                break

# Add the transaction to the blockchain
def add_transaction_to_blockchain(transaction):
    
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
    private_key = key_pair.export_key()
    public_key = key_pair.publickey().export_key()

if __name__ == '__main__':
    main()