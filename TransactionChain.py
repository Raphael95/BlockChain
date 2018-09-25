import hashlib
import json
import time
import flask
import uuid
from urllib.parse import urlparse
import requests
import socket
import rsa
import base64

class Blockchain:

    def __init__(self):
        self.blocks = []
        self.current_transactions = []
        self.nodes = set()

        # create the genesis block
        self.new_block(proof=100, previous_hash=1)

    def new_block(self, proof, previous_hash=None):
        # to crate a new block and add it ro chain
        block = {
            'index': len(self.blocks) + 1,
            'timeStamp': time.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hashBloack(self.blocks[-1]),
        }

        # reset the current list of transaction
        self.current_transactions = []
        self.blocks.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        # create a new transaction and add it to current_transactions
        self.current_transactions.append(
            {
                'sender': sender,
                'recipient': recipient,
                "amount": amount,

            }
        )
        return self.last_block['index'] + 1


    @staticmethod
    def hashBloack(block):
        # hash a block
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


    @property
    def last_block(self):
        # return the last block in the chain
        return self.blocks[-1]


    def proof_of_work(self, last_proof):
        proof = 0
        while self.validate_proof(proof, last_proof) is False:
            proof += 1

        return proof


    def validate_proof(self, proof, last_proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == '0000'

    def register_nodes(self, address):
        # add a new node to the list of nodes
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def validate_chain(self, chain):
        last_block = chain[0]
        current_index = 1
        while current_index < len(chain):
            # check the hash of chain is correct

            block = chain[current_index]
            if block['previous_hash'] != self.hashBloack(last_block):
                return False
            if self.validate_proof(block['proof'], last_block['proof']) is False:
                return False

            last_block = block
            current_index += 1
        return True

    def resolve_conficts(self):
        neighbours = self.nodes
        new_chain = None

        max_len = len(self.blocks)
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_len and self.validate_chain(chain):
                    max_len = length
                    new_chain = chain


        if new_chain:
            self.blocks = new_chain
            return True

        return False






app = flask.Flask(__name__)
node_identifier = str(uuid.uuid4()).replace('-', '')
blockChain = Blockchain()

@app.route('/nodes/register', methods=['POST'])
def register_node():
    values = flask.request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error, you must supply a valid list of nodes(address)", 400
    for node in nodes:
        blockChain.register_nodes(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockChain.nodes),
    }
    return flask.jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    is_replaced = blockChain.resolve_conficts()
    if is_replaced:
        response = {
            'message': 'our chain is replaced',
            'new_chain':blockChain.blocks
        }
    else:
        response ={
            'message': 'our chain is authoritative',
            'chain': blockChain.blocks
        }
    return flask.jsonify(response), 200


@app.route('/dig', methods=['GET'])
def digBlock():
    last_block = blockChain.last_block
    last_proof = last_block['proof']
    proof = blockChain.proof_of_work(last_proof)
    with open('public.pem', 'r') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read().encode())
    public = base64.b64encode(bytes(str(public_key), encoding='utf-8'))
    public = str(public, encoding='utf-8')
    blockChain.new_transaction(sender=0, recipient=public, amount=1)
    block = blockChain.new_block(proof)
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transaction': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    ip_address = flask.request.remote_addr + ':5000'
    nodes = blockChain.nodes
    neighbours_node = nodes.copy()
    if ip_address in neighbours_node:
        neighbours_node.remove(ip_address)
    for node in neighbours_node:
        response_code = requests.get(f'http://{node}/chain')
        if response_code.status_code == 200:
            response = requests.get(f'http://{node}/nodes/resolve')
            if response.status_code == 200:
                print("成功更新相邻节点的blockChain")
    return flask.jsonify(response), 200




@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    values1 = flask.request.get_data()
    values = json.loads(values1)
    ip_address = flask.request.remote_addr + ':5000'
    print("ip地址是："+str(ip_address))
    print(values)
    required = ['recipient', 'amount']
    for k in values:
        if k not in required:
            return "missing transaction values", 400

    # encryp and sign the transaction using sender's public_key
    with open('private.pem', 'r') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read().encode())
    scriptSign = rsa.sign(str(values['amount']).encode(), private_key, 'SHA-1')
    sender = str(base64.b64encode(scriptSign), encoding='utf-8')

    index = blockChain.new_transaction(sender, values['recipient'], values['amount'])
    nodes = blockChain.nodes
    neighbours_node = nodes.copy()
    if ip_address in neighbours_node:
        neighbours_node.remove(ip_address)
    print("邻居的节点有："+str(list(neighbours_node)))
    for eachNode in neighbours_node:
        response_code = requests.get(f'http://{eachNode}/chain')
        if response_code.status_code == 200:
            print("链接成功")
            return_request = requests.post(f'http://{eachNode}/transaction/new', data=json.dumps(values))
            print(return_request.status_code)
            if return_request.status_code == 201:
                print('交易成功广播出去！')

    response = {
        'message': f'Transaction will be added to Block {index}'
    }
    return flask.jsonify(response), 201



@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockChain.blocks,
        'length': len(blockChain.blocks),
    }
    return flask.jsonify(response), 200

@app.route('/transac', methods=['GET'])
def full_transactions():
    response = {
        'current_transactions': blockChain.current_transactions,
    }
    return flask.jsonify(response), 200


@app.route('/generateKeys', methods=['GET'])
def generateKeys():
    # 生成密钥
    (publicKey, privateKey) = rsa.newkeys(1024)

    # 保存密钥
    with open('public.pem', 'w+') as f:
        f.write(publicKey.save_pkcs1().decode())

    with open('private.pem', 'w+') as f:
        f.write(privateKey.save_pkcs1().decode())

    # 导入密钥
    with open('public.pem', 'r') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read().encode())

    with open('private.pem', 'r') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read().encode())

    response = {
        'public_key': f'{public_key}',
        'private_key': f'{private_key}',
    }
    return flask.jsonify(response), 200





if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)






