import datetime
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
import base64
from pymongo import MongoClient
from getpass import getpass
from tmp import temp


mongoC = temp.getMongoClient()
client = MongoClient(mongoC)
db = client.get_database('telecomms_db')
users = db.users
groups = db.groups


def main():
    try:
        loginUser = None
        while True:
            action = input('\nWhat would you like to do >>> ')
            action = action.split(' ')
            if action[0] == 'help':
                print_help()
                continue

            # not logged in
            if loginUser is None:
                if action[0] == 'register':
                    register()

                elif action[0] == 'login':
                    loginUser = login(loginUser)
                
                else:
                    print('Invalid input. Type \'help\' for more info.')
            
            # logged in
            else:
                if action[0] == 'create':
                    # action[1] is group name
                    create_group(action[1], loginUser)
                
                elif action[0] == 'post':
                    post_to_group(action[1], loginUser)
                
                elif action[0] == 'view':
                    view_group(action[1], loginUser)

                elif action[0] == 'invite':
                    # invite <user> <group>
                    invite(action[1], action[2], loginUser)

                elif action[0] == 'inbox':
                    loginUser = view_inbox(loginUser)

                elif action[0] == 'join':
                    loginUser = join_group(action[1], loginUser)
                
                elif action[0] == 'clear':
                    clear_inbox(loginUser)

                elif action[0] == 'logout' or action[0] == 'stop':
                    loginUser = logout(loginUser)

    except (KeyboardInterrupt, SystemExit):
        print('\n\nShutting down...')    


def print_help():
    print("""
    When not logged in:
        login
        register

    When logged in:
        create <group>
        view <group>
        decrypt <group>
        post <group>
        inbox
        invite <user> <group>
        remove <user> <group> (owner only)
        logout
    """)


def register():
    print('Please enter a username and password.')
    username = input('Username: ')
    # password = input('Password: ')
    password = getpass()
    private_key, public_key = generate_keys()
    new_user = {
        'username' : username,
        'password' : password,
        'private_key': private_key.exportKey(),
        'public_key': public_key.exportKey(),
        'group_keys': {},
        'invites': {}
    }
    users.insert_one(new_user)
    print('Registered user: ' + username)


# RSA user keys
def generate_keys():
   private_key = RSA.generate(2048)
   public_key = private_key.publickey()
   return private_key, public_key


def login(loginUser):
    username = input('Username: ')
    user = users.find_one({'username': username})
    if user:
        password = getpass()
        if password == user['password']:
            loginUser = user
            print('Logged in as: {0}'.format(loginUser['username']))
        else:
            print('Wrong password')
    else:
        print('User not found')
    return loginUser


def logout(loginUser):
    loginUser = None
    print('Logged out.')
    return loginUser


def create_group(group_name, owner):
    # owner is the loginUser who called create_group()
    owner_username = owner['username']
    group_key = Fernet.generate_key()
    f = Fernet(group_key)
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = 'Created {0}. Hello, world!'.format(group_name)
    token = f.encrypt(message.encode())
    new_group = {
        'owner': owner_username,
        'group_name': group_name,
        'users': [owner_username],
        'messages': [(owner_username, dt, token)]
    }
    groups.insert_one(new_group)
    print('Created group: {0}'.format(group_name))

    public_key = owner['public_key']
    public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(key = public_key)
    encrypted_key = cipher.encrypt(group_key)
    group_keys = owner['group_keys']
    group_keys.update({group_name: encrypted_key})
    owner_updates = {
        'group_keys': group_keys
    }
    users.update_one({'username': owner_username}, {'$set': owner_updates}) 


def post_to_group(group_name, loginUser):
    message = input('Post to {0}: \n'.format(group_name))
    group = groups.find_one({'group_name': group_name})
    group_key = group['group_key']
    f = Fernet(group_key)
    token = f.encrypt(message.encode())
    # print(token)
    # print(f.decrypt(token))
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    messages = group['messages']
    messages.append((loginUser['username'], dt ,token))
    group_updates = {
        'messages': messages
    }
    groups.update_one({'group_name': group_name}, {'$set': group_updates}) 


def view_group(group_name, user):
    group = groups.find_one({'group_name': group_name})
    messages = group['messages']
    
    # a user not part of the group sees the encrypted messages
    if user['username'] not in group['users']:
        print('\n>>>> Welcome to {0} <<<<'.format(group_name))
        for x in messages:
            print('>>> {0} @ {1}'.format(x[0], x[1]))
            print(x[2].decode() + '\n') 

    # a user inside the group is able to decrypt the messages
    else:
        private_key = user['private_key']
        private_key = RSA.importKey(private_key)
        decrypt = PKCS1_OAEP.new(key = private_key)
        encrypted_key = user['group_keys'][group_name]
        group_key = decrypt.decrypt(encrypted_key)
        f = Fernet(group_key)
        messages = group['messages']
        print('\n>>>> Welcome to {0} <<<<'.format(group_name))
        for x in messages:
            print('>>> {0} @ {1}'.format(x[0], x[1]))
            print((f.decrypt(x[2])).decode() + '\n') 


def invite(username, group_name, source):
    # decrypt owners key
    private_key = user['private_key']
    private_key = RSA.importKey(private_key)
    decrypt = PKCS1_OAEP.new(key = private_key)
    encrypted_key = source['group_keys'][group_name]
    group_key = decrypt.decrypt(encrypted_key)
    
    target = users.find_one({'username': username})
    if target:
        if target['username'] == source['username']:
            print('You cannot invite yourself to a group.')
        else:
            public_key = (target['public_key'])
            public_key = RSA.importKey(public_key)
            #Instantiating PKCS1_OAEP object with the public key for encryption
            cipher = PKCS1_OAEP.new(key = public_key)
            #Encrypting the message with the PKCS1_OAEP object
            invite_key = cipher.encrypt(group_key)
            invites = target['invites']
            invites.update({group_name: invite_key})
            target_updates = {
                'invites': invites
            }
            users.update_one({'username': target['username']}, {'$set': target_updates}) 
            print('Invite to \'{0}\' has been sent to \'{1}\''.format(group_name, target['username']))
    else:
        print('User \'{0}\' does not exist.'.format(username))


def view_inbox(user):
    updated_user = users.find_one({'username': user['username']})
    if updated_user['invites']:
        print('You are invited to {0} group(s).'.format(len(updated_user['invites'])))
        for x in updated_user['invites']:
            print('>> {0}'.format(x))
    else:
        print('Your inbox is empty.')
    return updated_user


def join_group(group_name, user):
    user = users.find_one({'username': user['username']})
    # add group and encrypted key to group_keys and delete invite
    invite_key = user['invites'][group_name]
    invites = user['invites']
    try:
        del invites[group_name]
    except KeyError:
        pass
    user_groups = user['group_keys']
    user_groups.update({group_name: invite_key})
    user_update = {
        'group_keys': user_groups,
        'invites': invites
    }
    users.update_one({'username': user['username']}, {'$set': user_update}) 

    group = groups.find_one({'group_name': group_name})
    # decrypt invite_key into group_key to encrypt message
    #Instantiating PKCS1_OAEP object with the private key for decryption
    private_key = user['private_key']
    private_key = RSA.importKey(private_key)
    decrypt = PKCS1_OAEP.new(key = private_key)
    #Decrypting the message with the PKCS1_OAEP object
    group_key = decrypt.decrypt(invite_key)
    f = Fernet(group_key)
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = '{0} has joined the group. Welcome!'.format(user['username'])
    token = f.encrypt(message.encode())
    messages = group['messages']
    messages.append((user['username'], dt, token))

    # add username to groups usernames, and post a join message
    group_users = group['users']
    group_users.append(user['username'])
    group_updates = {
        'users': group_users,
        'messages': messages
    }
    groups.update_one({'group_name': group_name}, {'$set': group_updates})
    print('You have successfully joined {0}'.format(group_name)) 
    return user


def clear_inbox(user):
    invites = {}
    invites_update = {
        'invites': invites
    }
    users.update_one({'username': user['username']}, {'$set': invites_update}) 
    print('Cleared inbox for \'{0}\''.format(user['username']))

if __name__ == '__main__':
    main()
