import datetime
import Crypto
from Crypto.PublicKey import RSA
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

# group = {
#     'session_key': '',
#     'messages': [(user, encryptedMessage), (user2, encryptedMessage2), ...]
# }


def main():
    try:
        global loginUser
        loginUser = ''
        # print some sort of 'help' with commands available
        while True:
            action = input('\nWhat would you like to do >>> ')
            action = action.split(' ')
            # not logged in
            if loginUser == '':
                if action[0] == 'register':
                    register()

                elif action[0] == 'login':
                    login()
                
                else:
                    print('Invalid input. Type \'help\' for more info.')
            
            # logged in
            else:
                if action[0] == 'create':
                    # action[1] is group name
                    create_group(action[1])
                
                elif action[0] == 'post':
                    post_to_group(action[1])
                
                elif action[0] == 'view':
                    view_group(action[1])
                
                elif action[0] == 'decrypt':
                    decrypt_group(action[1])

                elif action[0] == 'logout' or action[0] == 'stop':
                    logout()

                


    except (KeyboardInterrupt, SystemExit):
        print('\n\nShutting down...')    


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
        'public_key': public_key.exportKey()
    }
    users.insert_one(new_user)

# RSA user keys
def generate_keys():
   private_key = RSA.generate(2048)
   public_key = private_key.publickey()
   return private_key, public_key


def login():
    global loginUser
    username = input('Username: ')
    user = users.find_one({'username': username})
    # cache the keys here?
    if user:
        password = getpass()
        if password == user['password']:
            loginUser = username
            print('Logged in as: {0}'.format(loginUser))
        else:
            print('Wrong password')
    else:
        print('User not found')


def logout():
    global loginUser
    loginUser = ''
    print('Logged out.')


def create_group(group_name):
    global loginUser
    group_key = Fernet.generate_key()
    new_group = {
        'owner': loginUser,
        'group_name': group_name,
        'group_key': group_key,
        'users': [loginUser],
        'messages': []
    }
    groups.insert_one(new_group)
    print('Created group: {0}'.format(group_name))


def post_to_group(group_name):
    global loginUser
    message = input('Post to {0}: \n'.format(group_name))
    group = groups.find_one({'group_name': group_name})
    group_key = group['group_key']
    f = Fernet(group_key)
    token = f.encrypt(message.encode())
    # print(token)
    # print(f.decrypt(token))
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    messages = group['messages']
    messages.append((loginUser, dt ,token))
    group_updates = {
        'messages': messages
    }
    groups.update_one({'group_name': group_name}, {'$set': group_updates}) 


def view_group(group_name):
    group = groups.find_one({'group_name': group_name})
    messages = group['messages']
    print('\n>>>> Welcome to {0} <<<<'.format(group_name))
    for x in messages:
        print('>>> {0} @ {1}'.format(x[0], x[1]))
        print(x[2].decode() + '\n') 


def decrypt_group(group_name):
    group = groups.find_one({'group_name': group_name})
    group_key = group['group_key']
    f = Fernet(group_key)
    messages = group['messages']
    print('\n>>>> Welcome to {0} <<<<'.format(group_name))
    for x in messages:
        print('>>> {0} @ {1}'.format(x[0], x[1]))
        print((f.decrypt(x[2])).decode() + '\n') 

if __name__ == '__main__':
    main()
