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

# navigation in the program - since there is no GUI
def main():
    try:
        # loginUser represents the currently logged in user
        # if loginUser = None, no user currently logged in
        # otherwise it has the value of the currently logged in user object
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
                    # create <group>
                    create_group(action[1], loginUser)
                
                elif action[0] == 'post':
                    # post <group>
                    post_to_group(action[1], loginUser)
                
                elif action[0] == 'view':
                    # post <group>
                    view_group(action[1], loginUser)

                elif action[0] == 'invite':
                    # invite <user> <group>
                    invite(action[1], action[2], loginUser)

                elif action[0] == 'kick':
                    # kick <user> <group>
                    kick(action[1], action[2], loginUser)

                elif action[0] == 'join':
                    # join <group>
                    loginUser = join_group(action[1], loginUser)

                elif action[0] == 'inbox':
                    # inbox
                    loginUser = view_inbox(loginUser)
                
                elif action[0] == 'clear':
                    # clear
                    clear_inbox(loginUser)

                elif action[0] == 'logout' or action[0] == 'stop':
                    # logout
                    loginUser = logout(loginUser)

                else:
                    print('Invalid input. Type \'help\' for more info.')

    except (KeyboardInterrupt, SystemExit):
        print('\n\nShutting down...')    


# prints all the available commands that a user can enter
def print_help():
    print("""
    When not logged in:
        login
        register
        help

    When logged in:
        create <group>
        post <group>
        view <group>
        invite <user> <group>
        kick <user> <group> (owner only)
        join <group>
        inbox
        clear
        logout
    """)


# registers a new user into the database
def register():
    print('Please enter a username and password.')
    username = input('Username: ')
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
    print('Registered user: {0}'.format(username))


# generates user's private and public keys
# returns these keys
def generate_keys():
   private_key = RSA.generate(2048)
   public_key = private_key.publickey()
   return private_key, public_key


# encrypts a group key using the users public_key
# returns encrypted_key
def encrypt_group_key(user, group_key):
    public_key = user['public_key']
    public_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(key = public_key)
    encrypted_key = cipher.encrypt(group_key)
    return encrypted_key


# decrypts the encrypted_key of group_name using user's private_key
# returns group_key
def decrypt_group_key(user, group_name):
    encrypted_key = user['group_keys'][group_name]
    private_key = user['private_key']
    private_key = RSA.importKey(private_key)
    decrypt = PKCS1_OAEP.new(key = private_key)
    group_key = decrypt.decrypt(encrypted_key)
    return group_key


# log the user in
# returns a new loginUser object
def login(loginUser):
    username = input('Username: ')
    user = users.find_one({'username': username})
    if user:
        password = getpass()
        if password == user['password']:
            loginUser = user
            print('Logged in as: {0}'.format(loginUser['username']))
        else:
            print('Wrong password.')
    else:
        print('User not found.')
    return loginUser


# logs the user out
# returns loginUser as None to simulate logout
def logout(user):
    user = None
    print('Logged out.')
    return user


# a logged in user can create a group
def create_group(group_name, owner):
    # owner is the loginUser who called create_group()
    owner_username = owner['username']
    
    # generate a symmetric key for the group
    group_key = Fernet.generate_key()
    f = Fernet(group_key)
    
    # group creation message is posted into the group, with current datetime and the owner as author
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

    # encrypt group_key with owners public_key and add it to their group_keys
    encrypted_key = encrypt_group_key(owner, group_key)
    group_keys = owner['group_keys']
    group_keys.update({group_name: encrypted_key})
    owner_updates = {
        'group_keys': group_keys
    }
    users.update_one({'username': owner_username}, {'$set': owner_updates}) 


# a logged in user who is part of the group can post a message to the group
# a user not part of the group gets an error message
def post_to_group(group_name, user):
    group = groups.find_one({'group_name': group_name})
    if group:
        if check_membership(user, group):
            message = input('Post to {0}: \n'.format(group_name))
            group_key = decrypt_group_key(user, group_name)
            
            # encrypt the message using the group_key
            f = Fernet(group_key)
            token = f.encrypt(message.encode())
            dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            messages = group['messages']
            messages.append((user['username'], dt ,token))
            group_updates = {
                'messages': messages
            }
            groups.update_one({'group_name': group_name}, {'$set': group_updates}) 
        else:
            print('You must be part of the group to post to it.')
    else:
        print('This group does not exist.')


# a logged in user can view the group's messages
# author and datetime are left unencrypted to help with visibility
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
        group_key = decrypt_group_key(user, group_name)
        f = Fernet(group_key)
        messages = group['messages']
        print('\n>>>> Welcome to {0} <<<<'.format(group_name))
        for x in messages:
            print('>>> {0} @ {1}'.format(x[0], x[1]))
            print((f.decrypt(x[2])).decode() + '\n') 


# a member of a group can invite another existing user to the group
def invite(username, group_name, source):
    group = groups.find_one({'group_name': group_name})
    if group:
        if check_membership(source, group):
            group_key = decrypt_group_key(source, group_name)
            
            target = users.find_one({'username': username})
            if target:
                if target['username'] == source['username']:
                    print('You cannot invite yourself to a group.')
                else:
                    invite_key = encrypt_group_key(target, group_key)
                    invites = target['invites']
                    invites.update({group_name: invite_key})
                    target_updates = {
                        'invites': invites
                    }
                    users.update_one({'username': target['username']}, {'$set': target_updates}) 
                    print('Invite to \'{0}\' has been sent to \'{1}\''.format(group_name, target['username']))
            else:
                print('User \'{0}\' does not exist.'.format(username))
        else:
            print('You must be part of the group to invite to it.')
    else:
        print('This group does not exist.')


# the owner of a group is able to kick users out of the group
def kick(username, group_name, source):
    group = groups.find_one({'group_name': group_name})
    if group:
        # check if owner
        if source['username'] == group['owner']:
            if source['username'] == username:
                print('You cannot kick yourself from the group.')
            else:
                # delete target's group_key
                target = users.find_one({'username': username})
                if target:
                    if check_membership(target, group):
                        user_groups = target['group_keys']
                        try:
                            del user_groups[group_name]
                        except KeyError:
                            pass
                        user_update = {
                            'group_keys': user_groups
                        }
                        users.update_one({'username': target['username']}, {'$set': user_update}) 
                        print('\'{0}\' has been kicked from \'{1}\'.'.format(target['username'], group_name))
                        
                        # post a message to the group that user has been kicked
                        group_key = decrypt_group_key(source, group_name)
                        f = Fernet(group_key)
                        dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        message = '\'{0}\' has been kicked from \'{1}\'.'.format(target['username'], group_name)
                        token = f.encrypt(message.encode())
                        messages = group['messages']
                        messages.append((source['username'], dt, token))
                        
                        # delete user from group's users
                        group_users = group['users']
                        group_users.remove(username)
                        group_updates = {
                            'users': group_users,
                            'messages': messages
                        }
                        groups.update_one({'group_name': group_name}, {'$set': group_updates})
                    else:
                        print('User \'{0}\' is not part of this group.'.format(username))
                else:
                    print('User \'{0}\' does not exist.'.format(username))
        else:
            print('You cannot do that as you\'re not the owner of {0}.'.format(group_name))
    else:
        print('This group does not exist.')


# a logged in user can check their inbox - shows if they have any invitations to groups
def view_inbox(user):
    updated_user = users.find_one({'username': user['username']})
    if updated_user['invites']:
        print('You are invited to {0} group(s).'.format(len(updated_user['invites'])))
        for x in updated_user['invites']:
            print('>> {0}'.format(x))
    else:
        print('Your inbox is empty.')
    return updated_user


# a logged in user can clear their inbox - removing any exsiting invitations 
def clear_inbox(user):
    invites = {}
    invites_update = {
        'invites': invites
    }
    users.update_one({'username': user['username']}, {'$set': invites_update}) 
    print('Cleared inbox for \'{0}\''.format(user['username']))


# if have any invitations to groups, can join the group
def join_group(group_name, user):
    user = users.find_one({'username': user['username']})
    # add group_name and encrypted_key to group_keys and delete invite from inbox
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

    # decrypt invite_key into group_key to encrypt join message
    group = groups.find_one({'group_name': group_name})
    group_key = decrypt_group_key(user, group_name)
    f = Fernet(group_key)
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = '\'{0}\' has joined the group. Welcome!'.format(user['username'])
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


# checks whether a user is part of given group
def check_membership(user, group):
    if user['username'] in group['users']:
        return True
    return False


if __name__ == '__main__':
    main()
